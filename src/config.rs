// SPDX-License-Identifier: Apache-2.0
//! Configuration loading, validation, and router construction.
//!
//! Parses `zion.toml` into typed structs (`ZionConfig`), validates the
//! result (every WAF/auth/cache profile referenced by a route must
//! exist; CIDRs parse; xff_mode is a known string), and builds the
//! `matchit::Router<Arc<ResolvedRoute>>` consumed by `dispatch.rs`.
//!
//! `build_router` is the single fallible entry point; everything that
//! turns static TOML into runtime state flows through it.

use matchit::Router;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

// ============================================================================
// TOP-LEVEL CONFIG
// ============================================================================

#[derive(Deserialize, Clone)]
pub struct ZionConfig {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub upstream: HashMap<String, UpstreamConfig>,
    #[serde(default)]
    pub waf_profile: HashMap<String, WafProfile>,
    #[serde(default)]
    pub cache_profile: HashMap<String, CacheProfile>,
    pub route: Vec<RouteConfig>,
    /// Named auth profiles for JWT/OIDC validation (feature: auth).
    #[serde(default)]
    pub auth_profile: HashMap<String, crate::auth::AuthProfileConfig>,

    /// Sovereign Edge Intelligence config (feature: geo-ita / geo-eu).
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    #[serde(default)]
    pub sovereign: crate::sovereign::SovereignConfig,

    /// HMAC-chained audit log (Track B). When `enabled = true` Zion writes
    /// one signed JSON event per security-relevant action to the configured
    /// path. Every event carries a `prev_hash` field so any tamper breaks
    /// the chain at the next verification.
    #[serde(default)]
    pub audit: crate::audit::AuditConfig,

    /// PII redaction policy applied to access logs and audit events
    /// (Track B). Empty = no redaction (default — back-compat).
    #[serde(default)]
    pub redact: crate::audit::RedactConfig,

    // Legacy compat: flat upstreams map (just URLs)
    #[serde(default)]
    pub upstreams: HashMap<String, String>,
}

// ============================================================================
// SERVER
// ============================================================================

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_http: String,
    pub listen_https: String,
    /// Max requests per IP per window. 0 = unlimited (default).
    #[serde(default)]
    pub rate_limit_rps: u32,
    /// Rate limit window in seconds. Default: 1.
    #[serde(default = "default_rate_window")]
    pub rate_limit_window_secs: u64,
    /// Log format: "text" (default) or "json".
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// Trusted proxy CIDR ranges. When the TCP peer IP matches one of these,
    /// the real client IP is extracted from X-Forwarded-For (rightmost untrusted hop).
    /// Example: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// X-Forwarded-For policy applied to outbound requests to upstreams.
    ///
    /// * `"append"` (default): preserve any inbound XFF chain and append
    ///   the resolved client IP. Compatible with deployments where Zion
    ///   sits behind a sanitising edge (CDN/ALB).
    /// * `"rewrite"`: drop inbound XFF and emit a single trusted entry —
    ///   the resolved client IP. Recommended when Zion is the front edge.
    /// * `"drop"`: strip inbound XFF; emit nothing. Use when upstreams
    ///   must not learn the client IP at all.
    ///
    /// Invalid values fall back to `"append"` with a startup warning.
    #[serde(default = "default_xff_mode")]
    pub xff_mode: String,
}

fn default_xff_mode() -> String {
    "append".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_rate_window() -> u64 {
    1
}

// ============================================================================
// CORS
// ============================================================================

#[derive(Deserialize, Clone, Debug, Default)]
pub struct CorsConfig {
    /// Allowed origins. Empty = CORS disabled (default).
    /// Use `["*"]` for any origin, or `["https://app.example.com"]`.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Additional allowed headers beyond the CORS safelisted ones.
    #[serde(default = "default_cors_headers")]
    pub allowed_headers: Vec<String>,
    /// Max age for pre-flight cache (seconds). Default: 86400 (24h).
    #[serde(default = "default_cors_max_age")]
    pub max_age: u64,
}

fn default_cors_headers() -> Vec<String> {
    vec![
        "Content-Type".to_string(),
        "Authorization".to_string(),
        "X-Requested-With".to_string(),
    ]
}

fn default_cors_max_age() -> u64 {
    86400
}

// ============================================================================
// TLS (abstracted: min version, ALPN, cipher control)
// ============================================================================

#[derive(Deserialize, Clone)]
pub struct TlsConfig {
    /// Default cert (used when no SNI match, or single-FQDN mode)
    pub cert_path: String,
    pub key_path: String,
    #[serde(default = "default_true")]
    pub hot_reload: bool,
    #[serde(default = "default_tls_min_version")]
    pub min_version: String, // "1.2" or "1.3"
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>, // ["h2", "http/1.1"]
    /// Optional SNI-based cert mappings. If empty, single-cert mode (zero overhead).
    #[serde(default)]
    pub sni: Vec<SniCert>,
    /// ACME auto-renewal. If set, Zion auto-renews certificates via Let's Encrypt.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// Path to CA bundle for verifying client certificates (mTLS downstream).
    #[serde(default)]
    pub client_ca_path: Option<String>,
    /// Client auth mode: "none" (default), "optional", "required".
    #[serde(default = "default_client_auth")]
    pub client_auth: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SniCert {
    pub server_name: String,
    pub cert_path: String,
    pub key_path: String,
}

/// Always deserialized so users get a clear "unknown ACME field" error
/// even on builds without `--features acme`. The fields below are only
/// READ by acme.rs, which is feature-gated; hence the targeted allow.
#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct AcmeConfig {
    /// Contact email for Let's Encrypt (required).
    pub email: String,
    /// Domains to get certificates for.
    pub domains: Vec<String>,
    /// ACME directory URL. Default: Let's Encrypt production.
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    /// Days before expiry to trigger renewal. Default: 30.
    #[serde(default = "default_acme_renew_days")]
    pub renew_before_days: u64,
    /// Where to store ACME account key + certs. Default: /etc/zion/acme/
    #[serde(default = "default_acme_state_dir")]
    pub state_dir: String,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
fn default_acme_renew_days() -> u64 {
    30
}
fn default_acme_state_dir() -> String {
    "/etc/zion/acme".to_string()
}

fn default_true() -> bool {
    true
}
fn default_tls_min_version() -> String {
    "1.3".to_string()
}
fn default_alpn() -> Vec<String> {
    vec!["h2".to_string(), "http/1.1".to_string()]
}

// ============================================================================
// UPSTREAM (abstracted: url, timeouts, keepalive, TLS to backend)
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
pub struct UpstreamConfig {
    pub url: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_keepalive")]
    pub keepalive: usize,
    #[serde(default)]
    pub tls: bool, // backend is HTTPS
    /// Client certificate for upstream mTLS (Zion → backend).
    #[serde(default)]
    pub client_cert_path: Option<String>,
    /// Client key for upstream mTLS.
    #[serde(default)]
    pub client_key_path: Option<String>,
}

impl UpstreamConfig {
    pub fn get_urls(&self) -> Vec<String> {
        let mut all = self.urls.clone();
        if let Some(u) = &self.url {
            all.push(u.clone());
        }
        all
    }
}

fn default_connect_timeout() -> u64 {
    3000
}
fn default_keepalive() -> usize {
    64
}
pub(crate) fn default_client_auth() -> String {
    "none".to_string()
}

// ============================================================================
// WAF PROFILES (layered, named, per-route)
// ============================================================================

/// WAF detection mode — selects which Aho-Corasick pattern set is scanned.
///
/// `Balanced` (default): high-precision patterns. SQLi/XSS tags/path traversal/
/// SSRF/XXE/Log4Shell/CRLF/SSTI/most LDAP and PHP patterns. Tuned to keep the
/// false-positive rate low for content-bearing APIs (comments, code paste,
/// docs, payloads with base64).
///
/// `Aggressive`: balanced PLUS broad-substring patterns that catch more
/// attacks but also flag legitimate developer/tooling content. Use this on
/// strict admin paths, never on user-content APIs unless you've measured the
/// FP rate. Examples added under aggressive: `alert(`, `eval(`,
/// `document.cookie`, `innerhtml`, `os.system(`, `pickle.loads`,
/// `Runtime.getRuntime`, `$gt`/`$ne`/`$regex` (unanchored MongoDB ops), and
/// generic XSS event handlers like `onclick=`/`onmouseover=`.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    #[default]
    Balanced,
    Aggressive,
}

#[derive(Deserialize, Clone, Debug)]
pub struct WafProfile {
    #[serde(default)]
    pub mode: WafMode,
    #[serde(default = "default_max_body_mb")]
    pub max_body_mb: u64,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_max_string_len")]
    pub max_string_len: usize,
    #[serde(default = "default_true")]
    pub deny_unknown_content_types: bool,
    #[serde(default = "default_allowed_content_types")]
    pub allowed_content_types: Vec<String>,
    /// Run Shannon-entropy gate on bodies ≥256 bytes. When true, denies
    /// requests whose entropy exceeds `entropy_threshold`. Default: true.
    /// Disable on routes that legitimately accept high-entropy payloads
    /// (binary uploads as JSON-base64, encrypted blobs, signed envelopes).
    #[serde(default = "default_true")]
    pub entropy_check: bool,
    /// Entropy threshold in bits/byte. Default: 6.5 — leaves headroom above
    /// pure base64 (6.0 theoretical max) so JWTs, signed URLs and base64
    /// payloads are not flagged. Random/encrypted content sits at ~7.5–8.0.
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
}

fn default_max_body_mb() -> u64 {
    10
}
fn default_max_depth() -> usize {
    10
}
fn default_max_string_len() -> usize {
    1_048_576
}
fn default_allowed_content_types() -> Vec<String> {
    vec![
        "application/json".to_string(),
        "multipart/form-data".to_string(),
    ]
}
fn default_entropy_threshold() -> f64 {
    6.5
}

impl Default for WafProfile {
    fn default() -> Self {
        Self {
            mode: WafMode::default(),
            max_body_mb: default_max_body_mb(),
            max_depth: default_max_depth(),
            max_string_len: default_max_string_len(),
            deny_unknown_content_types: true,
            allowed_content_types: default_allowed_content_types(),
            entropy_check: true,
            entropy_threshold: default_entropy_threshold(),
        }
    }
}

// ============================================================================
// CACHE PROFILES
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
pub struct CacheProfile {
    #[serde(default = "default_cache_mode")]
    pub mode: CacheMode,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    Memory,
    None,
}

fn default_cache_mode() -> CacheMode {
    CacheMode::Memory
}
fn default_max_entries() -> usize {
    10_000
}
fn default_ttl() -> u64 {
    31_536_000
} // 1 year

// ============================================================================
// ROUTE CONFIG
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
pub struct RouteConfig {
    pub path: String,
    pub upstream: String,
    #[serde(default)]
    pub mode: RouteMode,
    #[serde(default)]
    pub internal_only: bool,

    // New: named profile references (None = disabled)
    pub waf_profile: Option<String>,
    pub cache_profile: Option<String>,

    /// Per-route Content-Security-Policy header. If set, injected into responses.
    /// If unset, upstream CSP is passed through unmodified.
    pub csp: Option<String>,

    /// Auth profile name for JWT/OIDC validation.
    /// If set, requests must carry a valid Bearer token.
    pub auth_profile: Option<String>,

    // Legacy compat: bool waf flag + inline max_body_mb
    #[serde(default)]
    pub waf: bool,
    pub max_body_mb: Option<u64>,

    /// Shadow mode: run WAF checks but do NOT block on violation.
    /// Each would-be denial is logged (`logging::warn`) with the matched
    /// reason and counted in the `waf_shadow_would_block` metric. Lets
    /// operators migrating from nginx/ModSecurity test their WAF profile
    /// against real traffic for hours/days before flipping to enforce.
    /// Has no effect when no WAF profile is attached to the route.
    #[serde(default)]
    pub waf_shadow: bool,

    /// Per-route CORS configuration. If unset, no CORS headers are injected.
    pub cors: Option<CorsConfig>,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    #[default]
    Standard,
    SseStream,
    StaticCache,
    Websocket,
}

// ============================================================================
// RESOLVED ROUTE (fully resolved at startup, zero lookups at runtime)
// ============================================================================

#[derive(Clone, Debug)]
pub struct ResolvedRoute {
    #[allow(dead_code)]
    pub upstream_url: Vec<String>,
    /// Pre-parsed URI parts — avoids full URI parse on every request.
    pub upstream_scheme: hyper::http::uri::Scheme,
    pub upstream_authority: hyper::http::uri::Authority,
    pub mode: RouteMode,
    pub waf: Option<WafProfile>,
    /// True iff the route is in WAF shadow mode (log + count, no block).
    pub waf_shadow: bool,
    pub cache: Option<CacheProfile>,
    pub internal_only: bool,
    /// Per-route CSP header value (pre-parsed at startup, zero cost at runtime).
    pub csp: Option<hyper::header::HeaderValue>,
    /// Resolved auth profile (pre-built at startup).
    #[cfg(feature = "auth")]
    pub auth: Option<crate::auth::ResolvedAuthProfile>,
    /// Pre-compiled CORS headers for lightning-fast matching per-route.
    pub cors: Option<std::sync::Arc<crate::security::CorsHeaders>>,
}

// ============================================================================
// LOADING & BUILDING
// ============================================================================

pub fn load_config(path: &str) -> Result<ZionConfig, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let config: ZionConfig =
        toml::from_str(&raw).map_err(|e| format!("Invalid TOML in {path}: {e}"))?;
    validate_config(&config, path)?;
    Ok(config)
}

/// Validate config at startup — fail fast with actionable error messages.
fn validate_config(config: &ZionConfig, path: &str) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    // Server addresses must parse
    if config
        .server
        .listen_http
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        errors.push(format!(
            "server.listen_http '{}' is not a valid address",
            config.server.listen_http
        ));
    }
    if config
        .server
        .listen_https
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        errors.push(format!(
            "server.listen_https '{}' is not a valid address",
            config.server.listen_https
        ));
    }

    // TLS cert files must exist
    if !std::path::Path::new(&config.tls.cert_path).exists() {
        errors.push(format!(
            "tls.cert_path '{}' does not exist",
            config.tls.cert_path
        ));
    }
    if !std::path::Path::new(&config.tls.key_path).exists() {
        errors.push(format!(
            "tls.key_path '{}' does not exist",
            config.tls.key_path
        ));
    }

    // SNI cert files must exist
    for (i, sni) in config.tls.sni.iter().enumerate() {
        if !std::path::Path::new(&sni.cert_path).exists() {
            errors.push(format!(
                "tls.sni[{}] cert_path '{}' does not exist",
                i, sni.cert_path
            ));
        }
        if !std::path::Path::new(&sni.key_path).exists() {
            errors.push(format!(
                "tls.sni[{}] key_path '{}' does not exist",
                i, sni.key_path
            ));
        }
        if sni.server_name.is_empty() {
            errors.push(format!("tls.sni[{i}] server_name is empty"));
        }
    }

    // Must have at least one route
    if config.route.is_empty() {
        errors.push("no [[route]] defined — at least one route is required".to_string());
    }

    // Each route must reference a valid upstream
    for route in &config.route {
        let has_upstream = config.upstream.contains_key(&route.upstream)
            || config.upstreams.contains_key(&route.upstream);
        if !has_upstream {
            errors.push(format!(
                "route '{}' references unknown upstream '{}'",
                route.path, route.upstream
            ));
        }

        // WAF profile reference must exist
        if let Some(ref profile) = route.waf_profile {
            if !config.waf_profile.contains_key(profile) {
                errors.push(format!(
                    "route '{}' references unknown waf_profile '{}'",
                    route.path, profile
                ));
            }
        }

        // Cache profile reference must exist
        if let Some(ref profile) = route.cache_profile {
            if !config.cache_profile.contains_key(profile) {
                errors.push(format!(
                    "route '{}' references unknown cache_profile '{}'",
                    route.path, profile
                ));
            }
        }

        // Auth profile reference must exist
        if let Some(ref profile) = route.auth_profile {
            if !config.auth_profile.contains_key(profile) {
                errors.push(format!(
                    "route '{}' references unknown auth_profile '{}'",
                    route.path, profile
                ));
            }
        }
    }

    // Upstream URLs must be valid
    for (name, up) in &config.upstream {
        let all_urls = up.get_urls();
        if all_urls.is_empty() {
            errors.push(format!("upstream '{name}' must have at least one url"));
        }
        for u in all_urls {
            if u.parse::<hyper::Uri>().is_err() {
                errors.push(format!("upstream.{name}.url '{u}' is not a valid URL"));
            }
        }
    }
    for (name, url) in &config.upstreams {
        if url.parse::<hyper::Uri>().is_err() {
            errors.push(format!("upstreams.{name} '{url}' is not a valid URL"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        let msg = format!(
            "config validation failed ({}):\n  - {}",
            path,
            errors.join("\n  - ")
        );
        Err(msg)
    }
}

/// Resolve upstream name to URLs. Checks new `[upstream.X]` first, then legacy `[upstreams]`.
/// Returns Err if the upstream name is not defined — callers propagate the
/// error to reject the config rather than panicking (important during hot-reload).
fn resolve_upstream(config: &ZionConfig, name: &str) -> Result<Vec<String>, String> {
    if let Some(up) = config.upstream.get(name) {
        return Ok(up.get_urls());
    }
    if let Some(url) = config.upstreams.get(name) {
        return Ok(vec![url.clone()]);
    }
    Err(format!(
        "Unknown upstream '{name}' — define it in [upstream.{name}] or [upstreams]"
    ))
}

/// Build a radix tree from config routes, pre-resolving all references.
/// Routes are wrapped in Arc for zero-allocation cloning on the hot path.
///
/// Returns `Err` if any route references an unknown upstream, profile, or
/// contains an invalid pattern. The caller (boot path or hot-reload) decides
/// whether to abort or log-and-keep the previous snapshot.
pub fn build_router(config: &ZionConfig) -> Result<Router<Arc<ResolvedRoute>>, String> {
    let mut router = Router::new();

    for route in &config.route {
        let upstream_url = resolve_upstream(config, &route.upstream)?;

        // Resolve WAF: named profile > legacy bool flag
        let waf = if let Some(ref profile_name) = route.waf_profile {
            Some(
                config
                    .waf_profile
                    .get(profile_name)
                    .ok_or_else(|| {
                        format!(
                            "Unknown waf_profile '{}' in route {}",
                            profile_name, route.path
                        )
                    })?
                    .clone(),
            )
        } else if route.waf {
            // Legacy: create inline profile from max_body_mb
            Some(WafProfile {
                max_body_mb: route.max_body_mb.unwrap_or(10),
                ..WafProfile::default()
            })
        } else {
            None
        };

        // Resolve cache: named profile > legacy mode=static_cache
        let cache = if let Some(ref profile_name) = route.cache_profile {
            Some(
                config
                    .cache_profile
                    .get(profile_name)
                    .ok_or_else(|| {
                        format!(
                            "Unknown cache_profile '{}' in route {}",
                            profile_name, route.path
                        )
                    })?
                    .clone(),
            )
        } else if route.mode == RouteMode::StaticCache {
            // Legacy: create default immutable cache profile
            Some(CacheProfile {
                mode: CacheMode::Memory,
                max_entries: default_max_entries(),
                ttl_seconds: default_ttl(),
            })
        } else {
            None
        };

        // Pre-parse the FIRST upstream URI at startup for legacy fallback.
        // In a true clustered setup with latency routing, we use the first to get the scheme.
        let upstream_uri: hyper::Uri = upstream_url[0]
            .parse()
            .map_err(|e| format!("Invalid upstream URL '{}': {}", upstream_url[0], e))?;
        let upstream_scheme = upstream_uri
            .scheme()
            .cloned()
            .unwrap_or_else(|| "http".parse().unwrap());
        let upstream_authority = upstream_uri
            .authority()
            .cloned()
            .ok_or_else(|| format!("Upstream '{}' has no authority", upstream_url[0]))?;

        // Pre-parse CSP at startup for zero-cost injection at runtime
        let csp = match route.csp.as_ref() {
            Some(s) => Some(
                hyper::header::HeaderValue::from_str(s)
                    .map_err(|e| format!("Invalid CSP in route '{}': {}", route.path, e))?,
            ),
            None => None,
        };

        // Resolve auth profile at startup (feature-gated)
        #[cfg(feature = "auth")]
        let auth = match route.auth_profile.as_ref() {
            Some(name) => {
                let profile_config = config.auth_profile.get(name).ok_or_else(|| {
                    format!("Auth profile '{}' not found (route '{}')", name, route.path)
                })?;
                let resolved = crate::auth::resolve_auth_profile(profile_config).map_err(|e| {
                    format!("Auth profile '{}' (route '{}'): {}", name, route.path, e)
                })?;
                eprintln!(
                    "  auth: route {} → profile '{}' (alg={})",
                    route.path, name, profile_config.algorithm
                );
                Some(resolved)
            }
            None => None,
        };

        let cors = route
            .cors
            .as_ref()
            .map(|c| Arc::new(crate::security::CorsHeaders::from_config(c)));

        let resolved = Arc::new(ResolvedRoute {
            upstream_url,
            upstream_scheme,
            upstream_authority,
            mode: route.mode.clone(),
            waf,
            waf_shadow: route.waf_shadow,
            cache,
            internal_only: route.internal_only,
            csp,
            #[cfg(feature = "auth")]
            auth,
            cors,
        });

        router
            .insert(route.path.clone(), resolved)
            .map_err(|e| format!("Bad route pattern '{}': {}", route.path, e))?;
    }

    print_routes_table(&config.route);
    Ok(router)
}

// ═══════════════════════════════════════════════════════════════════
// ROUTES MINI-TABLE (boot-time visualization)
// ═══════════════════════════════════════════════════════════════════

/// Print the configured routes as a styled mini-table. Replaces the
/// per-route `eprintln!("route ... [waf=, cache=, mode=]")` line with a
/// scannable layout: aligned paths, dim arrow, cyan upstream, semantic
/// tags (`waf`, `cache`, `sse`, `ws`, `static`, `internal`) colored by
/// category. Falls back to plain ASCII when stderr is not a TTY or when
/// `NO_COLOR` / `ZION_BOOT_PLAIN` is set.
fn print_routes_table(routes: &[RouteConfig]) {
    use std::io::IsTerminal;

    let plain =
        std::env::var_os("NO_COLOR").is_some() || std::env::var_os("ZION_BOOT_PLAIN").is_some();
    let color = !plain && std::io::stderr().is_terminal();

    // Cap path column at 40 chars so very long matchers don't blow up the
    // layout. Truncate with an ellipsis when over.
    const PATH_CAP: usize = 40;
    let max_path_chars = routes
        .iter()
        .map(|r| r.path.chars().count().min(PATH_CAP))
        .max()
        .unwrap_or(0);

    let header_dim = if color { "\x1b[2m" } else { "" };
    let arrow_dim = if color { "\x1b[2m" } else { "" };
    let cyan = if color { "\x1b[38;5;51m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };

    eprintln!("  {}routes ({}){}", header_dim, routes.len(), reset);

    for route in routes {
        let path = truncate_chars(&route.path, PATH_CAP);
        let pad = " ".repeat(max_path_chars.saturating_sub(path.chars().count()));
        let tags = render_route_tags(route, color);
        eprintln!(
            "    {}{} {}→{} {}{}{}{}",
            path,
            pad,
            arrow_dim,
            reset,
            cyan,
            route.upstream,
            reset,
            if tags.is_empty() {
                String::new()
            } else {
                format!("    {tags}")
            },
        );
    }
}

/// Build the tag suffix for a route: a `·`-joined list of colored chips
/// (`waf`, `sse`, `ws`, `static`, `cache`, `internal`). Returns "" when
/// the route is a plain pass-through with no special features.
fn render_route_tags(route: &RouteConfig, color: bool) -> String {
    let reset = if color { "\x1b[0m" } else { "" };
    let dim_sep = if color { "\x1b[2m" } else { "" };
    let green = if color { "\x1b[38;5;46m" } else { "" }; // security ON
    let yellow = if color { "\x1b[38;5;220m" } else { "" }; // perf / restricted
    let cyan = if color { "\x1b[38;5;51m" } else { "" }; // streaming / special

    let mut tags: Vec<String> = Vec::new();

    match route.mode {
        RouteMode::SseStream => tags.push(format!("{cyan}sse{reset}")),
        RouteMode::Websocket => tags.push(format!("{cyan}ws{reset}")),
        RouteMode::StaticCache => tags.push(format!("{cyan}static{reset}")),
        RouteMode::Standard => {}
    }
    if route.waf || route.waf_profile.is_some() {
        if route.waf_shadow {
            // Distinct tag — the operator must see at a glance which routes
            // are simulating vs enforcing. Amber matches "warning" semantics.
            tags.push(format!("{yellow}waf:shadow{reset}"));
        } else {
            tags.push(format!("{green}waf{reset}"));
        }
    }
    if route.cache_profile.is_some() {
        tags.push(format!("{yellow}cache{reset}"));
    }
    if route.internal_only {
        tags.push(format!("{yellow}internal{reset}"));
    }

    if tags.is_empty() {
        return String::new();
    }
    let sep = format!(" {dim_sep}·{reset} ");
    tags.join(&sep)
}

fn truncate_chars(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(path: &str) -> RouteConfig {
        RouteConfig {
            path: path.into(),
            upstream: "backend".into(),
            mode: RouteMode::Standard,
            internal_only: false,
            waf_profile: None,
            cache_profile: None,
            csp: None,
            auth_profile: None,
            waf: false,
            max_body_mb: None,
            waf_shadow: false,
            cors: None,
        }
    }

    #[test]
    fn route_tags_plain_passthrough_is_empty() {
        let r = route("/static");
        assert_eq!(render_route_tags(&r, false), "");
    }

    #[test]
    fn route_tags_waf_only() {
        let mut r = route("/api");
        r.waf = true;
        assert_eq!(render_route_tags(&r, false), "waf");
    }

    #[test]
    fn route_tags_named_waf_profile_counts() {
        let mut r = route("/api");
        r.waf_profile = Some("strict".into());
        assert_eq!(render_route_tags(&r, false), "waf");
    }

    #[test]
    fn route_tags_static_with_cache() {
        let mut r = route("/_next/static");
        r.mode = RouteMode::StaticCache;
        r.cache_profile = Some("immutable".into());
        // Mode tag first, then perf tag
        assert_eq!(render_route_tags(&r, false), "static · cache");
    }

    #[test]
    fn route_tags_sse_stream() {
        let mut r = route("/events");
        r.mode = RouteMode::SseStream;
        assert_eq!(render_route_tags(&r, false), "sse");
    }

    #[test]
    fn route_tags_websocket() {
        let mut r = route("/ws");
        r.mode = RouteMode::Websocket;
        assert_eq!(render_route_tags(&r, false), "ws");
    }

    #[test]
    fn route_tags_internal_marked() {
        let mut r = route("/metrics");
        r.internal_only = true;
        assert_eq!(render_route_tags(&r, false), "internal");
    }

    #[test]
    fn route_tags_shadow_replaces_waf_tag() {
        // waf=true alone → "waf"
        let mut r = route("/api");
        r.waf = true;
        assert_eq!(render_route_tags(&r, false), "waf");
        // waf=true + shadow → "waf:shadow" so the visual distinction is
        // unmissable when scanning the boot output.
        r.waf_shadow = true;
        assert_eq!(render_route_tags(&r, false), "waf:shadow");
    }

    #[test]
    fn route_tags_shadow_with_named_profile() {
        let mut r = route("/api");
        r.waf_profile = Some("strict".into());
        r.waf_shadow = true;
        assert_eq!(render_route_tags(&r, false), "waf:shadow");
    }

    #[test]
    fn route_tags_shadow_no_waf_attached_no_tag() {
        // Shadow without any WAF profile attached → no tag (logical no-op).
        let mut r = route("/static");
        r.waf_shadow = true;
        // We still don't render anything because there's no WAF on the route.
        // Treating shadow as a strict modifier of the waf tag.
        assert_eq!(render_route_tags(&r, false), "");
    }

    #[test]
    fn route_tags_color_uses_ansi_per_category() {
        let mut r = route("/api");
        r.waf = true;
        r.internal_only = true;
        let tagged = render_route_tags(&r, true);
        // Green for waf (security), amber for internal (restricted), dim
        // separator between them.
        assert!(tagged.contains("\x1b[38;5;46mwaf"), "got: {tagged}");
        assert!(tagged.contains("\x1b[38;5;220minternal"), "got: {tagged}");
        assert!(
            tagged.contains("\x1b[2m·"),
            "expected dim separator: {tagged}"
        );
    }

    #[test]
    fn truncate_chars_keeps_short_unchanged() {
        assert_eq!(truncate_chars("/api", 40), "/api");
    }

    #[test]
    fn truncate_chars_clips_long_with_ellipsis() {
        let long = "/api/v1/very/long/nested/path/that/exceeds/the/cap/easily";
        let out = truncate_chars(long, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_chars_handles_unicode() {
        // Em-dashes and box characters count as 1 each
        let s = "abc—def★ghi";
        assert_eq!(truncate_chars(s, 5).chars().count(), 5);
    }

    fn minimal_toml() -> &'static str {
        r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"

[tls]
cert_path = "/tmp/cert.pem"
key_path = "/tmp/key.pem"

[upstreams]
backend = "http://127.0.0.1:8000"

[[route]]
path = "/api/{*rest}"
upstream = "backend"
waf = true
"#
    }

    fn profile_toml() -> &'static str {
        r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"

[tls]
cert_path = "/tmp/cert.pem"
key_path = "/tmp/key.pem"

[upstream.api]
url = "http://127.0.0.1:8000"
connect_timeout_ms = 5000
keepalive = 128

[upstream.frontend]
url = "http://127.0.0.1:3000"

[waf_profile.strict]
max_body_mb = 5
max_depth = 8
max_string_len = 524288

[waf_profile.upload]
max_body_mb = 200
deny_unknown_content_types = false

[cache_profile.immutable]
mode = "memory"
max_entries = 5000
ttl_seconds = 86400

[[route]]
path = "/api/{*rest}"
upstream = "api"
waf_profile = "strict"

[[route]]
path = "/upload"
upstream = "api"
waf_profile = "upload"

[[route]]
path = "/_next/static/{*rest}"
upstream = "frontend"
cache_profile = "immutable"

[[route]]
path = "/{*rest}"
upstream = "frontend"
"#
    }

    #[test]
    fn parse_minimal_config() {
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(config.server.listen_http, "0.0.0.0:80");
        assert_eq!(config.server.listen_https, "0.0.0.0:443");
        assert_eq!(config.tls.cert_path, "/tmp/cert.pem");
        assert!(config.tls.hot_reload); // default true
        assert_eq!(config.tls.min_version, "1.3"); // default
        assert_eq!(config.route.len(), 1);
    }

    #[test]
    fn parse_legacy_upstreams() {
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(
            config.upstreams.get("backend"),
            Some(&"http://127.0.0.1:8000".to_string())
        );
    }

    #[test]
    fn parse_named_upstream() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let api = config.upstream.get("api").unwrap();
        assert_eq!(api.url.as_deref(), Some("http://127.0.0.1:8000"));
        assert_eq!(api.connect_timeout_ms, 5000);
        assert_eq!(api.keepalive, 128);
        assert!(!api.tls); // default false
    }

    #[test]
    fn upstream_defaults() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let fe = config.upstream.get("frontend").unwrap();
        assert_eq!(fe.connect_timeout_ms, 3000); // default
        assert_eq!(fe.keepalive, 64); // default
    }

    #[test]
    fn parse_waf_profiles() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let strict = config.waf_profile.get("strict").unwrap();
        assert_eq!(strict.max_body_mb, 5);
        assert_eq!(strict.max_depth, 8);
        assert_eq!(strict.max_string_len, 524288);
        assert!(strict.deny_unknown_content_types); // default true

        let upload = config.waf_profile.get("upload").unwrap();
        assert_eq!(upload.max_body_mb, 200);
        assert!(!upload.deny_unknown_content_types);
    }

    #[test]
    fn parse_cache_profiles() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let imm = config.cache_profile.get("immutable").unwrap();
        assert_eq!(imm.mode, CacheMode::Memory);
        assert_eq!(imm.max_entries, 5000);
        assert_eq!(imm.ttl_seconds, 86400);
    }

    #[test]
    fn build_router_with_legacy_upstreams() {
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        let router = build_router(&config).unwrap();
        let matched = router.at("/api/v1/users").unwrap();
        assert_eq!(matched.value.upstream_url[0], "http://127.0.0.1:8000");
        assert!(matched.value.waf.is_some()); // legacy waf=true
        assert_eq!(matched.value.waf.as_ref().unwrap().max_body_mb, 10); // default
    }

    #[test]
    fn build_router_with_named_profiles() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let router = build_router(&config).unwrap();

        // API route with strict WAF
        let api = router.at("/api/v1/test").unwrap();
        assert_eq!(api.value.upstream_url[0], "http://127.0.0.1:8000");
        let waf = api.value.waf.as_ref().unwrap();
        assert_eq!(waf.max_body_mb, 5);
        assert_eq!(waf.max_depth, 8);

        // Upload route with upload WAF
        let upload = router.at("/upload").unwrap();
        let waf = upload.value.waf.as_ref().unwrap();
        assert_eq!(waf.max_body_mb, 200);

        // Static cache route
        let statics = router.at("/_next/static/chunk.js").unwrap();
        assert_eq!(statics.value.upstream_url[0], "http://127.0.0.1:3000");
        let cache = statics.value.cache.as_ref().unwrap();
        assert_eq!(cache.ttl_seconds, 86400);
        assert_eq!(cache.max_entries, 5000);

        // Catch-all has no WAF or cache
        let catchall = router.at("/about").unwrap();
        assert!(catchall.value.waf.is_none());
        assert!(catchall.value.cache.is_none());
    }

    #[test]
    fn legacy_waf_with_custom_body_limit() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
backend = "http://127.0.0.1:8000"
[[route]]
path = "/upload"
upstream = "backend"
waf = true
max_body_mb = 500
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at("/upload").unwrap();
        assert_eq!(route.value.waf.as_ref().unwrap().max_body_mb, 500);
    }

    #[test]
    fn static_cache_mode_auto_creates_cache_profile() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
fe = "http://127.0.0.1:3000"
[[route]]
path = "/_next/static/{*rest}"
upstream = "fe"
mode = "static_cache"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at("/_next/static/chunk.js").unwrap();
        assert!(route.value.cache.is_some());
        assert_eq!(route.value.cache.as_ref().unwrap().ttl_seconds, 31_536_000);
    }

    #[test]
    fn internal_only_route() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
backend = "http://127.0.0.1:8000"
[[route]]
path = "/metrics"
upstream = "backend"
internal_only = true
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at("/metrics").unwrap();
        assert!(route.value.internal_only);
    }

    #[test]
    fn route_mode_sse_stream() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
backend = "http://127.0.0.1:8000"
[[route]]
path = "/events"
upstream = "backend"
mode = "sse_stream"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at("/events").unwrap();
        assert_eq!(route.value.mode, RouteMode::SseStream);
    }

    #[test]
    fn tls_defaults() {
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(config.tls.min_version, "1.3");
        assert_eq!(config.tls.alpn, vec!["h2", "http/1.1"]);
        assert!(config.tls.hot_reload);
    }

    #[test]
    fn tls_custom_values() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
hot_reload = false
min_version = "1.2"
alpn = ["http/1.1"]
[[route]]
path = "/{*rest}"
upstream = "be"
[upstreams]
be = "http://127.0.0.1:8000"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.tls.hot_reload);
        assert_eq!(config.tls.min_version, "1.2");
        assert_eq!(config.tls.alpn, vec!["http/1.1"]);
    }

    #[test]
    fn err_on_unknown_upstream() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[[route]]
path = "/test"
upstream = "nonexistent"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let err = build_router(&config).unwrap_err();
        assert!(err.contains("Unknown upstream"), "got: {err}");
    }

    #[test]
    fn err_on_unknown_waf_profile() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
be = "http://127.0.0.1:8000"
[[route]]
path = "/test"
upstream = "be"
waf_profile = "nonexistent"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let err = build_router(&config).unwrap_err();
        assert!(err.contains("Unknown waf_profile"), "got: {err}");
    }

    #[test]
    fn err_on_unknown_cache_profile() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
be = "http://127.0.0.1:8000"
[[route]]
path = "/test"
upstream = "be"
cache_profile = "nonexistent"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let err = build_router(&config).unwrap_err();
        assert!(err.contains("Unknown cache_profile"), "got: {err}");
    }

    #[test]
    fn waf_profile_defaults() {
        let profile = WafProfile::default();
        assert_eq!(profile.max_body_mb, 10);
        assert_eq!(profile.max_depth, 10);
        assert_eq!(profile.max_string_len, 1_048_576);
        assert!(profile.deny_unknown_content_types);
        assert_eq!(
            profile.allowed_content_types,
            vec!["application/json", "multipart/form-data"]
        );
    }

    #[test]
    fn resolve_upstream_prefers_new_format_over_legacy() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstream.api]
url = "http://new:9000"
[upstreams]
api = "http://old:8000"
[[route]]
path = "/test"
upstream = "api"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at("/test").unwrap();
        // New [upstream.X] takes precedence over [upstreams] legacy
        assert_eq!(route.value.upstream_url[0], "http://new:9000");
    }
}
