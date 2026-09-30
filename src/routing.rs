// SPDX-License-Identifier: Apache-2.0
//! Route resolution: turns the parsed `[[route]]` / `[upstream.*]` schema in
//! `config.rs` into the runtime-shaped `ResolvedRoute` snapshot and the
//! host-aware radix `HostRouter` the request pipeline looks routes up in.
//!
//! Split out of `config.rs` (ZION-ARCH-02): `config` is the serde schema plus
//! validation; this module is the *resolve* step, so the runtime types it
//! produces (`auth::ResolvedAuthProfile`, `security::CorsHeaders`) are no longer
//! embedded in the schema module. The dependency runs one way: `routing` reads
//! `config`, never the reverse.

use crate::config::{
    catchall_bare_prefix, default_max_entries, default_ttl, trailing_slash_variant, CacheMode,
    CacheProfile, RouteConfig, RouteMode, RouteTarget, WafPolicy, WafProfile, ZionConfig,
};
use matchit::Router;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// RESOLVED ROUTE (fully resolved at startup, zero lookups at runtime)
// ============================================================================

#[derive(Clone, Debug)]
pub struct ResolvedRoute {
    #[allow(dead_code)]
    pub upstream_url: Vec<String>,
    /// TCP connect deadline for this route's upstream (ms; 0 = none). Selects the
    /// HTTP client whose connector enforces it — see `AppState::client_for`.
    pub connect_timeout_ms: u64,
    /// Pre-parsed URI parts — avoids full URI parse on every request.
    pub upstream_scheme: hyper::http::uri::Scheme,
    pub upstream_authority: hyper::http::uri::Authority,
    pub mode: RouteMode,
    /// For `RouteMode::Static`: the serve directory (not canonicalized here —
    /// existence is a per-request check so an imported config validates offline).
    pub serve_dir: Option<std::path::PathBuf>,
    /// SPA fallback (serve `index.html` on a miss) for `RouteMode::Static`.
    pub spa_fallback: bool,
    /// Serve `.br`/`.gz` sidecars via `Accept-Encoding` for `RouteMode::Static`.
    pub precompressed: bool,
    /// Literal path prefix stripped before the on-disk file lookup.
    pub static_prefix: String,
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

impl ResolvedRoute {
    /// May the plaintext `:80` listener hand an ACME-challenge request that no
    /// in-memory token matched to this route's upstream (for external clients such
    /// as certbot)? That fallback proxies without going through the request
    /// pipeline, so it skips the auth gate, `internal_only`, and the WAF. It is
    /// therefore only allowed for a route that has none of those protections to
    /// bypass, and one that actually has an upstream: a static route's placeholder
    /// upstream is `127.0.0.1`, which would send the request to a local port 80.
    /// ACME challenge paths are public by nature (the CA fetches them without
    /// credentials), so serve them from a route that is public too.
    pub fn serves_acme_fallback(&self) -> bool {
        #[cfg(feature = "auth")]
        let authed = self.auth.is_some();
        #[cfg(not(feature = "auth"))]
        let authed = false;
        !self.internal_only && !authed && self.mode != RouteMode::Static
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

/// Host-aware L7 router (ADR-0010). Holds the hostless/shared radix tree, one
/// tree per exact bound host, and one tree per `*.suffix` wildcard. A route with
/// no `hosts` lands in `default` and is reachable from every authority (the
/// shared fallback layer). When no route declares `hosts`, `active` is false and
/// lookups go straight to `default` — identical, and identically cheap, to the
/// pre-host-routing single router. Precedence: exact host > most-specific
/// wildcard > shared.
#[derive(Debug)]
pub struct HostRouter {
    /// Hostless / shared routes — matched for every authority.
    default: Router<Arc<ResolvedRoute>>,
    /// Exact-host radix trees, keyed by normalized authority.
    by_host: HashMap<Box<str>, Router<Arc<ResolvedRoute>>>,
    /// Wildcard trees keyed by their dotted suffix (`*.example.com` →
    /// `.example.com`), sorted longest-suffix-first so the most specific wins.
    /// A request host matches when it `ends_with` the suffix.
    wildcards: Vec<(String, Router<Arc<ResolvedRoute>>)>,
    /// True iff at least one route is host-bound (exact or wildcard). Lets the
    /// hot path skip authority extraction entirely in the hostless deployment.
    active: bool,
}

impl Default for HostRouter {
    fn default() -> Self {
        Self {
            default: Router::new(),
            by_host: HashMap::new(),
            wildcards: Vec::new(),
            active: false,
        }
    }
}

impl HostRouter {
    /// Whether any host-bound route exists. Callers gate authority extraction
    /// and cache-key hashing on this, so a hostless deployment pays nothing.
    #[inline]
    pub fn host_routing_active(&self) -> bool {
        self.active
    }

    /// Resolve `(host, path)` to a route, per ADR-0010's hostless-as-shared-layer
    /// rule with precedence exact > wildcard > shared: an exact-host tree wins;
    /// otherwise the most-specific matching `*.suffix` wildcard; then the shared
    /// `default` tree. On a path-miss within the selected host tree we still fall
    /// through to shared (shared routes are reachable from every host). `host` is
    /// the normalized request authority ([`crate::security::normalize_host`]), or
    /// `None` when absent/invalid — then only the shared layer is consulted.
    #[inline]
    pub fn at(&self, host: Option<&str>, path: &str) -> Option<&Arc<ResolvedRoute>> {
        if self.active {
            if let Some(h) = host {
                if let Some(tree) = self.by_host.get(h) {
                    // Exact host wins outright (nginx-style); path-miss → shared.
                    if let Ok(m) = tree.at(path) {
                        return Some(m.value);
                    }
                } else {
                    // No exact host: the most-specific matching wildcard, if any.
                    // `wildcards` is sorted longest-suffix-first, so the first
                    // `ends_with` hit is the most specific one.
                    for (suffix, tree) in &self.wildcards {
                        if h.ends_with(suffix.as_str()) {
                            if let Ok(m) = tree.at(path) {
                                return Some(m.value);
                            }
                            break; // most-specific wildcard chosen; fall to shared
                        }
                    }
                }
            }
        }
        self.default.at(path).ok().map(|m| m.value)
    }
}

/// Accumulates the routes of a single host-group into one radix tree, deferring
/// the catch-all bare-prefix and trailing-slash aliases until every explicit
/// route of the group is inserted (so an explicit route always wins a conflict).
struct RouterBuilder {
    router: Router<Arc<ResolvedRoute>>,
    aliases: Vec<(String, Arc<ResolvedRoute>)>,
}

impl Default for RouterBuilder {
    fn default() -> Self {
        Self {
            router: Router::new(),
            aliases: Vec::new(),
        }
    }
}

impl RouterBuilder {
    /// Insert one explicit route and record its bare-prefix / trailing-slash
    /// alias for the deferred second pass.
    fn insert(&mut self, path: &str, resolved: Arc<ResolvedRoute>) -> Result<(), String> {
        // A matchit catch-all "<prefix>/{*name}" does NOT match the bare
        // "<prefix>" (nor the root "/" when the prefix is empty), so a
        // "/{*rest}" route silently 404s on "/" even though it is meant to be
        // the fallback for everything. Record the bare prefix so we can also
        // map it to this route in a second pass (after all explicit routes).
        match catchall_bare_prefix(path) {
            Some(bare) => {
                self.router
                    .insert(path.to_string(), resolved.clone())
                    .map_err(|e| format!("Bad route pattern '{path}': {e}"))?;
                self.aliases.push((bare, resolved));
            }
            None => {
                // Non-catch-all: also alias the trailing-slash-toggled variant
                // so "/x" and "/x/" resolve to the SAME route. matchit treats
                // them as distinct, so "/x/" would otherwise fall through to a
                // different (often more permissive) route — e.g. a stricter
                // per-route WAF profile silently downgraded.
                match trailing_slash_variant(path) {
                    Some(variant) => {
                        self.router
                            .insert(path.to_string(), resolved.clone())
                            .map_err(|e| format!("Bad route pattern '{path}': {e}"))?;
                        self.aliases.push((variant, resolved));
                    }
                    None => {
                        self.router
                            .insert(path.to_string(), resolved)
                            .map_err(|e| format!("Bad route pattern '{path}': {e}"))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Apply the deferred aliases and return the finished tree. Alias inserts
    /// are best-effort: a conflict means an explicit route already owns the
    /// slot — exactly the precedence we want (matchit specificity then makes an
    /// exact prefix win over a less-specific parent catch-all, e.g. "/api" →
    /// "/api/{*rest}", not the root "/{*rest}").
    fn finish(mut self) -> Router<Arc<ResolvedRoute>> {
        for (alias, resolved) in self.aliases {
            let _ = self.router.insert(alias, resolved);
        }
        self.router
    }
}

/// Build the host-aware router from config routes, pre-resolving all references.
/// A route with `hosts` is inserted into each of its host trees; a route without
/// `hosts` goes into the shared/default tree (ADR-0010, hostless-as-shared).
///
/// Returns `Err` if any route references an unknown upstream, profile, or
/// contains an invalid pattern. The caller (boot path or hot-reload) decides
/// whether to abort or log-and-keep the previous snapshot.
pub fn build_router(config: &ZionConfig) -> Result<HostRouter, String> {
    let router = build_router_quiet(config)?;
    print_routes_table(&config.route);
    Ok(router)
}

/// [`build_router`] without the boot-banner routes table — for callers that
/// build a router as a validation step, not to serve traffic (`zion import`'s
/// self-validation gate, ADR-0011).
pub fn build_router_quiet(config: &ZionConfig) -> Result<HostRouter, String> {
    let mut default = RouterBuilder::default();
    let mut by_host: HashMap<Box<str>, RouterBuilder> = HashMap::new();

    let mut wild: HashMap<String, RouterBuilder> = HashMap::new();

    for route in &config.route {
        let resolved = resolve_route(config, route)?;
        match &route.hosts {
            // Shared route: reachable from every authority.
            None => default.insert(&route.path, resolved)?,
            // Host-bound. Validation guarantees each entry is either a canonical
            // exact host or a `*.<canonical-domain>` wildcard.
            Some(hosts) => {
                let mut seen_exact = std::collections::HashSet::new();
                let mut seen_wild = std::collections::HashSet::new();
                for h in hosts {
                    if let Some(rest) = h.strip_prefix("*.") {
                        // Wildcard: the match key is the dotted, normalized
                        // suffix (`*.example.com` → `.example.com`).
                        let domain = crate::security::normalize_host(rest).ok_or_else(|| {
                            format!("route '{}': invalid wildcard host '{}'", route.path, h)
                        })?;
                        let suffix = format!(".{domain}");
                        // A suffix repeated in one route's list inserts once.
                        if !seen_wild.insert(suffix.clone()) {
                            continue;
                        }
                        wild.entry(suffix)
                            .or_default()
                            .insert(&route.path, resolved.clone())?;
                    } else {
                        let key = crate::security::normalize_host(h)
                            .ok_or_else(|| format!("route '{}': invalid host '{}'", route.path, h))?
                            .into_owned();
                        // A host repeated in one route's list must insert once,
                        // not twice into the same tree (matchit rejects a dup).
                        if !seen_exact.insert(key.clone()) {
                            continue;
                        }
                        by_host
                            .entry(key.into_boxed_str())
                            .or_default()
                            .insert(&route.path, resolved.clone())?;
                    }
                }
            }
        }
    }

    let active = !by_host.is_empty() || !wild.is_empty();
    let by_host = by_host
        .into_iter()
        .map(|(host, builder)| (host, builder.finish()))
        .collect();
    // Longest suffix first so the most specific wildcard wins at lookup; the
    // content tiebreak keeps the order deterministic across rebuilds.
    let mut wildcards: Vec<(String, Router<Arc<ResolvedRoute>>)> = wild
        .into_iter()
        .map(|(suffix, builder)| (suffix, builder.finish()))
        .collect();
    wildcards.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));

    Ok(HostRouter {
        default: default.finish(),
        by_host,
        wildcards,
        active,
    })
}

/// Resolve one `[[route]]` into its fully pre-computed [`ResolvedRoute`]
/// (upstream URLs, WAF/cache profiles, CSP, auth, CORS) — everything the hot
/// path needs, computed once at build. Pure: no router insertion, so
/// `build_router` can place the result into one or more host-scoped trees.
fn resolve_route(config: &ZionConfig, route: &RouteConfig) -> Result<Arc<ResolvedRoute>, String> {
    // A static route (ADR-0015) serves from disk and needs no upstream — ignore
    // any stray `upstream` field so `validate_semantics` and `build_router`
    // agree (both skip the upstream for a static route).
    let upstream_url = match &route.target {
        RouteTarget::Static { .. } => Vec::new(),
        RouteTarget::Upstream { name, .. } => resolve_upstream(config, name)?,
    };

    // Resolve WAF from the route's single policy value.
    let waf = match &route.waf {
        WafPolicy::Profile(profile_name) => Some(
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
        ),
        // Legacy `waf = true`: an inline profile from max_body_mb.
        WafPolicy::Inline { max_body_mb } => Some(WafProfile {
            max_body_mb: max_body_mb.unwrap_or(10),
            ..WafProfile::default()
        }),
        WafPolicy::Off {
            ignored_max_body_mb,
        } => {
            // Footgun guard: `max_body_mb` is enforced by the WAF body gate, so
            // on a WAF-off route it has no effect. Surface it at boot rather
            // than silently dropping the operator's intended size cap (a no-WAF
            // route otherwise streams the body to the upstream, hyper-framed).
            if ignored_max_body_mb.is_some() {
                eprintln!(
                    "  ⚠ route '{}': max_body_mb is set but WAF is off (no waf=true / waf_profile) \
                     — the body-size cap is NOT enforced; enable WAF or remove max_body_mb",
                    route.path
                );
            }
            None
        }
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
    } else if route.mode() == RouteMode::StaticCache {
        // Default in-RAM profile for a profile-less static_cache route:
        // conservative 1h TTL (default_ttl), NOT immutable. Name an explicit
        // [cache_profile] with a longer ttl_seconds for content-hashed assets.
        Some(CacheProfile {
            mode: CacheMode::Memory,
            max_entries: default_max_entries(),
            ttl_seconds: default_ttl(),
        })
    } else {
        None
    };

    // Pre-parse the FIRST upstream URI at startup for legacy fallback. A static
    // route has no upstream, so it gets placeholder parts the Static dispatch
    // arm never reads.
    let (upstream_scheme, upstream_authority) = if upstream_url.is_empty() {
        ("http".parse().unwrap(), "127.0.0.1".parse().unwrap())
    } else {
        let upstream_uri: hyper::Uri = upstream_url[0]
            .parse()
            .map_err(|e| format!("Invalid upstream URL '{}': {}", upstream_url[0], e))?;
        let scheme = upstream_uri
            .scheme()
            .cloned()
            .unwrap_or_else(|| "http".parse().unwrap());
        let authority = upstream_uri
            .authority()
            .cloned()
            .ok_or_else(|| format!("Upstream '{}' has no authority", upstream_url[0]))?;
        (scheme, authority)
    };

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
            let resolved = crate::auth::resolve_auth_profile(profile_config)
                .map_err(|e| format!("Auth profile '{}' (route '{}'): {}", name, route.path, e))?;
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

    // Static file serving (ADR-0015): the serve dir + the literal prefix to
    // strip from the request path. Not canonicalized here — existence is a
    // per-request check so an imported config validates offline.
    let (serve_dir, spa_fallback, precompressed, static_prefix) = match &route.target {
        RouteTarget::Static {
            serve_dir,
            spa_fallback,
            precompressed,
        } => {
            let prefix = route
                .path
                .split("{*")
                .next()
                .unwrap_or("/")
                .trim_end_matches('/')
                .to_string();
            (
                Some(std::path::PathBuf::from(serve_dir)),
                *spa_fallback,
                *precompressed,
                prefix,
            )
        }
        RouteTarget::Upstream { .. } => (None, false, false, String::new()),
    };

    Ok(Arc::new(ResolvedRoute {
        upstream_url,
        connect_timeout_ms: route
            .upstream_name()
            .and_then(|name| config.upstream.get(name))
            .map(|u| u.connect_timeout_ms)
            .unwrap_or(crate::proxy::DEFAULT_CONNECT_TIMEOUT_MS),
        upstream_scheme,
        upstream_authority,
        mode: route.mode(),
        serve_dir,
        spa_fallback,
        precompressed,
        static_prefix,
        waf,
        waf_shadow: route.waf_shadow,
        cache,
        internal_only: route.internal_only,
        csp,
        #[cfg(feature = "auth")]
        auth,
        cors,
    }))
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
            route.upstream_name().unwrap_or(""),
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

    match route.mode() {
        RouteMode::SseStream => tags.push(format!("{cyan}sse{reset}")),
        RouteMode::Websocket => tags.push(format!("{cyan}ws{reset}")),
        RouteMode::StaticCache => tags.push(format!("{cyan}static{reset}")),
        RouteMode::Static => tags.push(format!("{cyan}files{reset}")),
        RouteMode::Standard => {}
    }
    if route.waf.is_enabled() {
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
    use crate::config::UpstreamMode;

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

    fn route(path: &str) -> RouteConfig {
        RouteConfig {
            path: path.into(),
            hosts: None,
            target: RouteTarget::Upstream {
                name: "backend".into(),
                mode: UpstreamMode::Standard,
            },
            internal_only: false,
            waf: WafPolicy::Off {
                ignored_max_body_mb: None,
            },
            waf_shadow: false,
            cache_profile: None,
            csp: None,
            auth_profile: None,
            cors: None,
        }
    }

    /// The same route with a different proxying flavour.
    fn with_mode(mut r: RouteConfig, mode: UpstreamMode) -> RouteConfig {
        r.target = RouteTarget::Upstream {
            name: "backend".into(),
            mode,
        };
        r
    }

    #[test]
    fn route_tags_plain_passthrough_is_empty() {
        let r = route("/static");
        assert_eq!(render_route_tags(&r, false), "");
    }

    #[test]
    fn route_tags_waf_only() {
        let mut r = route("/api");
        r.waf = WafPolicy::Inline { max_body_mb: None };
        assert_eq!(render_route_tags(&r, false), "waf");
    }

    #[test]
    fn route_tags_named_waf_profile_counts() {
        let mut r = route("/api");
        r.waf = WafPolicy::Profile("strict".into());
        assert_eq!(render_route_tags(&r, false), "waf");
    }

    #[test]
    fn route_tags_static_with_cache() {
        let mut r = route("/_next/static");
        r = with_mode(r, UpstreamMode::StaticCache);
        r.cache_profile = Some("immutable".into());
        // Mode tag first, then perf tag
        assert_eq!(render_route_tags(&r, false), "static · cache");
    }

    #[test]
    fn route_tags_sse_stream() {
        let mut r = route("/events");
        r = with_mode(r, UpstreamMode::SseStream);
        assert_eq!(render_route_tags(&r, false), "sse");
    }

    #[test]
    fn route_tags_websocket() {
        let mut r = route("/ws");
        r = with_mode(r, UpstreamMode::Websocket);
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
        r.waf = WafPolicy::Inline { max_body_mb: None };
        assert_eq!(render_route_tags(&r, false), "waf");
        // waf=true + shadow → "waf:shadow" so the visual distinction is
        // unmissable when scanning the boot output.
        r.waf_shadow = true;
        assert_eq!(render_route_tags(&r, false), "waf:shadow");
    }

    #[test]
    fn route_tags_shadow_with_named_profile() {
        let mut r = route("/api");
        r.waf = WafPolicy::Profile("strict".into());
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
        r.waf = WafPolicy::Inline { max_body_mb: None };
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
        let route = router.at(None, "/test").unwrap();
        // New [upstream.X] takes precedence over [upstreams] legacy
        assert_eq!(route.upstream_url[0], "http://new:9000");
    }

    #[test]
    fn host_router_exact_and_shared_fallback() {
        // Two host-bound routes on the SAME path + a shared catch-all — exactly
        // what path-only routing could not express (ADR-0010).
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstream.api]
url = "http://127.0.0.1:8000"
[upstream.app]
url = "http://127.0.0.1:3000"
[upstream.fallback]
url = "http://127.0.0.1:9000"
[[route]]
path = "/{*rest}"
hosts = ["api.example.com"]
upstream = "api"
[[route]]
path = "/{*rest}"
hosts = ["app.example.com"]
upstream = "app"
[[route]]
path = "/{*rest}"
upstream = "fallback"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        assert!(router.active);

        // Same path, different host → different backend (the whole point).
        assert_eq!(
            router
                .at(Some("api.example.com"), "/x")
                .unwrap()
                .upstream_url[0],
            "http://127.0.0.1:8000"
        );
        assert_eq!(
            router
                .at(Some("app.example.com"), "/x")
                .unwrap()
                .upstream_url[0],
            "http://127.0.0.1:3000"
        );
        // Unknown host → shared/default layer.
        assert_eq!(
            router
                .at(Some("other.example.com"), "/x")
                .unwrap()
                .upstream_url[0],
            "http://127.0.0.1:9000"
        );
        // No host (e.g. HTTP/1.0) → shared layer.
        assert_eq!(
            router.at(None, "/x").unwrap().upstream_url[0],
            "http://127.0.0.1:9000"
        );
    }

    #[test]
    fn hostless_config_is_not_active() {
        // No route declares `hosts` ⇒ host routing inactive ⇒ the shared tree
        // behaves exactly as the pre-ADR-0010 single router.
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        let router = build_router(&config).unwrap();
        assert!(!router.active);
        // A host is simply ignored — everything resolves via the shared tree.
        assert!(router.at(Some("whatever.example.com"), "/api/x").is_some());
        assert!(router.at(None, "/api/x").is_some());
    }

    #[test]
    fn host_router_wildcard_and_precedence() {
        fn url<'a>(r: &'a HostRouter, host: &str, path: &str) -> &'a str {
            r.at(Some(host), path)
                .expect("route should resolve")
                .upstream_url[0]
                .as_str()
        }
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstream.exact]
url = "http://127.0.0.1:8000"
[upstream.wild]
url = "http://127.0.0.1:8001"
[upstream.deep]
url = "http://127.0.0.1:8002"
[upstream.shared]
url = "http://127.0.0.1:9000"
[[route]]
path = "/{*rest}"
hosts = ["api.example.com"]
upstream = "exact"
[[route]]
path = "/{*rest}"
hosts = ["*.example.com"]
upstream = "wild"
[[route]]
path = "/{*rest}"
hosts = ["*.api.example.com"]
upstream = "deep"
[[route]]
path = "/{*rest}"
upstream = "shared"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        assert!(router.active);

        // Exact host beats any wildcard.
        assert_eq!(
            url(&router, "api.example.com", "/x"),
            "http://127.0.0.1:8000"
        );
        // A subdomain with no exact entry matches the wildcard.
        assert_eq!(
            url(&router, "foo.example.com", "/x"),
            "http://127.0.0.1:8001"
        );
        // The most-specific wildcard wins (`*.api.example.com` > `*.example.com`).
        assert_eq!(
            url(&router, "v1.api.example.com", "/x"),
            "http://127.0.0.1:8002"
        );
        // The apex (no leading label) does NOT match `*.example.com` → shared.
        assert_eq!(url(&router, "example.com", "/x"), "http://127.0.0.1:9000");
        // An unrelated host → shared.
        assert_eq!(url(&router, "other.org", "/x"), "http://127.0.0.1:9000");
    }

    #[test]
    fn acme_fallback_is_refused_for_routes_with_something_to_bypass() {
        // ZION-AUTH-02: the plaintext :80 ACME fallback skips auth, internal_only
        // and the WAF, and a static route's placeholder upstream is 127.0.0.1.
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n";
        let cfg =
            |routes: &str| -> ZionConfig { toml::from_str(&format!("{base}{routes}")).unwrap() };
        let c = cfg("[[route]]\npath=\"/public/{*rest}\"\nupstream=\"be\"\n\
             [[route]]\npath=\"/internal/{*rest}\"\nupstream=\"be\"\ninternal_only=true\n\
             [[route]]\npath=\"/site/{*rest}\"\nmode=\"static\"\nserve_dir=\"/srv\"\n");
        let router = build_router_quiet(&c).unwrap();
        let get = |p: &str| router.at(None, p).unwrap().clone();
        assert!(
            get("/public/x").serves_acme_fallback(),
            "a plain public route may"
        );
        assert!(
            !get("/internal/x").serves_acme_fallback(),
            "internal_only must not"
        );
        assert!(
            !get("/site/x").serves_acme_fallback(),
            "static has no real upstream"
        );
    }

    #[cfg(feature = "auth")]
    #[test]
    fn acme_fallback_is_refused_for_an_authenticated_route() {
        // The finding's exact scenario: a catch-all protected by auth_profile must
        // not be reachable on :80 without a token via the ACME fallback.
        let toml = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [auth_profile.p]\nsecret=\"unit-test-secret\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\nauth_profile=\"p\"\n";
        let c: ZionConfig = toml::from_str(toml).unwrap();
        let router = build_router_quiet(&c).unwrap();
        let rule = router.at(None, "/.well-known/acme-challenge/x").unwrap();
        assert!(
            !rule.serves_acme_fallback(),
            "auth-protected route must not bypass auth on :80"
        );
    }
}
