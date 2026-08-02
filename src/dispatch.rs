// SPDX-License-Identifier: Apache-2.0
//! Request dispatch — the per-request state machine.
//!
//! Sits between the TLS listener and the upstream/cache. For each
//! accepted request it walks the pipeline:
//!
//!   1. inline fast-path (`/healthz`, `/readyz`, `/metrics`,
//!      `/_zion/snapshot.json`)
//!   2. security gates (URI length, method whitelist, rate limiter,
//!      CORS pre-flight)
//!   3. radix routing → `Arc<ResolvedRoute>`
//!   4. WAF pipeline (content-type, size, structural validation,
//!      entropy, Aho-Corasick scan)
//!   5. cache lookup or upstream proxy
//!   6. response hardening (security headers, hop-by-hop strip)
//!
//! Hot path: zero allocation in the common case. Everything that turns
//! a `Request` into a `Response` lives here or is called from here.

use crate::audit;
use crate::audit::AuditEvent;
use crate::proxy::ZionBody;
use crate::{
    cache, config, health, logging, metrics, observability, proxy, security, waf, AppState,
};
use crate::{
    empty_response, generate_request_id, inject_security_headers, method_not_allowed,
    text_response, REQUEST_COUNTER,
};
// `unauthorized` is only referenced from the JWT/OIDC auth gate.
#[cfg(feature = "auth")]
use crate::unauthorized;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "auth")]
use crate::auth;

use crate::config::ResolvedRoute;
use http_body_util::Limited;

/// Issue #151: turn an enforcement *deny* into a bounded held (tarpit)
/// response when the operator enabled it, otherwise the plain immediate
/// rejection. Bounded by the global ceiling — at capacity it sheds back to
/// the immediate reject, so the tarpit can never become a self-DoS. The
/// request is denied either way; the tarpit only changes *how long* the
/// flagged client waits for the refusal.
#[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
async fn deny_or_tarpit(
    enforce: &crate::sovereign::EnforcePolicy,
    status: StatusCode,
) -> Response<ZionBody> {
    use std::sync::atomic::Ordering::Relaxed;
    if enforce.tarpit_enabled {
        match crate::tarpit::try_enter(enforce.tarpit_max_concurrent) {
            Some(_guard) => {
                metrics::METRICS.tarpit_total.fetch_add(1, Relaxed);
                tokio::time::sleep(enforce.tarpit_hold).await;
                // `_guard` drops here: active gauge--, held-time recorded.
            }
            None => {
                // Ceiling full — shed to the immediate rejection.
                metrics::METRICS.tarpit_shed_total.fetch_add(1, Relaxed);
            }
        }
    }
    empty_response(status)
}

const MAX_URI_LEN: usize = 8192;
const MAX_CACHEABLE_BODY: usize = 50 * 1024 * 1024;

/// Per-frame idle timeout while reading a request body on the streaming WAF
/// path: if no body frame arrives within this window the client is trickling
/// (slow-read / slowloris-body) and we evict it with 408. This bounds the idle
/// time *between* reads rather than total upload time, so a legit large upload
/// over a slow-but-steady link is not penalised.
const BODY_FRAME_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Total timeout for buffering a request body on the non-streaming path (the
/// smaller default bodies). A trickled body trips this long before a legit
/// upload near `max_body_mb` would.
const BODY_COLLECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

const CACHE_CONTROL_IMMUTABLE: &str = "public, max-age=31536000, immutable";

#[inline]
fn check_rate_limit(state: &AppState, ip: std::net::IpAddr) -> bool {
    let cfg = state.cfg();
    security::check_rate_limit(
        cfg.rate_limit_rps,
        cfg.rate_limit_window,
        &state.rate_map,
        ip,
    )
}

/// Emit a `request_blocked` audit event when a WAF gate denies a request.
/// Cheap: when the audit subsystem is disabled, the underlying
/// `AuditHandle::emit` is a no-op and the only cost is a single Arc deref
/// + a redact lookup.
///
/// Source labels:
///   * `"uri"`     — pre-routing URI scan denied the path/query.
///   * `"body"`    — body-bearing method (POST/PUT/PATCH/DELETE) failed validation.
///   * `"headers"` — idempotent method (GET/HEAD/DELETE/OPTIONS) failed header validation.
fn emit_waf_block(
    state: &AppState,
    remote_addr: &SocketAddr,
    method: &str,
    path: &str,
    source: &'static str,
    reason: &str,
) {
    // Apply path redaction — query params can carry secrets (auth=…, token=…).
    // We only redact the query string; the path itself is rarely sensitive
    // and an auditor needs it to investigate the rule firing.
    let path_safe: String = match path.split_once('?') {
        Some((p, q)) => {
            let q_redacted = state.redact.redact_query_string(q);
            format!("{p}?{q_redacted}")
        }
        None => path.to_string(),
    };

    state.audit.emit(AuditEvent {
        seq: 0, // assigned by the writer task
        ts: String::new(),
        kind: "request_blocked",
        trace_id: None,
        remote_ip: Some(remote_addr.ip().to_string()),
        method: Some(method.to_string()),
        path: Some(path_safe),
        detail: Some(format!("waf:{source}:{reason}")),
    });

    // ── AIMP control-plane publish (Track B) ────────────────────────
    // Tell the gossip mesh that *this* zion node has just blocked
    // `remote_addr.ip()`. Best-effort: if the queue is full or the
    // control plane is not bootstrapped, we drop the publish. The
    // local block has already happened; gossip is purely informational.
    #[cfg(feature = "sovereign-aimp")]
    if let Some(cp) = state.aimp_cp.as_ref() {
        // Map source label → numeric reason for the wire payload.
        let reason_code: u8 = match source {
            "uri" | "body" | "headers" => 1, // legacy WAF gate
            "ml" => 2,                       // ML scorer (Track C)
            _ => 0,                          // generic
        };
        let _ = cp.publish_block(remote_addr.ip(), 1.0, reason_code);
    }
}

/// Public entry point. Runs the full pipeline via `process_request_inner`,
/// then applies the response security headers to EVERY outcome — the success
/// path AND all the early-return error branches (WAF deny, 405, 413, 431,
/// 425, ...) — in one place. Previously HSTS / X-Content-Type-Options /
/// X-Frame-Options / referrer-policy / permissions-policy were only set on the
/// success path, so Zion-generated error responses shipped without them.
/// inject_security_headers is idempotent (insert), so the few inner call sites
/// are harmless. Also echoes the client's X-Request-ID on error responses for
/// correlation.
pub(crate) async fn process_request(
    req: Request<ZionBody>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
    is_early_data: bool,
) -> Result<Response<ZionBody>, hyper::Error> {
    let client_request_id = req.headers().get("X-Request-ID").cloned();
    let mut resp = process_request_inner(req, state, remote_addr, is_early_data).await?;
    inject_security_headers(&mut resp);
    if !resp.headers().contains_key("X-Request-ID") {
        if let Some(id) = client_request_id {
            resp.headers_mut().insert("X-Request-ID", id);
        }
    }
    Ok(resp)
}

/// RFC 8470 §5.2: TLS 1.3 early data (0-RTT) is replay-vulnerable — a network
/// adversary who captures the ClientHello + early data can replay it. Only
/// safe/idempotent methods may ride in 0-RTT; a state-changing method replayed
/// from early data could duplicate effects, so it gets **425 Too Early** and
/// the client retries once the handshake completes. Returns `true` when the
/// request MUST be rejected. Pure + unit-tested — guards the otherwise
/// untestable `main.rs → dispatch.rs` `was_early` plumbing against a silent
/// regression that would re-enable non-idempotent 0-RTT replay.
fn early_data_rejected(is_early_data: bool, method: &hyper::Method) -> bool {
    is_early_data && !matches!(*method, hyper::Method::GET | hyper::Method::HEAD)
}

/// Thread-local route-cache key. Folds the normalized host into the key when a
/// host is present (host routing active) so two authorities that share a path
/// never collide — the ADR-0010 cache invariant. A collision would let one
/// host's request reuse another host's cached `ResolvedRoute`, bypassing a
/// per-route WAF/auth profile or an `internal_only` gate. With `host = None`
/// the key is the bare path hash, byte-identical to the pre-host-routing key,
/// so hostless deployments are unchanged. `str`'s `Hash` writes a terminator,
/// so `(host, path)` can never alias a different host/path split.
#[inline]
fn route_cache_key(host: Option<&str>, path: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = fnv::FnvHasher::default();
    if let Some(host) = host {
        host.hash(&mut h);
    }
    path.hash(&mut h);
    h.finish()
}

async fn process_request_inner(
    mut req: Request<ZionBody>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
    is_early_data: bool,
) -> Result<Response<ZionBody>, hyper::Error> {
    let request_start = std::time::Instant::now();

    // Snapshot the config once. The same `Arc<ResolvedAppConfig>` is
    // used throughout this request, so route lookup, WAF gating, and
    // upstream selection all see the same generation even if a
    // hot-reload swaps in a new snapshot mid-flight. Cost: ~5 ns
    // (Acquire load + Arc refcount bump).
    let cfg = state.cfg();

    // ── Pre-routing security gates (zero-cost, before any processing) ──

    // Gate: URI length (reject oversized URIs before routing).
    // Check full path+query, not just path — an attacker could send a short
    // path with an enormous query string to consume memory downstream.
    let uri_len = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().len())
        .unwrap_or_else(|| req.uri().path().len());
    if uri_len > MAX_URI_LEN {
        return Ok(empty_response(StatusCode::URI_TOO_LONG));
    }

    // Gate: HTTP method whitelist (block TRACE/CONNECT/exotic methods)
    if !matches!(
        *req.method(),
        hyper::Method::GET
            | hyper::Method::POST
            | hyper::Method::PUT
            | hyper::Method::PATCH
            | hyper::Method::DELETE
            | hyper::Method::HEAD
            | hyper::Method::OPTIONS
    ) {
        return Ok(method_not_allowed(
            "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
        ));
    }

    // Gate: 0-RTT replay protection (RFC 8470 — 425 Too Early).
    // TLS 1.3 early data is inherently replay-vulnerable. Only idempotent
    // methods (GET/HEAD) are safe — state-changing methods could be replayed
    // by a network adversary capturing the ClientHello + early data.
    if early_data_rejected(is_early_data, req.method()) {
        // SAFETY: 425 "Too Early" (RFC 8470) is a valid HTTP status code in
        // the 100..1000 range that hyper accepts. The literal `425` is a
        // compile-time constant; `from_u16` rejects only out-of-range u16s.
        return Ok(empty_response(StatusCode::from_u16(425).unwrap()));
    }

    // ── Resolve real client IP (proxy-aware) ──
    // When trusted_proxies is configured, extract the real client IP from
    // X-Forwarded-For using the rightmost-untrusted-hop algorithm.
    // This prevents rate limit bypass and internal-only gate evasion when
    // Zion is behind ALB/Cloudflare/nginx.
    let client_ip = cfg.trusted_proxies.resolve_client_ip(
        remote_addr.ip(),
        req.headers()
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok()),
    );
    // SocketAddr wrapper for proxy::proxy_pass*, which extracts only the IP.
    // The port is irrelevant for forwarding headers — using 0 is safe.
    // We intentionally pass the *resolved* client IP (not the TCP peer)
    // so XffMode::Rewrite emits the trusted real-client value rather than
    // the upstream proxy's address.
    let forward_addr = SocketAddr::new(client_ip, 0);

    // Gate: per-IP rate limit (zero cost when disabled)
    // Placed BEFORE health endpoints so /healthz can't bypass rate limiting for DDoS.
    if !check_rate_limit(&state, client_ip) {
        metrics::METRICS
            .rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(empty_response(StatusCode::TOO_MANY_REQUESTS));
    }

    // ── Sovereign Edge: IP classification (zero cost when feature is off or disabled) ──
    //
    // Track D fix: previously this branch did `format!("ip=… class=…")` once
    // per *every* request when `sovereign_log_classification` was on — that's
    // a heap allocation on the hot path with no opt-out. We now:
    //
    //   1. Always bump a per-class atomic counter (4 ns) so /metrics carries
    //      `zion_sovereign_classifications_total{class="…"}` whether the
    //      operator opted into logging or not.
    //   2. When `log_classification = true`, emit a zero-alloc
    //      `tracing::info!()` event using the class's `&'static str` label
    //      and `Display` impl for the IP. The event is a no-op when no
    //      subscriber consumes it; with the JSON subscriber attached it
    //      still beats `format!` because the formatter writes directly to
    //      the subscriber's buffer instead of materialising a `String`.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    {
        use crate::sovereign;
        if cfg.sovereign_enabled {
            let ip_class = sovereign::classify(client_ip);
            sovereign::record_classification(ip_class);
            req.extensions_mut().insert(ip_class);
            // Tag-driven enforcement (#150): deny classes the operator
            // opted in. Off by default; the local WAF / rate-limit / auth
            // gates stay authoritative — this only adds a deny on top.
            if cfg.enforce.denies_class(ip_class.as_str()) {
                metrics::METRICS
                    .enforcement_denied_class
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(deny_or_tarpit(&cfg.enforce, StatusCode::FORBIDDEN).await);
            }
            if cfg.sovereign_log_classification && ip_class != sovereign::IpClass::Unknown {
                tracing::info!(
                    target: "sovereign",
                    ip = %client_ip,
                    class = ip_class.as_str(),
                    "classified",
                );
            }
        }
    }

    // ── AIMP mesh score lookup (signal, not gate) ──
    //
    // If the AIMP control plane is up and has a reputation entry for
    // `client_ip` (received via gossip from another zion node), inject
    // the score into the request headers as `X-Zion-Mesh-Score`. The
    // header travels to the upstream so application code can use it
    // as one more signal alongside its own anti-abuse logic.
    //
    // We deliberately do NOT use this score as a hard gate here — the
    // local WAF / rate-limiter / auth decisions remain authoritative.
    // The mesh is advisory only, by design (see issue #65).
    #[cfg(feature = "sovereign-aimp")]
    if let Some(cp) = state.aimp_cp.as_ref() {
        if let Some(rep) = cp.lookup(&client_ip) {
            // Issue #69: count score-lookup hits. Bumped on the
            // *positive* path only — the bare `cp.is_some()` is not
            // a useful signal because every request takes that
            // branch when the feature is on; the operator wants to
            // see the rate of mesh-influenced requests.
            metrics::METRICS
                .mesh_score_lookups
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Tag-driven enforcement (#150): deny low-reputation sources
            // when the operator set a threshold. Promotes the mesh score
            // from advisory header to optional hard gate (ADR-0008). The
            // policy lives under the geo-gated `[sovereign]` block, so this
            // deny is only compiled when geo is on too.
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            if cfg.enforce.denies_score(rep.score) {
                metrics::METRICS
                    .enforcement_denied_mesh_score
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(deny_or_tarpit(&cfg.enforce, StatusCode::FORBIDDEN).await);
            }
            // 3 decimals so log/grep humans see a stable string;
            // upstreams parse as f32 and tolerate any precision.
            let formatted = format!("{:.3}", rep.score);
            if let Ok(val) = hyper::header::HeaderValue::from_str(&formatted) {
                req.headers_mut().insert(
                    hyper::header::HeaderName::from_static("x-zion-mesh-score"),
                    val,
                );
            }
        }
    }

    // ── Built-in health endpoints (no routing, no upstream) ──
    {
        let path = req.uri().path();
        if path == "/healthz" {
            return Ok(text_response(StatusCode::OK, "ok"));
        }
        if path == "/readyz" {
            return Ok(text_response(StatusCode::OK, "ready"));
        }
        // S-02 FIX: /metrics restricted to internal IPs only.
        // Without this, the built-in handler takes precedence over the route
        // config's internal_only flag, exposing metrics to external clients.
        if path == "/metrics" {
            if !is_internal_ip(&client_ip) {
                return Ok(empty_response(StatusCode::FORBIDDEN));
            }
            // Content-negotiate: serve OpenMetrics (histogram exemplars + EOF)
            // only when the scraper accepts it, otherwise classic Prometheus
            // 0.0.4. Emitting OpenMetrics exemplars under the classic
            // content-type makes /metrics unparseable by a standard Prometheus.
            let openmetrics = req
                .headers()
                .get(hyper::header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("application/openmetrics-text"))
                .unwrap_or(false);
            let content_type = if openmetrics {
                "application/openmetrics-text; version=1.0.0; charset=utf-8"
            } else {
                "text/plain; version=0.0.4; charset=utf-8"
            };
            let body = metrics::METRICS.render(openmetrics);
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", content_type)
                .body(Full::new(body).map_err(|never| match never {}).boxed())
                .unwrap());
        }
        // Live JSON snapshot — what `zion top` and dashboards consume.
        // Same internal-only gate as /metrics: never expose to the world.
        if path == "/_zion/snapshot.json" {
            if !is_internal_ip(&client_ip) {
                return Ok(empty_response(StatusCode::FORBIDDEN));
            }
            let platform = crate::bootstrap::detect();
            let mut rows: Vec<metrics::UpstreamRow<'_>> = cfg
                .health_map
                .iter()
                .map(|(url, h)| metrics::UpstreamRow {
                    url: url.as_str(),
                    healthy: h.healthy.load(std::sync::atomic::Ordering::Relaxed),
                    latency_us: h.latency_us.load(std::sync::atomic::Ordering::Relaxed),
                })
                .collect();
            // Stable order — keep the TUI from flickering as DashMap-style
            // iteration drifts. URL is unique so this is total-order.
            rows.sort_by(|a, b| a.url.cmp(b.url));
            let body = metrics::snapshot_json(platform, &rows);
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Cache-Control", "no-store")
                .body(Full::new(body).map_err(|never| match never {}).boxed())
                .unwrap());
        }
        // Cache purge — flush the in-RAM cache so a deploy can invalidate
        // immediately instead of waiting out the TTL. Internal-only + POST
        // (mutating). `?prefix=/path` purges matching keys; no prefix = all.
        if path == "/_zion/cache/purge" {
            if !is_internal_ip(&client_ip) {
                return Ok(empty_response(StatusCode::FORBIDDEN));
            }
            if *req.method() != hyper::Method::POST {
                return Ok(method_not_allowed("POST"));
            }
            let prefix = req.uri().query().and_then(|q| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("prefix="))
                    .map(|p| p.to_string())
            });
            let (removed, scope) = match &prefix {
                Some(p) => (state.static_cache.purge_prefix(p), format!("{p:?}")),
                None => (state.static_cache.purge_all(), "\"all\"".to_string()),
            };
            crate::logging::info("cache", &format!("purge scope={scope} removed={removed}"));
            let body = Bytes::from(format!("{{\"purged\":{removed},\"scope\":{scope}}}\n"));
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Cache-Control", "no-store")
                .body(Full::new(body).map_err(|never| match never {}).boxed())
                .unwrap());
        }
    }

    // ── Route lookup (thread-local LRU + radix tree fallback) ──
    // Hot routes hit the thread-local cache in ~5ns. Cache misses fall through
    // to the radix tree (~30ns) and are promoted to MRU. The cache is a true
    // O(1) LRU bounded at ROUTE_CACHE_CAP entries: when full, the LRU entry is
    // evicted on insert. The earlier "if len < 256 { insert }" stopped
    // promoting any new path once the cap was reached, so a client hitting
    // 256 distinct paths first (cache-busted CDN paths, scanners) permanently
    // locked out subsequent hot routes for the worker thread.
    thread_local! {
        static ROUTE_CACHE: std::cell::RefCell<route_cache::RouteCache<Arc<ResolvedRoute>>> =
            std::cell::RefCell::new(route_cache::RouteCache::new(route_cache::ROUTE_CACHE_CAP));
    }

    let rule = {
        let path = req.uri().path();

        // Host-based routing (ADR-0010): extract the normalized authority only
        // when a route is host-bound — hostless deployments skip this entirely.
        // The URI :authority (HTTP/2 / absolute-form) wins over the Host header
        // (HTTP/1 origin-form).
        let host_cow = if cfg.router.host_routing_active() {
            crate::security::request_host(&req)
        } else {
            None
        };
        let host = host_cow.as_deref();

        // Cache key folds the host in when present, so two authorities sharing a
        // path never collide (ADR-0010 cache invariant); with no host it is the
        // bare path hash — byte-identical to the pre-host-routing key.
        let cache_key = route_cache_key(host, path);

        // Thread-local cache hit (~5ns) — touch promotes to MRU
        let cached = ROUTE_CACHE.with(|cache| cache.borrow_mut().get(cache_key));

        if let Some(route) = cached {
            route
        } else {
            // Radix tree fallback (~30ns)
            match cfg.router.at(host, path) {
                Some(matched) => {
                    let route = matched.clone();
                    ROUTE_CACHE.with(|cache| {
                        cache.borrow_mut().insert(cache_key, route.clone());
                    });
                    route
                }
                None => return Ok(empty_response(StatusCode::NOT_FOUND)),
            }
        }
    };

    // ── CORS (Per-Route) ──
    // Clone origin HeaderValue (16 bytes, ref-counted) to release the
    // immutable borrow on req before any mutations below.
    let req_origin: Option<hyper::header::HeaderValue> = if rule.cors.is_some() {
        req.headers().get(hyper::header::ORIGIN).cloned()
    } else {
        None
    };

    // Pre-compute CORS allow origin for response injection later
    let cors_allow_origin: Option<hyper::header::HeaderValue> = req_origin
        .as_ref()
        .and_then(|v| v.to_str().ok())
        .and_then(|o| rule.cors.as_ref().and_then(|c| c.check_origin(o)));

    if let Some(ref cors) = rule.cors {
        if let Some(ref origin_val) = req_origin {
            let origin_str = origin_val.to_str().unwrap_or("");
            if let Some(allow_origin) = cors.check_origin(origin_str) {
                // Pre-flight OPTIONS — respond immediately without proxying
                if *req.method() == hyper::Method::OPTIONS {
                    let mut resp = empty_response(StatusCode::NO_CONTENT);
                    let h = resp.headers_mut();
                    h.insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
                    h.insert(
                        hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
                        cors.allow_methods.clone(),
                    );
                    h.insert(
                        hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
                        cors.allow_headers.clone(),
                    );
                    h.insert(hyper::header::ACCESS_CONTROL_MAX_AGE, cors.max_age.clone());
                    inject_security_headers(&mut resp);
                    return Ok(resp);
                }
            } else {
                // Origin not in allowed list — block state-changing methods AND preflight.
                if *req.method() == hyper::Method::OPTIONS
                    || matches!(
                        *req.method(),
                        hyper::Method::POST
                            | hyper::Method::PUT
                            | hyper::Method::PATCH
                            | hyper::Method::DELETE
                    )
                {
                    return Ok(empty_response(StatusCode::FORBIDDEN));
                }
            }
        }
    }

    // --- Gate: internal_only ---
    if rule.internal_only && !is_internal_ip(&client_ip) {
        return Ok(empty_response(StatusCode::FORBIDDEN));
    }

    // --- Gate: Upstream health check + Latency Routing (B-04) ---
    // Select the healthy upstream with the lowest latency. A `mode="static"`
    // route serves from disk and has NO upstream, so it must skip this gate —
    // otherwise `select_best_upstream` sees an empty list and 503s before the
    // `RouteMode::Static` arm can run. The placeholder is only parsed into
    // dyn_scheme/authority, which that arm never reads (WAF/auth/CSP/security
    // headers still apply on the way down).
    static EMPTY_UPSTREAM: String = String::new();
    let target_upstream_url =
        match health::select_best_upstream(&cfg.health_map, &rule.upstream_url) {
            Some(url) => url,
            None if rule.mode == config::RouteMode::Static => &EMPTY_UPSTREAM,
            None => {
                metrics::METRICS.record_status(503);
                return Ok(text_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "upstream unavailable",
                ));
            }
        };

    // SAFETY (inner unwrap): "/" is a compile-time-constant single-char URI
    // that always parses successfully. Used as a defensive fallback when the
    // configured upstream URL fails to parse — a config-validation error
    // that should have been caught at boot, but keeping this as a runtime
    // soft fallback prevents a panic if a hot-reload sneaks in a bad URL.
    let target_uri: hyper::Uri = target_upstream_url
        .parse()
        .unwrap_or_else(|_| "/".parse().unwrap());
    let dyn_scheme = target_uri
        .scheme()
        .cloned()
        .unwrap_or_else(|| rule.upstream_scheme.clone());
    let dyn_authority = target_uri
        .authority()
        .cloned()
        .unwrap_or_else(|| rule.upstream_authority.clone());

    // --- Gate: Auth (JWT/OIDC) ---
    #[cfg(feature = "auth")]
    if let Some(ref auth_profile) = rule.auth {
        let auth_header = req
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        match auth_header {
            Some(header_val) => {
                match auth::extract_bearer(header_val) {
                    Some(token) => {
                        match auth::validate_token(token, auth_profile) {
                            Ok(claims) => {
                                // Inject decoded claims as headers for upstream
                                if auth_profile.forward_claims {
                                    if let Some(ref sub) = claims.sub {
                                        if let Ok(v) = hyper::header::HeaderValue::from_str(sub) {
                                            req.headers_mut().insert("X-Auth-Subject", v);
                                        }
                                    }
                                    if let Some(ref email) = claims.email {
                                        if let Ok(v) = hyper::header::HeaderValue::from_str(email) {
                                            req.headers_mut().insert("X-Auth-Email", v);
                                        }
                                    }
                                }
                            }
                            Err(auth::AuthError::Expired) => {
                                return Ok(unauthorized(
                                    "token expired",
                                    "Bearer error=\"invalid_token\", error_description=\"token expired\"",
                                ));
                            }
                            Err(_) => {
                                return Ok(empty_response(StatusCode::FORBIDDEN));
                            }
                        }
                    }
                    None => {
                        return Ok(unauthorized(
                            "invalid authorization",
                            "Bearer error=\"invalid_token\"",
                        ));
                    }
                }
            }
            None => {
                return Ok(unauthorized("authorization required", "Bearer"));
            }
        }
    }

    // --- Gate: WAF ---
    if let Some(ref waf_profile) = rule.waf {
        // Map method to a static str to avoid allocation and lifetime issues
        let method: &'static str = match *req.method() {
            hyper::Method::GET => "GET",
            hyper::Method::POST => "POST",
            hyper::Method::PUT => "PUT",
            hyper::Method::PATCH => "PATCH",
            hyper::Method::DELETE => "DELETE",
            hyper::Method::HEAD => "HEAD",
            hyper::Method::OPTIONS => "OPTIONS",
            _ => "OTHER",
        };

        // Gate: WAF URI scan (catches SQLi/XSS in query parameters for ALL methods)
        let uri_str = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_else(|| req.uri().path());
        if let waf::WafVerdict::Deny(reason) = waf::validate_uri(uri_str, waf_profile.mode) {
            if rule.waf_shadow {
                metrics::METRICS
                    .waf_shadow_would_block
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                logging::warn(
                    "waf_shadow",
                    &format!("would_block=true source=uri reason={reason} path={uri_str}"),
                );
                // Fall through — shadow mode never denies the request.
            } else {
                metrics::METRICS
                    .waf_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics::METRICS.record_status(400);
                logging::info("waf", &format!("URI denied: {reason} ({uri_str})"));
                emit_waf_block(&state, &remote_addr, method, uri_str, "uri", &reason);
                return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
            }
        }

        // ── Gate: ML scorer (Track C, --features ml-waf) ─────────────
        // Anomaly score over URI + headers. Cheap (~50µs p50, 200µs p99
        // budget enforced via metrics, not active cancel). Returns None
        // when the model is disabled or failed to load — fall through.
        #[cfg(feature = "ml-waf")]
        if let Some(verdict) = crate::waf_ml::evaluate(method, uri_str, req.headers()) {
            if verdict.over_budget {
                logging::warn(
                    "waf_ml",
                    &format!(
                        "score over budget: elapsed_us={} score={:.3} path={}",
                        verdict.elapsed_us, verdict.score, uri_str
                    ),
                );
            }
            if verdict.denies {
                let reason = "ml score above threshold";
                if rule.waf_shadow {
                    metrics::METRICS
                        .waf_shadow_would_block
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    logging::warn(
                        "waf_shadow",
                        &format!(
                            "would_block=true source=ml score={:.3} path={uri_str}",
                            verdict.score
                        ),
                    );
                } else {
                    metrics::METRICS
                        .waf_denied
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    metrics::METRICS.record_status(400);
                    logging::info(
                        "waf_ml",
                        &format!(
                            "denied: score={:.3} elapsed_us={} path={}",
                            verdict.score, verdict.elapsed_us, uri_str
                        ),
                    );
                    emit_waf_block(&state, &remote_addr, method, uri_str, "ml", reason);
                    return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
                }
            }
        }

        if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
            let (parts, body) = req.into_parts();

            // Borrow content-type from parts.headers — no String allocation needed.
            // The header lives in `parts` which is alive through this scope.
            let ct: Option<&str> = parts
                .headers
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());

            let max_body_bytes = (waf_profile.max_body_mb * 1_048_576) as usize;

            // ── Body collection: streaming (#49) vs buffered ──────────────
            // When `[waf_profile.X] streaming = true`, the dispatcher feeds
            // each frame to a StreamingScanner as it arrives off the wire.
            // An injection pattern in the first chunk denies before the
            // rest of the upload is read. The frames are tee'd into a
            // BytesMut and reassembled on Allow so the regular
            // `validate_request` pipeline still runs the encoded-payload
            // pass + entropy + JSON gates that the streamer does not cover.
            //
            // On the buffered path (default) `Limited::new` enforces the
            // size cap; on the streaming path the StreamingScanner does
            // the same incrementally and emits its own size-exceeded deny.
            let body_bytes = if waf_profile.streaming {
                let mut scanner =
                    waf::StreamingScanner::new(waf_profile.mode, max_body_bytes as u64);
                let mut chunks: Vec<Bytes> = Vec::new();
                let mut total: usize = 0;
                let mut body = body;
                let mut early_deny: Option<&'static str> = None;
                loop {
                    match tokio::time::timeout(BODY_FRAME_IDLE_TIMEOUT, BodyExt::frame(&mut body))
                        .await
                    {
                        Ok(Some(Ok(frame))) => match frame.into_data() {
                            Ok(data) => {
                                match scanner.feed(&data) {
                                    waf::StreamVerdict::Allow => {}
                                    waf::StreamVerdict::Deny(reason) => {
                                        early_deny = Some(reason);
                                        break;
                                    }
                                }
                                total += data.len();
                                chunks.push(data);
                            }
                            // Trailers / non-data frames: ignore (no body bytes).
                            Err(_other) => continue,
                        },
                        Ok(Some(Err(_))) => {
                            return Ok(text_response(
                                StatusCode::BAD_REQUEST,
                                "request body read error",
                            ))
                        }
                        Ok(None) => break, // EOF
                        Err(_elapsed) => {
                            return Ok(text_response(
                                StatusCode::REQUEST_TIMEOUT,
                                "request body read timeout",
                            ))
                        }
                    }
                }

                if let Some(reason) = early_deny {
                    if rule.waf_shadow {
                        metrics::METRICS
                            .waf_shadow_would_block
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        logging::warn(
                            "waf_shadow",
                            &format!(
                                "would_block=true source=body_streaming method={} reason={} path={}",
                                method,
                                reason,
                                parts.uri.path()
                            ),
                        );
                        // Shadow mode: don't deny. We did NOT read the rest
                        // of the body off the wire; reconstruct from what
                        // we have and forward — this produces a truncated
                        // request to upstream, which is the correct shadow-
                        // mode trade-off (we never silently buffer attacks
                        // for the upstream after a streaming match).
                    } else {
                        metrics::METRICS
                            .waf_denied
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        metrics::METRICS.record_status(400);
                        emit_waf_block(
                            &state,
                            &remote_addr,
                            method,
                            parts.uri.path(),
                            "body",
                            reason,
                        );
                        return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
                    }
                }

                // Reassemble Bytes from the frame Vec for the buffered
                // re-validation + upstream forward.
                let mut buf = bytes::BytesMut::with_capacity(total);
                for c in &chunks {
                    buf.extend_from_slice(c);
                }
                buf.freeze()
            } else {
                let limited = Limited::new(body, max_body_bytes);
                match tokio::time::timeout(BODY_COLLECT_TIMEOUT, BodyExt::collect(limited)).await {
                    Ok(Ok(collected)) => collected.to_bytes(),
                    Ok(Err(_)) => {
                        return Ok(text_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "request body too large",
                        ))
                    }
                    Err(_elapsed) => {
                        return Ok(text_response(
                            StatusCode::REQUEST_TIMEOUT,
                            "request body read timeout",
                        ))
                    }
                }
            };

            let verdict = waf::validate_request(method, ct, &body_bytes, waf_profile);
            if let waf::WafVerdict::Deny(reason) = verdict {
                if rule.waf_shadow {
                    metrics::METRICS
                        .waf_shadow_would_block
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    logging::warn(
                        "waf_shadow",
                        &format!(
                            "would_block=true source=body method={} reason={} path={}",
                            method,
                            reason,
                            parts.uri.path()
                        ),
                    );
                    // Fall through — request body is reassembled below.
                } else {
                    metrics::METRICS
                        .waf_denied
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    metrics::METRICS.record_status(400);
                    emit_waf_block(
                        &state,
                        &remote_addr,
                        method,
                        parts.uri.path(),
                        "body",
                        &reason,
                    );
                    return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
                }
            }

            // Re-assemble request with validated body for dispatch below.
            // Do NOT return early — fall through to post-response processing
            // (CORS, metrics, request-ID, security headers).
            let body: ZionBody = Full::new(body_bytes)
                .map_err(|never| match never {})
                .boxed();
            req = Request::from_parts(parts, body);
        } else {
            // GET/HEAD/DELETE/OPTIONS — no body to validate
            let ct = req
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());
            let verdict = waf::validate_request(method, ct, &[], waf_profile);
            if let waf::WafVerdict::Deny(reason) = verdict {
                if rule.waf_shadow {
                    metrics::METRICS
                        .waf_shadow_would_block
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    logging::warn(
                        "waf_shadow",
                        &format!(
                            "would_block=true source=headers method={} reason={} path={}",
                            method,
                            reason,
                            req.uri().path()
                        ),
                    );
                    // Fall through — shadow mode never denies the request.
                } else {
                    metrics::METRICS
                        .waf_denied
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    metrics::METRICS.record_status(400);
                    emit_waf_block(
                        &state,
                        &remote_addr,
                        method,
                        req.uri().path(),
                        "headers",
                        &reason,
                    );
                    return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
                }
            }
        }
    }

    // --- Gate: WebSocket upgrade detection ---
    // Check for Upgrade: websocket on ANY route (or explicit websocket mode)
    let is_websocket = rule.mode == config::RouteMode::Websocket
        || req
            .headers()
            .get(hyper::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

    if is_websocket {
        metrics::METRICS
            .websocket_upgrades
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let on_upgrade = hyper::upgrade::on(&mut req);
        let mut resp = proxy::proxy_websocket(
            req,
            on_upgrade,
            &dyn_scheme,
            &dyn_authority,
            Some(forward_addr),
            "https",
            cfg.xff_mode,
        )
        .await?;
        inject_security_headers(&mut resp);
        return Ok(resp);
    }

    // ── Request ID (preserve client's or generate new) ──
    let has_client_id = req.headers().contains_key("X-Request-ID");
    let generated_id: [u8; 21];
    if !has_client_id {
        generated_id = generate_request_id();
        // SAFETY: all bytes are ASCII hex digits or '-'
        if let Ok(val) = hyper::header::HeaderValue::from_bytes(&generated_id) {
            req.headers_mut().insert("X-Request-ID", val);
        }
    }

    // ── W3C Trace Context propagation ──
    // 1. If the client sent `traceparent`, validate it. A valid header is
    //    propagated unchanged so end-to-end traces stitch in Tempo/Jaeger.
    //    A malformed header is dropped (we replace with a freshly-generated
    //    one) and `zion_traces_invalid_total` is bumped — we never forward
    //    junk to upstreams.
    // 2. If absent (or invalid), generate one with the same zero-alloc
    //    stack-buffer scheme used historically.
    //
    // The 16-byte trace ID is captured into `trace_id_bytes` regardless,
    // so the latency histogram can attach it as an OpenMetrics exemplar.
    let trace_id_bytes: [u8; 16];
    let inbound_valid = req
        .headers()
        .get("traceparent")
        .and_then(|v| observability::parse_traceparent(v.as_bytes()));

    if let Some(ctx) = inbound_valid {
        trace_id_bytes = ctx.trace_id;
    } else {
        // Either no header, or the value was malformed. Bump the invalid
        // counter only when a header was actually present.
        if req.headers().contains_key("traceparent") {
            observability::TRACES_INVALID_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Generate: 00-{32hex trace_id}-{16hex span_id}-01
        // Zero-alloc: stack buffer + hex lookup table (no format! calls).
        let ts_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let seq = REQUEST_COUNTER.load(std::sync::atomic::Ordering::Relaxed);

        // Build the trace ID once, in raw bytes — we both stringify it for
        // the header and keep it for the exemplar.
        let mut tid = [0u8; 16];
        tid[0..8].copy_from_slice(&ts_us.to_be_bytes());
        tid[8..16].copy_from_slice(&seq.to_be_bytes());
        trace_id_bytes = tid;

        let mut buf = [0u8; 55]; // "00-" + 32hex + "-" + 16hex + "-01"
        buf[0..3].copy_from_slice(b"00-");
        for (i, &byte) in tid.iter().enumerate() {
            buf[3 + i * 2] = crate::HEX_DIGITS[(byte >> 4) as usize];
            buf[3 + i * 2 + 1] = crate::HEX_DIGITS[(byte & 0xF) as usize];
        }
        buf[35] = b'-';
        // span_id: same 8 trailing bytes — sequence is unique within a process
        // for the lifetime of `REQUEST_COUNTER`. A future change can split
        // span IDs from request IDs; for now they coincide.
        for i in 0..8 {
            buf[36 + i * 2] = crate::HEX_DIGITS[(tid[8 + i] >> 4) as usize];
            buf[36 + i * 2 + 1] = crate::HEX_DIGITS[(tid[8 + i] & 0xF) as usize];
        }
        buf[52..55].copy_from_slice(b"-01");
        // SAFETY: all bytes are ASCII hex, '-', or '0'/'1'
        if let Ok(val) = hyper::header::HeaderValue::from_bytes(&buf) {
            req.headers_mut().insert("traceparent", val);
        }
    }
    observability::TRACES_EMITTED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // Pre-extract X-Request-ID for response echo (before req is consumed)
    let request_id_val = req.headers().get("X-Request-ID").cloned();

    // Capture method + path-and-query *before* the request is consumed by
    // the proxy / cache pipeline. Used by the access-log emission below.
    // `Method` and `String` are cheap to materialise once per request.
    let log_method = req.method().clone();
    let log_path_query: String = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Issue #60: snapshot configured headers (redacted) BEFORE the
    // request is consumed by the proxy / cache pipeline. Emitted
    // below as a single `headers` field carrying a JSON object —
    // tracing's macro requires field names to be string literals,
    // so dynamic header lists go through one structured value.
    //
    // mTLS fingerprint is captured separately so the access-log
    // event can put it on a dedicated `mtls_fp` field (the value is
    // a SHA-256 hash, never redacted).
    //
    // Empty/absent by default — the operator opts in via
    // `[access_log] include_headers = [...]`.
    let log_headers_json: Option<String> = if cfg.access_log.include_headers.is_empty() {
        None
    } else {
        let pairs: std::collections::BTreeMap<&str, String> = cfg
            .access_log
            .include_headers
            .iter()
            .filter_map(|name_lc| {
                let value = req
                    .headers()
                    .get(name_lc.as_str())
                    .and_then(|v| v.to_str().ok())?;
                let redacted = state.redact.redact_header_value(name_lc, value);
                Some((name_lc.as_str(), redacted.into_owned()))
            })
            .collect();
        if pairs.is_empty() {
            None
        } else {
            // serde_json on a BTreeMap of plain types can't fail.
            serde_json::to_string(&pairs).ok()
        }
    };
    let log_mtls_fp: Option<String> = if cfg.access_log.mtls_fingerprint {
        req.headers()
            .get("x-client-cert-fingerprint")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    // --- Dispatch by mode ---
    let mut resp = if rule.cache.is_some() {
        handle_static_cache(
            req,
            state.clone(),
            &rule,
            forward_addr,
            &dyn_scheme,
            &dyn_authority,
            cfg.xff_mode,
        )
        .await?
    } else {
        match &rule.mode {
            config::RouteMode::StaticCache => {
                handle_static_cache(
                    req,
                    state.clone(),
                    &rule,
                    remote_addr,
                    &dyn_scheme,
                    &dyn_authority,
                    cfg.xff_mode,
                )
                .await?
            }
            config::RouteMode::SseStream => {
                proxy::proxy_pass_stream(
                    &state.http_client,
                    req,
                    &dyn_scheme,
                    &dyn_authority,
                    Some(forward_addr),
                    "https",
                    cfg.xff_mode,
                )
                .await?
            }
            config::RouteMode::Standard => {
                proxy::proxy_pass_ha(
                    &state.http_client,
                    req,
                    &rule.upstream_url,
                    &dyn_scheme,
                    &dyn_authority,
                    &cfg.health_map,
                    Some(forward_addr),
                    "https",
                    cfg.xff_mode,
                )
                .await?
            }
            config::RouteMode::Websocket => {
                proxy::proxy_pass(
                    &state.http_client,
                    req,
                    &dyn_scheme,
                    &dyn_authority,
                    Some(forward_addr),
                    "https",
                    cfg.xff_mode,
                )
                .await?
            }
            config::RouteMode::Static => match rule.serve_dir.as_deref() {
                Some(dir) => {
                    let path = req.uri().path();
                    let tail = path
                        .strip_prefix(rule.static_prefix.as_str())
                        .unwrap_or(path)
                        .trim_start_matches('/');
                    crate::static_files::serve(dir, tail, rule.spa_fallback, req.method()).await
                }
                // Unreachable (resolve_route requires serve_dir) — fail CLOSED
                // rather than serve the process CWD if a future refactor slips.
                None => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
            },
        }
    };

    // Inject security headers on all responses
    inject_security_headers(&mut resp);

    // Per-route CSP: if the route has a csp value, inject it.
    // Otherwise, upstream CSP is passed through unmodified.
    if let Some(ref csp_val) = rule.csp {
        resp.headers_mut()
            .insert(hyper::header::CONTENT_SECURITY_POLICY, csp_val.clone());
    }

    // Record metrics (atomic increment, ~2ns)
    metrics::METRICS.record_status(resp.status().as_u16());

    let request_elapsed = request_start.elapsed();

    // Record request duration histogram, attaching the request's trace ID
    // as an OpenMetrics exemplar so /metrics consumers can jump straight
    // from a slow-bucket count to the matching trace in Tempo/Jaeger.
    metrics::METRICS
        .request_duration
        .observe_with_trace(request_elapsed, trace_id_bytes);

    // GDPR-aware access log (Track E). One structured event per request:
    //   * status, method, latency_us — per-request metric data, no PII;
    //   * path with the query string redacted via state.redact (the same
    //     compiled policy used by audit::emit_waf_block);
    //   * remote_ip — necessary for forensics, classified under GDPR
    //     Art. 6(1)(f) "legitimate interest" of operating the service.
    //
    // The event is a no-op when no tracing subscriber consumes it. With
    // the JSON subscriber attached, fields are written directly to the
    // subscriber's buffer — no `format!` allocation, redaction is the
    // only owned-`String` produced.
    {
        // Redact the query string per the operator's [redact] policy.
        // Path itself is rarely sensitive and the auditor needs it; we
        // only rewrite the part after the first `?`.
        let path_safe: std::borrow::Cow<'_, str> = match log_path_query.split_once('?') {
            Some((p, q)) => {
                let q_redacted = state.redact.redact_query_string(q);
                std::borrow::Cow::Owned(format!("{p}?{q_redacted}"))
            }
            None => std::borrow::Cow::Borrowed(log_path_query.as_str()),
        };
        tracing::info!(
            target: "access",
            status = resp.status().as_u16(),
            latency_us = request_elapsed.as_micros() as u64,
            method = %log_method,
            path = %path_safe,
            remote_ip = %remote_addr.ip(),
            // Issue #60: configured request headers, redacted via the
            // [redact.headers] policy, packed into one JSON object so
            // dynamic field names don't fight the tracing macro.
            // `tracing::field::Empty` collapses absent fields to no-op.
            headers = log_headers_json.as_deref().unwrap_or(""),
            // mTLS fingerprint (SHA-256 hex; never redacted — already a hash).
            mtls_fp = log_mtls_fp.as_deref().unwrap_or(""),
            "request",
        );

        // Issue #60: when the audit log is enabled, emit a parallel
        // `request_completed` event so compliance reviewers have a
        // signed, HMAC-chained record alongside the unsigned tracing
        // line. Same field set; the audit handle's `try_send` is
        // non-blocking, so a saturated audit queue silently drops
        // (counted via `zion_audit_events_dropped_total`).
        if !cfg.access_log.include_headers.is_empty() || cfg.access_log.mtls_fingerprint {
            // Compose the detail string out-of-band — keeps the audit
            // event small and lets the operator filter by kind.
            let mut detail_parts: Vec<String> = Vec::with_capacity(3);
            detail_parts.push(format!(
                "status={} latency_us={}",
                resp.status().as_u16(),
                request_elapsed.as_micros()
            ));
            if let Some(ref h) = log_headers_json {
                detail_parts.push(format!("headers={h}"));
            }
            if let Some(ref fp) = log_mtls_fp {
                detail_parts.push(format!("mtls_fp={fp}"));
            }
            let _ = state.audit.emit(audit::AuditEvent {
                seq: 0,
                ts: String::new(),
                kind: audit::kind::REQUEST_COMPLETED,
                trace_id: None,
                remote_ip: Some(remote_addr.ip().to_string()),
                method: Some(log_method.to_string()),
                path: Some(path_safe.to_string()),
                detail: Some(detail_parts.join(" ")),
            });
        }
    }

    // CORS: add Access-Control-Allow-Origin on actual requests
    if let Some(allow) = cors_allow_origin {
        resp.headers_mut()
            .insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
    }

    // X-Request-ID on response (echo from request for client correlation)
    if let Some(rid) = request_id_val {
        resp.headers_mut().insert("X-Request-ID", rid);
    }

    // Alt-Svc: advertise HTTP/3 to clients (zero cost if feature disabled)
    #[cfg(feature = "http3")]
    resp.headers_mut()
        .insert("Alt-Svc", crate::quic::ALT_SVC_H3.clone());

    Ok(resp)
}

/// Serve from RAM cache or fetch from upstream, then cache.
/// Preserves Content-Type and status from upstream to prevent MIME-sniff
/// issues (S-05: browsers blocked cached CSS/JS without Content-Type
/// because nosniff was set).
#[inline]
/// Cache-Control to emit for a cached asset when the upstream did not set one:
/// the profile TTL as a public max-age, or `immutable` ONLY when the operator
/// explicitly set a ttl >= 1 year (content-hashed assets opt in). The default
/// is now a conservative 1h, so a header-less response is never frozen.
fn profile_cache_control(ttl_seconds: u64) -> hyper::header::HeaderValue {
    if ttl_seconds >= 31_536_000 {
        hyper::header::HeaderValue::from_static(CACHE_CONTROL_IMMUTABLE)
    } else {
        hyper::header::HeaderValue::try_from(format!("public, max-age={ttl_seconds}"))
            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("public"))
    }
}

/// Origin freshness lifetime (seconds) from the response `Cache-Control`.
/// Prefers `s-maxage` (the shared-cache directive) over `max-age`. Returns
/// `None` when the origin states no explicit lifetime — the caller then falls
/// back to the profile TTL. This is what lets a short-lived origin policy
/// (e.g. `max-age=300` on HTML) actually shorten zion's cache lifetime instead
/// of being ignored in favour of the profile's blanket TTL.
fn origin_freshness(headers: &hyper::HeaderMap) -> Option<u64> {
    let cc = headers
        .get(hyper::header::CACHE_CONTROL)?
        .to_str()
        .ok()?
        .to_ascii_lowercase();
    // s-maxage wins for shared caches; only then fall back to max-age.
    for directive in ["s-maxage", "max-age"] {
        for part in cc.split(',') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix(directive) {
                if let Some(val) = rest.trim_start().strip_prefix('=') {
                    if let Ok(secs) = val.trim().trim_matches('"').parse::<u64>() {
                        return Some(secs);
                    }
                }
            }
        }
    }
    None
}

/// RFC 9111 storability decision for zion's **shared** cache: `true` if a 200
/// response may be stored under the path key, `false` if it must be streamed
/// straight through (bypass). Pure + unit-tested — the policy gate that keeps
/// the cache RFC-correct. Bypass when ANY holds:
/// - effective freshness lifetime is 0, or the object already arrived stale
///   (`Age >= lifetime`) — §4.2;
/// - the response is marked `private` / `no-store` / `no-cache` (§3.2, §5.2.2);
/// - the request carried `Authorization` and the response does NOT explicitly
///   opt in via `public` / `s-maxage` / `must-revalidate` (**§3.5** — without
///   this a shared cache leaks one user's authenticated body to another);
/// - `Vary` nominates a content-negotiation / personalization header a
///   path-only key can't separate (§4.1); `Accept-Encoding` is treated as safe
///   (the entry stores raw bytes + its `Content-Encoding`).
fn is_shared_cacheable(
    req_authenticated: bool,
    resp_headers: &hyper::HeaderMap,
    effective_ttl: u64,
    initial_age: u64,
) -> bool {
    if effective_ttl == 0 || initial_age >= effective_ttl {
        return false;
    }

    let cc = resp_headers
        .get(hyper::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase());

    // §3.2 / §5.2.2: origin forbids shared storage.
    if let Some(cc) = &cc {
        if cc.contains("private") || cc.contains("no-store") || cc.contains("no-cache") {
            return false;
        }
    }

    // §3.5: a response to an authenticated request is storable in a shared
    // cache ONLY when the origin explicitly allows it.
    if req_authenticated {
        let opted_in = cc
            .as_deref()
            .map(|cc| {
                cc.contains("public") || cc.contains("s-maxage") || cc.contains("must-revalidate")
            })
            .unwrap_or(false);
        if !opted_in {
            return false;
        }
    }

    // §4.1: a stored response that varies must be matched on the varied headers.
    // We fold `Accept-Encoding` into the cache key (see `accept_encoding_key`),
    // so a response varying SOLELY on Accept-Encoding is safe to store. Any other
    // varied header (Accept, Cookie, Accept-Language, User-Agent, `*`, …) we can't
    // key on — don't store it, or we'd serve one variant to every requester.
    let vary_safe = resp_headers
        .get(hyper::header::VARY)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .all(|t| t.eq_ignore_ascii_case("accept-encoding"))
        })
        .unwrap_or(true); // no Vary → safe
    vary_safe
}

/// Canonical `Accept-Encoding` fragment for the cache key (RFC 9111 §4.1, the
/// Accept-Encoding case). Requests that accept the same set of codings share a
/// cache entry; a different set gets its own — so a client that only accepts
/// `identity` is never served a `gzip` body. Tokens are lowercased, `q=0`
/// (explicitly refused) dropped, deduplicated, and sorted so header order
/// doesn't fragment the cache. An absent header yields an empty fragment.
fn accept_encoding_key(headers: &hyper::HeaderMap) -> String {
    let raw = headers
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut codings: Vec<&str> = raw
        .split(',')
        .filter_map(|tok| {
            let mut it = tok.split(';');
            let name = it.next().unwrap_or("").trim();
            if name.is_empty() {
                return None;
            }
            // Drop a coding the client explicitly refuses (q=0 / q=0.0).
            let refused = it.any(|p| {
                p.trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .map(|q| q <= 0.0)
                    .unwrap_or(false)
            });
            if refused {
                None
            } else {
                Some(name)
            }
        })
        .collect();
    codings.sort_unstable();
    codings.dedup();
    codings.join(",")
}

/// Age (seconds) the response already carried on arrival, from the upstream
/// `Age` header (the shield Varnish stamps it). Seeds the entry's age so the
/// `Age` zion emits reflects the object's true age across all cache tiers,
/// rather than restarting from zero at the zion layer.
fn upstream_age(headers: &hyper::HeaderMap) -> u64 {
    headers
        .get(hyper::header::AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Build the response for a RAM cache hit: preserved status/Content-Type/
/// Content-Encoding, a `Cache-Control` whose `max-age` matches the entry's
/// freshness lifetime, and the `Age` header so downstream caches subtract
/// elapsed time instead of resetting their freshness clock on every hit.
/// Serve a stored body with the given `X-Zion-Cache` disposition. `HIT` = a
/// fresh hit; `REVALIDATED` = a stale entry the origin confirmed with a 304
/// (RFC 9111 §4.3), served without re-downloading; `STALE` = stale served on an
/// origin error (§4.2.4 stale-if-error).
fn cache_response(hit: cache::CacheHit, disposition: &'static str) -> Response<ZionBody> {
    let mut builder = Response::builder()
        .status(hit.meta.status)
        .header("Cache-Control", profile_cache_control(hit.max_age_secs))
        .header("X-Zion-Cache", disposition)
        .header(hyper::header::AGE, hit.age_secs);
    if let Some(ct) = &hit.meta.content_type {
        builder = builder.header(hyper::header::CONTENT_TYPE, ct.clone());
    }
    if let Some(ce) = &hit.meta.content_encoding {
        builder = builder.header(hyper::header::CONTENT_ENCODING, ce.clone());
    }
    builder
        .body(Full::new(hit.body).map_err(|never| match never {}).boxed())
        .unwrap()
}

#[inline]
fn cache_hit_response(hit: cache::CacheHit) -> Response<ZionBody> {
    cache_response(hit, "HIT")
}

/// Seed a conditional GET for origin revalidation (RFC 9111 §4.3.1) from a
/// stale entry's stored validators. `insert` overwrites any client-supplied
/// conditional header so we revalidate against *our* copy; the origin prefers
/// `If-None-Match` when both are present (RFC 9110 §13.1.3).
fn add_conditional_headers(headers: &mut hyper::HeaderMap, meta: &cache::CachedMeta) {
    if let Some(etag) = &meta.etag {
        headers.insert(hyper::header::IF_NONE_MATCH, etag.clone());
    }
    if let Some(lm) = &meta.last_modified {
        headers.insert(hyper::header::IF_MODIFIED_SINCE, lm.clone());
    }
}

/// Parse the REQUEST's `Cache-Control` for the directives a shared cache honors
/// (RFC 9111 §5.2.1): returns `(no_store, no_cache, only_if_cached)`. `no-cache`
/// and `max-age=0` both mean "don't serve a stored response without
/// revalidation", so they're folded together.
fn parse_request_cache_control(headers: &hyper::HeaderMap) -> (bool, bool, bool) {
    let cc = headers
        .get(hyper::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let has = |d: &str| cc.split(',').any(|t| t.trim() == d);
    let max_age_zero = cc.split(',').any(|t| {
        t.trim()
            .strip_prefix("max-age=")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|v| v == 0)
            .unwrap_or(false)
    });
    (
        has("no-store"),
        has("no-cache") || max_age_zero,
        has("only-if-cached"),
    )
}

/// 504 for `Cache-Control: only-if-cached` on a cache miss — the cache must NOT
/// contact the origin, so an absent entry is a gateway timeout (§5.2.1.7).
fn cache_only_if_cached_miss() -> Response<ZionBody> {
    Response::builder()
        .status(StatusCode::GATEWAY_TIMEOUT)
        .header("X-Zion-Cache", "MISS")
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Strip a weak-ETag `W/` prefix for the weak comparison `If-None-Match` uses
/// (RFC 9110 §8.8.3.2).
fn strip_weak(etag: &str) -> &str {
    etag.strip_prefix("W/").unwrap_or(etag)
}

/// Does a client conditional request match this cached entry — i.e. can we
/// answer 304 Not Modified? RFC 9110 §13.1: `If-None-Match` takes precedence
/// (weak comparison; `*` matches any stored entry); otherwise `If-Modified-Since`
/// is honored as an exact echo of the stored `Last-Modified` (the dominant
/// browser revalidation pattern — full HTTP-date comparison is a follow-up).
fn client_conditional_hit(req_headers: &hyper::HeaderMap, meta: &cache::CachedMeta) -> bool {
    if let Some(inm) = req_headers
        .get(hyper::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let inm = inm.trim();
        if inm == "*" {
            return true;
        }
        let stored = match meta.etag.as_ref().and_then(|e| e.to_str().ok()) {
            Some(e) => strip_weak(e.trim()),
            None => return false,
        };
        return inm.split(',').any(|t| strip_weak(t.trim()) == stored);
    }
    if let (Some(ims), Some(lm)) = (
        req_headers
            .get(hyper::header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok()),
        meta.last_modified.as_ref().and_then(|v| v.to_str().ok()),
    ) {
        return ims.trim() == lm.trim();
    }
    false
}

/// 304 Not Modified from a cache hit — preserved validators + freshness, no body
/// (RFC 9110 §15.4.5).
fn not_modified_response(hit: &cache::CacheHit) -> Response<ZionBody> {
    let mut builder = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header("Cache-Control", profile_cache_control(hit.max_age_secs))
        .header("X-Zion-Cache", "HIT")
        .header(hyper::header::AGE, hit.age_secs);
    if let Some(etag) = &hit.meta.etag {
        builder = builder.header(hyper::header::ETAG, etag.clone());
    }
    if let Some(lm) = &hit.meta.last_modified {
        builder = builder.header(hyper::header::LAST_MODIFIED, lm.clone());
    }
    builder
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

async fn handle_static_cache(
    mut req: Request<ZionBody>,
    state: Arc<AppState>,
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    dyn_scheme: &hyper::http::uri::Scheme,
    dyn_authority: &hyper::http::uri::Authority,
    xff_mode: proxy::XffMode,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Only GET is cacheable. HEAD/POST/PUT/PATCH/DELETE/OPTIONS must bypass the
    // cache and never populate it: the cache key is the path (no method), so a
    // non-GET 200 stored under it — a HEAD's empty body, or a POST response —
    // would later be served to a GET (method-confusion cache poisoning).
    if *req.method() != hyper::Method::GET {
        return proxy::proxy_pass(
            &state.http_client,
            req,
            dyn_scheme,
            dyn_authority,
            Some(remote_addr),
            "https",
            xff_mode,
        )
        .await;
    }

    // Cache TTL / capacity from the profile (mode=StaticCache without an
    // explicit profile uses the conservative 1h default; see config::default_ttl).
    let (cache_ttl, cache_max) = match &rule.cache {
        Some(cp) => (cp.ttl_seconds, cp.max_entries),
        // Conservative fallback (1h) for a static_cache route with no resolved
        // profile — never the old 1-year freeze. See config::default_ttl.
        None => (3600, 10_000),
    };

    // RFC 9111 §3.5: capture whether the request is authenticated BEFORE `req`
    // is consumed by the upstream fetch — the storability gate below needs it
    // to avoid caching one user's authenticated response in the shared cache.
    let req_authenticated = req.headers().contains_key(hyper::header::AUTHORIZATION);

    // RFC 9111 §5.2.1: request Cache-Control. `no-store` bypasses the cache
    // (read + write); `no-cache` / `max-age=0` force a fresh response (don't
    // serve a stored one — without conditional revalidation that's a re-fetch);
    // `only-if-cached` answers from cache or 504, never contacting the origin.
    let (rcc_no_store, rcc_no_cache, rcc_only_if_cached) =
        parse_request_cache_control(req.headers());

    // Cache key = full path+query (so /api?user=alice and /api?user=bob never
    // share an entry — cache-poisoning guard) PLUS the canonical Accept-Encoding
    // set, so encoding variants don't cross-contaminate (RFC 9111 §4.1). The
    // 0x1F unit separator can't occur in a valid request target, so the suffix
    // can never collide with a real path.
    let pq = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| req.uri().path());
    let cache_key = format!("{pq}\u{1f}{}", accept_encoding_key(req.headers()));

    // only-if-cached (§5.2.1.7): serve from cache or 504 — never fetch.
    if rcc_only_if_cached {
        return Ok(match state.static_cache.get(&cache_key) {
            // only-if-cached (§5.2.1.7) must not contact the origin, so a stale
            // stored response can't be revalidated → 504, same as a miss.
            cache::CacheLookup::Fresh(hit) => cache_hit_response(hit),
            _ => cache_only_if_cached_miss(),
        });
    }

    // RAM lookup. `Fresh` → zero-copy serve. `Stale` → keep the body and
    // revalidate with the origin below (RFC 9111 §4.3) instead of refetching.
    // `Miss` → fall through to a full fetch. Skipped when the client demanded a
    // fresh response (`no-cache` / `no-store`).
    let mut revalidate: Option<cache::CacheHit> = None;
    if !rcc_no_cache && !rcc_no_store {
        match state.static_cache.get(&cache_key) {
            cache::CacheLookup::Fresh(hit) => {
                // Client conditional request (RFC 9110 §13): a matching
                // If-None-Match / If-Modified-Since → 304 Not Modified, skipping
                // the body entirely.
                if client_conditional_hit(req.headers(), &hit.meta) {
                    return Ok(not_modified_response(&hit));
                }
                return Ok(cache_hit_response(hit));
            }
            cache::CacheLookup::Stale(hit) => {
                // Only revalidate when we hold a validator; without one a
                // conditional GET is pointless, so fall through to a full fetch.
                if hit.meta.etag.is_some() || hit.meta.last_modified.is_some() {
                    add_conditional_headers(req.headers_mut(), &hit.meta);
                    revalidate = Some(hit);
                }
            }
            cache::CacheLookup::Miss => {}
        }
    }

    // Own cache key before consuming req — use Arc directly (cache stores Arc<str>)
    let path_owned: Arc<str> = Arc::from(cache_key);

    // Singleflight: coalesce concurrent cache misses for the same key.
    // If another request is already fetching, subscribe to its watch channel
    // and wait for completion. We use watch (not Notify) because
    // `Receiver::wait_for` inspects the current value at first poll: if the
    // fetcher already sent `true` between our get() and our .await, we still
    // observe it and return immediately instead of hanging.
    let waiter = state
        .inflight
        .get(&path_owned)
        .map(|entry| entry.value().subscribe());

    if let Some(mut rx) = waiter {
        // Err = sender dropped without sending true (fetch aborted/errored).
        // In both Ok and Err cases we re-check the cache; on miss we fall
        // through to fetch ourselves.
        let _ = rx.wait_for(|v| *v).await;
        if let Some(hit) = state.static_cache.get(path_owned.as_ref()).fresh() {
            // get() already counted this hit — don't double-count it here.
            return Ok(cache_hit_response(hit));
        }
        // Cache miss (or stale) even after wait — fall through to fetch from
        // upstream, which re-populates (a stale re-check here is rare: the
        // fetcher we waited on just stored a fresh entry).
    }

    // Register as the inflight fetcher for this key.
    // Initial value `false` = "fetch in progress"; we publish `true` once the
    // cache is populated. Drop without sending `true` signals abort to waiters.
    let (tx, _) = tokio::sync::watch::channel(false);
    state.inflight.insert(path_owned.clone(), tx.clone());

    // RAM miss — fetch from upstream.
    // On error, drop the inflight sender. Waiters' wait_for() returns Err
    // (channel closed without receiving `true`), they re-check the cache,
    // miss, and fall through to fetch themselves.
    let resp = match proxy::proxy_pass(
        &state.http_client,
        req,
        dyn_scheme,
        dyn_authority,
        Some(remote_addr),
        "https",
        xff_mode,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            state.inflight.remove(&path_owned);
            // stale-if-error (RFC 9111 §4.2.4): if we were revalidating a stale
            // entry and the origin is unreachable, serve the stale body rather
            // than fail — a flapping origin doesn't take cached content down.
            if let Some(hit) = revalidate {
                return Ok(cache_response(hit, "STALE"));
            }
            // tx drops at end of scope → channel closed → waiters get Err
            return Err(e);
        }
    };

    // Revalidation outcome (RFC 9111 §4.3): a 304 confirms the stored entry is
    // still good — revive its freshness and serve the stored body without the
    // re-download. A 200 (or anything else) falls through to the normal
    // store-and-serve path, replacing the stale entry with the new content.
    if let Some(hit) = revalidate {
        if resp.status() == StatusCode::NOT_MODIFIED {
            let initial_age = upstream_age(resp.headers());
            let effective_ttl = origin_freshness(resp.headers())
                .map(|o| o.min(cache_ttl))
                .unwrap_or(cache_ttl);
            state.static_cache.refresh(
                &path_owned,
                hit.body.clone(),
                hit.meta.clone(),
                effective_ttl,
                initial_age,
                cache_max,
            );
            state.inflight.remove(&path_owned);
            let _ = tx.send(true); // waiters observe the revived (fresh) entry
            crate::metrics::METRICS
                .cache_revalidations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(cache_response(hit, "REVALIDATED"));
        }
        // else: origin returned new content (200) or a non-304 status — drop the
        // stale hit and let the normal path below store/serve the fresh response.
    }

    // Only cache 200 OK responses
    if resp.status() == StatusCode::OK {
        let (parts, body) = resp.into_parts();

        // Honor the origin's freshness instead of blanket-applying the profile
        // TTL: a short origin `max-age`/`s-maxage` shortens the lifetime, the
        // profile TTL is the ceiling. Seed the entry's age from the upstream
        // `Age` (shield Varnish) so freshness is computed across all tiers.
        let initial_age = upstream_age(&parts.headers);
        let effective_ttl = origin_freshness(&parts.headers)
            .map(|o| o.min(cache_ttl))
            .unwrap_or(cache_ttl);

        // RFC 9111 storability gate (Vary §4.1 / private-no-store §3.2 / §3.5
        // authenticated-request / freshness §4.2). A request `Cache-Control:
        // no-store` (§5.2.1.5) also forbids storing the response. On a bypass,
        // stream the body straight through without populating the shared cache.
        if rcc_no_store
            || !is_shared_cacheable(
                req_authenticated,
                &parts.headers,
                effective_ttl,
                initial_age,
            )
        {
            // Stream the body straight to the client without caching.
            // Drop the inflight sender (no `true` sent): waiters fall through
            // to a fresh fetch, since cache will not be populated for this key.
            state.inflight.remove(&path_owned);
            let mut resp = Response::from_parts(parts, body.map_err(hyper::Error::from).boxed());
            resp.headers_mut().insert(
                "X-Zion-Cache",
                hyper::header::HeaderValue::from_static("BYPASS"),
            );
            return Ok(resp);
        }

        // Preserve Content-Type and Content-Encoding for cache (S-05 fix).
        // Without Content-Encoding, gzip-compressed bodies are served garbled.
        let content_type = parts.headers.get(hyper::header::CONTENT_TYPE).cloned();
        let content_encoding = parts.headers.get(hyper::header::CONTENT_ENCODING).cloned();
        // Preserve validators for conditional requests (client If-None-Match →
        // 304; origin revalidation in a later phase).
        let etag = parts.headers.get(hyper::header::ETAG).cloned();
        let last_modified = parts.headers.get(hyper::header::LAST_MODIFIED).cloned();
        let meta = cache::CachedMeta {
            content_type,
            content_encoding,
            status: parts.status,
            etag,
            last_modified,
        };

        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(16);
        let stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
        let stream_body = http_body_util::StreamBody::new(stream);

        let state_clone = state.clone();
        let path_clone = path_owned.clone();
        let meta_clone = meta.clone();
        let tx_clone = tx.clone();

        // Cache Tee-Reader Pipeline
        tokio::spawn(async move {
            let mut cache_buffer = bytes::BytesMut::new();
            let mut total_bytes = 0;
            let mut cache_aborted = false;
            let mut stream_body = body; // Consume inner body entirely

            loop {
                match BodyExt::frame(&mut stream_body).await {
                    Some(Ok(frame)) => {
                        let f = match frame.into_data() {
                            Ok(data) => {
                                if !cache_aborted {
                                    total_bytes += data.len();
                                    if total_bytes > MAX_CACHEABLE_BODY {
                                        cache_aborted = true; // Stop buffering, but continue streaming!
                                    } else {
                                        cache_buffer.extend_from_slice(&data);
                                    }
                                }
                                hyper::body::Frame::data(data)
                            }
                            Err(other_frame) => other_frame,
                        };

                        // Stream chunk directly to the client immediately
                        if sender.send(Ok(f)).await.is_err() {
                            // Client disconnected mid-stream. Drop inflight without
                            // signaling completion: cache buffer is partial/aborted.
                            // Waiters' wait_for returns Err and they re-fetch.
                            state_clone.inflight.remove(&path_clone);
                            return;
                        }
                    }
                    Some(Err(e)) => {
                        // Upstream chunking failed — drop inflight (abort signal).
                        let _ = sender.send(Err(e)).await;
                        state_clone.inflight.remove(&path_clone);
                        return;
                    }
                    None => {
                        break;
                    }
                }
            }

            if !cache_aborted {
                state_clone.static_cache.insert(
                    &path_clone,
                    cache_buffer.into(),
                    meta_clone,
                    effective_ttl,
                    initial_age,
                    cache_max,
                );
                // Cache populated: signal `true` so waiters' wait_for resolves
                // immediately at the next poll, even if they hadn't subscribed
                // before this point. Send before remove so the value is the
                // last-observed state when the sender drops.
                let _ = tx_clone.send(true);
            }
            // (else cache_aborted — body exceeded MAX_CACHEABLE_BODY: don't
            //  signal completion; waiters re-fetch through normal miss path.)
            state_clone.inflight.remove(&path_clone);
        });

        let mut resp = Response::from_parts(parts, stream_body.boxed());
        // This response was fetched from upstream and is being populated into
        // the cache as it streams — a MISS that fills the cache for next time.
        resp.headers_mut().insert(
            "X-Zion-Cache",
            hyper::header::HeaderValue::from_static("MISS"),
        );
        // Preserve the upstream Cache-Control if it set one; otherwise supply
        // the profile-derived default — don't blanket-stamp 1-year immutable.
        if !resp.headers().contains_key(hyper::header::CACHE_CONTROL) {
            resp.headers_mut()
                .insert("Cache-Control", profile_cache_control(effective_ttl));
        }
        return Ok(resp);
    }

    // Non-200 or non-cacheable: drop inflight without signaling completion.
    // Waiters re-check the cache (miss) and fall through to fetch themselves.
    state.inflight.remove(&path_owned);

    Ok(resp)
}

/// Check if an IP is internal — delegates to security module.
#[inline]
fn is_internal_ip(ip: &std::net::IpAddr) -> bool {
    security::is_internal_ip(ip)
}

// ==========================================================================
// Thread-local route LRU
// --------------------------------------------------------------------------
// O(1) get/insert/evict via an intrusive doubly-linked list backed by a Vec.
// Same primitive as cache::L1Cache but stripped to what the route cache needs:
// no TTL (routes are immutable for the lifetime of the daemon — they come
// from the static config) and no generation counter. The cache key is the
// FNV hash of the request path (already computed at the call site).
// ==========================================================================
mod route_cache {
    pub(super) const ROUTE_CACHE_CAP: usize = 256;
    const NIL: usize = usize::MAX;

    struct Node {
        key: u64,
        prev: usize,
        next: usize,
    }

    /// Generic on V so tests can drive the LRU with a trivial value type
    /// (e.g. u32) without needing to construct a fully populated
    /// ResolvedRoute. Monomorphises to the same code at the call site.
    pub(super) struct RouteCache<V: Clone> {
        map: fnv::FnvHashMap<u64, (V, usize)>,
        nodes: Vec<Node>,
        free: Vec<usize>,
        head: usize, // LRU — evicted first
        tail: usize, // MRU
        cap: usize,
    }

    impl<V: Clone> RouteCache<V> {
        pub(super) fn new(cap: usize) -> Self {
            Self {
                map: fnv::FnvHashMap::with_capacity_and_hasher(cap, Default::default()),
                nodes: Vec::with_capacity(cap),
                free: Vec::new(),
                head: NIL,
                tail: NIL,
                cap,
            }
        }

        #[inline]
        fn unlink(&mut self, idx: usize) {
            let prev = self.nodes[idx].prev;
            let next = self.nodes[idx].next;
            if prev != NIL {
                self.nodes[prev].next = next;
            } else {
                self.head = next;
            }
            if next != NIL {
                self.nodes[next].prev = prev;
            } else {
                self.tail = prev;
            }
            self.nodes[idx].prev = NIL;
            self.nodes[idx].next = NIL;
        }

        #[inline]
        fn push_tail(&mut self, idx: usize) {
            self.nodes[idx].prev = self.tail;
            self.nodes[idx].next = NIL;
            if self.tail != NIL {
                self.nodes[self.tail].next = idx;
            } else {
                self.head = idx;
            }
            self.tail = idx;
        }

        #[inline]
        fn alloc_node(&mut self, key: u64) -> usize {
            if let Some(idx) = self.free.pop() {
                self.nodes[idx] = Node {
                    key,
                    prev: NIL,
                    next: NIL,
                };
                idx
            } else {
                let idx = self.nodes.len();
                self.nodes.push(Node {
                    key,
                    prev: NIL,
                    next: NIL,
                });
                idx
            }
        }

        /// Lookup with MRU promotion. Returns a clone of the value (for
        /// `Arc<T>` this is just an atomic refcount bump).
        pub(super) fn get(&mut self, key: u64) -> Option<V> {
            let (value, idx) = self.map.get(&key)?;
            let value = value.clone();
            let idx = *idx;
            self.unlink(idx);
            self.push_tail(idx);
            Some(value)
        }

        /// Insert or update. On capacity full, evicts the LRU entry. Always
        /// places the inserted/updated key at MRU.
        pub(super) fn insert(&mut self, key: u64, value: V) {
            if let Some((existing, idx)) = self.map.get_mut(&key) {
                *existing = value;
                let idx = *idx;
                self.unlink(idx);
                self.push_tail(idx);
                return;
            }
            // Evict LRU if at capacity (must run BEFORE allocating, otherwise
            // a single-shot of cap+1 distinct keys would never reclaim space).
            while self.map.len() >= self.cap && self.head != NIL {
                let lru_idx = self.head;
                let lru_key = self.nodes[lru_idx].key;
                self.unlink(lru_idx);
                self.free.push(lru_idx);
                self.map.remove(&lru_key);
            }
            let idx = self.alloc_node(key);
            self.push_tail(idx);
            self.map.insert(key, (value, idx));
        }

        #[cfg(test)]
        pub(super) fn len(&self) -> usize {
            self.map.len()
        }

        /// Returns keys in LRU→MRU order. Test-only helper that walks the
        /// intrusive list, so it also implicitly verifies link integrity.
        #[cfg(test)]
        pub(super) fn order(&self) -> Vec<u64> {
            let mut out = Vec::with_capacity(self.map.len());
            let mut cur = self.head;
            while cur != NIL {
                out.push(self.nodes[cur].key);
                cur = self.nodes[cur].next;
            }
            out
        }
    }
}

// ==========================================================================
// TESTS
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_cache_key_is_host_scoped() {
        // The load-bearing ADR-0010 cache invariant: two authorities that share
        // a path MUST get distinct keys, or a thread-local cache hit would
        // cross-wire their routes (bypassing a per-host WAF/auth/internal gate).
        let a = route_cache_key(Some("api.example.com"), "/x");
        let b = route_cache_key(Some("app.example.com"), "/x");
        assert_ne!(a, b, "same path, different host must not collide");

        // A hostless key equals the bare path hash — byte-identical to the
        // pre-host-routing behavior, so hostless deployments are unchanged.
        let none = route_cache_key(None, "/x");
        let bare = {
            use std::hash::{Hash, Hasher};
            let mut h = fnv::FnvHasher::default();
            "/x".hash(&mut h);
            h.finish()
        };
        assert_eq!(
            none, bare,
            "hostless key must match the legacy path-only key"
        );
        assert_ne!(
            none, a,
            "a host-scoped key must differ from the hostless key"
        );

        // The key is stable for the same (host, path).
        assert_eq!(a, route_cache_key(Some("api.example.com"), "/x"));
    }

    fn hdr(name: hyper::header::HeaderName, val: &str) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(name, val.parse().unwrap());
        h
    }

    #[test]
    fn origin_freshness_reads_max_age() {
        let h = hdr(hyper::header::CACHE_CONTROL, "public, max-age=300");
        assert_eq!(origin_freshness(&h), Some(300));
    }

    #[test]
    fn origin_freshness_prefers_s_maxage() {
        let h = hdr(hyper::header::CACHE_CONTROL, "max-age=60, s-maxage=600");
        assert_eq!(origin_freshness(&h), Some(600));
    }

    #[test]
    fn origin_freshness_none_when_absent() {
        assert_eq!(origin_freshness(&hyper::HeaderMap::new()), None);
        // no max-age directive present
        let h = hdr(hyper::header::CACHE_CONTROL, "public");
        assert_eq!(origin_freshness(&h), None);
    }

    #[test]
    fn origin_freshness_ignores_substring_of_s_maxage() {
        // "max-age" must not falsely match inside "s-maxage".
        let h = hdr(hyper::header::CACHE_CONTROL, "s-maxage=42");
        assert_eq!(origin_freshness(&h), Some(42));
    }

    // ── RFC 9111 shared-cache storability gate (is_shared_cacheable) ──
    // The cache-policy correctness suite. TTL constant kept generous so only the
    // directive under test decides the outcome.
    const TTL: u64 = 300;

    #[test]
    fn cacheable_anonymous_fresh_plain_200() {
        // Anonymous request, no caching directives, fresh → storable (the
        // common static-asset case must keep working).
        assert!(is_shared_cacheable(false, &hyper::HeaderMap::new(), TTL, 0));
    }

    #[test]
    fn bypass_when_zero_ttl_or_born_stale() {
        // §4.2: lifetime 0, or arrived with Age >= lifetime → never store.
        assert!(!is_shared_cacheable(false, &hyper::HeaderMap::new(), 0, 0));
        assert!(!is_shared_cacheable(
            false,
            &hyper::HeaderMap::new(),
            TTL,
            TTL
        ));
        assert!(!is_shared_cacheable(
            false,
            &hyper::HeaderMap::new(),
            TTL,
            TTL + 1
        ));
    }

    #[test]
    fn bypass_when_response_forbids_shared_storage() {
        // §3.2 / §5.2.2: private / no-store / no-cache → never store.
        for d in ["private", "no-store", "no-cache", "public, private"] {
            let h = hdr(hyper::header::CACHE_CONTROL, d);
            assert!(
                !is_shared_cacheable(false, &h, TTL, 0),
                "should bypass: {d}"
            );
        }
    }

    #[test]
    fn p0_bypass_authenticated_request_without_explicit_optin() {
        // RFC 9111 §3.5 — THE P0. An authenticated request's response must NOT
        // be stored in the shared cache unless the origin explicitly opts in.
        // No directives → bypass (don't leak user A's body to user B).
        assert!(!is_shared_cacheable(true, &hyper::HeaderMap::new(), TTL, 0));
        // A plain `max-age` is NOT a §3.5 opt-in — still bypass.
        let h = hdr(hyper::header::CACHE_CONTROL, "max-age=300");
        assert!(
            !is_shared_cacheable(true, &h, TTL, 0),
            "max-age alone is not a §3.5 shared-cache opt-in for authenticated requests"
        );
    }

    #[test]
    fn p0_caches_authenticated_request_only_on_explicit_optin() {
        // §3.5 explicit opt-ins that DO permit shared storage of an
        // authenticated response: public / s-maxage / must-revalidate.
        for d in [
            "public",
            "s-maxage=60",
            "must-revalidate",
            "public, max-age=300",
        ] {
            let h = hdr(hyper::header::CACHE_CONTROL, d);
            assert!(
                is_shared_cacheable(true, &h, TTL, 0),
                "should cache (opt-in): {d}"
            );
        }
        // …but a forbidding directive still wins over auth opt-in logic.
        let h = hdr(hyper::header::CACHE_CONTROL, "private");
        assert!(!is_shared_cacheable(true, &h, TTL, 0));
    }

    #[test]
    fn bypass_unsafe_vary_but_allow_accept_encoding() {
        // §4.1: only `Accept-Encoding` is folded into the cache key, so any OTHER
        // varied header (incl. ones the old block-list missed, like
        // Accept-Language / User-Agent) is uncacheable — we can't key on it.
        for v in [
            "Accept",
            "Cookie",
            "Authorization",
            "*",
            "Accept-Encoding, Accept",
            "Accept-Language",
            "User-Agent",
            "Accept-Encoding, Accept-Language",
        ] {
            let h = hdr(hyper::header::VARY, v);
            assert!(!is_shared_cacheable(false, &h, TTL, 0), "unsafe vary: {v}");
        }
        // Vary on Accept-Encoding (alone, any case, repeated) IS safe — the key
        // now incorporates the canonical Accept-Encoding set.
        for v in [
            "Accept-Encoding",
            "accept-encoding",
            "Accept-Encoding, accept-encoding",
        ] {
            let h = hdr(hyper::header::VARY, v);
            assert!(is_shared_cacheable(false, &h, TTL, 0), "safe vary: {v}");
        }
    }

    #[test]
    fn accept_encoding_key_canonicalizes() {
        let key = |v: &str| {
            let mut h = hyper::HeaderMap::new();
            if !v.is_empty() {
                h.insert(hyper::header::ACCEPT_ENCODING, v.parse().unwrap());
            }
            accept_encoding_key(&h)
        };
        // Absent header → empty fragment.
        assert_eq!(key(""), "");
        // Lowercased, sorted, order-independent.
        assert_eq!(key("gzip, br"), "br,gzip");
        assert_eq!(key("br, gzip"), "br,gzip");
        assert_eq!(key("GZIP"), "gzip");
        // q=0 = explicitly refused → dropped (so an identity-only client that
        // refuses gzip never shares the gzip variant's entry).
        assert_eq!(key("gzip;q=0, br"), "br");
        assert_eq!(key("gzip;q=0"), "");
        // A normal q-value is not a refusal.
        assert_eq!(key("gzip;q=1.0"), "gzip");
        assert_eq!(key("identity"), "identity");
    }

    #[test]
    fn request_cache_control_directives() {
        // (no_store, no_cache, only_if_cached)
        let cc = |v: &str| {
            let mut h = hyper::HeaderMap::new();
            if !v.is_empty() {
                h.insert(hyper::header::CACHE_CONTROL, v.parse().unwrap());
            }
            parse_request_cache_control(&h)
        };
        assert_eq!(cc(""), (false, false, false));
        assert_eq!(cc("no-store"), (true, false, false));
        assert_eq!(cc("no-cache"), (false, true, false));
        // max-age=0 folds into no-cache (force revalidation); max-age=60 doesn't.
        assert_eq!(cc("max-age=0"), (false, true, false));
        assert_eq!(cc("max-age=60"), (false, false, false));
        assert_eq!(cc("only-if-cached"), (false, false, true));
        assert_eq!(cc("no-store, no-cache"), (true, true, false));
        // Case-insensitive directive names.
        assert_eq!(cc("No-Store"), (true, false, false));
    }

    #[test]
    fn client_conditional_304_matching() {
        let meta = |etag: Option<&str>, lm: Option<&str>| cache::CachedMeta {
            content_type: None,
            content_encoding: None,
            status: hyper::StatusCode::OK,
            etag: etag.map(|e| e.parse().unwrap()),
            last_modified: lm.map(|l| l.parse().unwrap()),
        };
        let req = |name: hyper::header::HeaderName, val: &str| {
            let mut h = hyper::HeaderMap::new();
            h.insert(name, val.parse().unwrap());
            h
        };
        use hyper::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
        // If-None-Match exact, weak (either side), list, and `*` → 304.
        assert!(client_conditional_hit(
            &req(IF_NONE_MATCH, "\"abc\""),
            &meta(Some("\"abc\""), None)
        ));
        assert!(client_conditional_hit(
            &req(IF_NONE_MATCH, "W/\"abc\""),
            &meta(Some("\"abc\""), None)
        ));
        assert!(client_conditional_hit(
            &req(IF_NONE_MATCH, "\"abc\""),
            &meta(Some("W/\"abc\""), None)
        ));
        assert!(client_conditional_hit(
            &req(IF_NONE_MATCH, "\"x\", \"abc\""),
            &meta(Some("\"abc\""), None)
        ));
        assert!(client_conditional_hit(
            &req(IF_NONE_MATCH, "*"),
            &meta(Some("\"abc\""), None)
        ));
        // Non-match, or no stored ETag → not 304.
        assert!(!client_conditional_hit(
            &req(IF_NONE_MATCH, "\"other\""),
            &meta(Some("\"abc\""), None)
        ));
        assert!(!client_conditional_hit(
            &req(IF_NONE_MATCH, "\"abc\""),
            &meta(None, None)
        ));
        // If-Modified-Since: exact echo of stored Last-Modified → 304; differ → not.
        let d = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert!(client_conditional_hit(
            &req(IF_MODIFIED_SINCE, d),
            &meta(None, Some(d))
        ));
        assert!(!client_conditional_hit(
            &req(IF_MODIFIED_SINCE, "Mon, 07 Nov 1994 00:00:00 GMT"),
            &meta(None, Some(d))
        ));
        // No conditional headers → not 304.
        assert!(!client_conditional_hit(
            &hyper::HeaderMap::new(),
            &meta(Some("\"abc\""), None)
        ));
    }

    // ── RFC 8470 §5.2: 0-RTT early-data replay gate (early_data_rejected) ──
    // CI-run coverage for the 425 behavior the docs claimed via a
    // (nonexistent) integration test; guards the main.rs `was_early` plumbing.
    #[test]
    fn early_data_allows_safe_methods() {
        // GET/HEAD are safe to carry in 0-RTT → not rejected.
        assert!(!early_data_rejected(true, &hyper::Method::GET));
        assert!(!early_data_rejected(true, &hyper::Method::HEAD));
    }

    #[test]
    fn early_data_rejects_state_changing_methods() {
        // Non-idempotent / unsafe methods replayed from 0-RTT → 425 Too Early.
        for m in [
            hyper::Method::POST,
            hyper::Method::PUT,
            hyper::Method::PATCH,
            hyper::Method::DELETE,
            hyper::Method::OPTIONS,
        ] {
            assert!(
                early_data_rejected(true, &m),
                "{m} in early data must be rejected"
            );
        }
    }

    #[test]
    fn no_early_data_never_rejects() {
        // Handshake complete (not 0-RTT) → every method passes the gate.
        for m in [
            hyper::Method::GET,
            hyper::Method::POST,
            hyper::Method::DELETE,
        ] {
            assert!(
                !early_data_rejected(false, &m),
                "{m} outside early data must pass"
            );
        }
    }

    // ── RFC 9111 §4.2.2: conservative default freshness + immutable opt-in ──
    #[test]
    fn profile_cache_control_immutable_is_opt_in_via_explicit_year() {
        // The conservative 1h default → plain max-age, NOT immutable (so a
        // header-less response can't be frozen — the audiolibri staleness fix).
        assert_eq!(
            profile_cache_control(3600).to_str().unwrap(),
            "public, max-age=3600"
        );
        // `immutable` is emitted ONLY when an operator explicitly sets a >= 1-year
        // TTL — the deliberate "content-hashed, never revalidate" opt-in.
        assert!(profile_cache_control(31_536_000)
            .to_str()
            .unwrap()
            .contains("immutable"));
    }

    #[test]
    fn upstream_age_parses_header() {
        let h = hdr(hyper::header::AGE, "123");
        assert_eq!(upstream_age(&h), 123);
    }

    #[test]
    fn upstream_age_defaults_zero() {
        assert_eq!(upstream_age(&hyper::HeaderMap::new()), 0);
    }

    #[test]
    fn test_is_internal_ip_loopback_v4() {
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_internal_ip(&ip));
    }

    #[test]
    fn test_is_internal_ip_private_10() {
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_internal_ip(&ip));
    }

    #[test]
    fn test_is_internal_ip_private_172() {
        let ip: std::net::IpAddr = "172.16.5.1".parse().unwrap();
        assert!(is_internal_ip(&ip));
    }

    #[test]
    fn test_is_internal_ip_private_192() {
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        assert!(is_internal_ip(&ip));
    }

    #[test]
    fn test_is_internal_ip_link_local() {
        let ip: std::net::IpAddr = "169.254.0.1".parse().unwrap();
        assert!(is_internal_ip(&ip));
    }

    // ── #151 L7 tarpit wiring (deny_or_tarpit) ──
    //
    // Deterministic, no timing: `hold_secs = 0` exercises the held path
    // without sleeping; `max_concurrent = 0` forces the shed path. Only
    // `deny_or_tarpit` ever touches the `zion_tarpit_*` metrics, so these
    // before/after deltas are race-free across the parallel test run.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    #[tokio::test]
    async fn tarpit_wiring_holds_and_sheds() {
        use crate::sovereign::{EnforceConfig, EnforcePolicy, TarpitConfig};
        use std::sync::atomic::Ordering::Relaxed;

        let m = &metrics::METRICS;

        // Tarpit disabled → immediate 403, no tarpit accounting.
        let disabled = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(!disabled.tarpit_enabled);
        let (t0, s0) = (
            m.tarpit_total.load(Relaxed),
            m.tarpit_shed_total.load(Relaxed),
        );
        let r = deny_or_tarpit(&disabled, StatusCode::FORBIDDEN).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(m.tarpit_total.load(Relaxed), t0);
        assert_eq!(m.tarpit_shed_total.load(Relaxed), s0);

        // Tarpit on, zero hold, ceiling 1 → held path: total +1, gauge back to
        // baseline once the guard drops before return.
        let held = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            tarpit: TarpitConfig {
                enabled: true,
                hold_secs: 0,
                max_concurrent: 1,
            },
            ..Default::default()
        });
        assert!(held.tarpit_enabled);
        let (t1, a1) = (m.tarpit_total.load(Relaxed), m.tarpit_active.load(Relaxed));
        let r = deny_or_tarpit(&held, StatusCode::FORBIDDEN).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(m.tarpit_total.load(Relaxed), t1 + 1);
        assert_eq!(m.tarpit_active.load(Relaxed), a1);

        // Tarpit on but ceiling 0 → shed path: shed +1, nothing held.
        let shed = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            tarpit: TarpitConfig {
                enabled: true,
                hold_secs: 0,
                max_concurrent: 0,
            },
            ..Default::default()
        });
        assert!(shed.tarpit_enabled);
        let s1 = m.tarpit_shed_total.load(Relaxed);
        let r = deny_or_tarpit(&shed, StatusCode::FORBIDDEN).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(m.tarpit_shed_total.load(Relaxed), s1 + 1);
    }

    // ── Singleflight primitive (race fix) ──
    //
    // These tests exercise the watch-channel semantics that replaced the
    // earlier `Notify`-based singleflight. They model the fetcher/waiter
    // interaction in isolation (no HTTP stack, no cache) so the property
    // we fixed — "wait_for resolves immediately if completion already
    // happened, even if the waiter hadn't subscribed yet" — is verifiable
    // deterministically without timing assumptions.

    #[tokio::test]
    async fn singleflight_waiter_subscribes_before_completion() {
        // Standard happy path: subscribe → fetcher completes → waiter wakes.
        let (tx, _) = tokio::sync::watch::channel(false);
        let mut rx = tx.subscribe();
        let fetcher = tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(true);
        });
        rx.wait_for(|v| *v).await.expect("must observe completion");
        fetcher.await.unwrap();
    }

    #[tokio::test]
    async fn singleflight_waiter_subscribes_after_completion() {
        // The race the original Notify-based code could not handle:
        // the fetcher publishes completion AND drops the sender BEFORE
        // the waiter polls wait_for. With watch, wait_for inspects the
        // current value at first poll, so we still observe `true`.
        let (tx, _) = tokio::sync::watch::channel(false);
        let rx = tx.subscribe();

        // Drive the fetcher to completion before we touch the receiver.
        let _ = tx.send(true);
        drop(tx); // sender gone; channel "closed" but last value retained

        let mut rx = rx;
        rx.wait_for(|v| *v)
            .await
            .expect("watch must surface the retained `true` even after sender drop");
    }

    #[tokio::test]
    async fn singleflight_aborted_fetcher_yields_err_to_waiters() {
        // Aborted fetch: sender drops without sending `true`. wait_for
        // must return Err so the waiter falls through to a fresh fetch
        // instead of hanging.
        let (tx, _) = tokio::sync::watch::channel(false);
        let mut rx = tx.subscribe();
        drop(tx);

        let result = rx.wait_for(|v| *v).await;
        assert!(
            result.is_err(),
            "dropped sender without `true` must yield Err to waiters"
        );
    }

    // ── Route LRU (replacement for the "len < 256 then nothing" bug) ──
    //
    // The replaced code accepted inserts only while `len < 256`. After the
    // first 256 distinct path hashes, all subsequent paths fell through to
    // the radix tree forever for that worker thread. These tests pin the
    // new behaviour: O(1) insert with LRU eviction, and — crucially —
    // adversarial path flooding does NOT lock out subsequent hot routes.

    #[test]
    fn route_lru_get_returns_inserted_value() {
        let mut c = route_cache::RouteCache::<u32>::new(4);
        c.insert(1, 100);
        assert_eq!(c.get(1), Some(100));
        assert_eq!(c.get(2), None);
    }

    #[test]
    fn route_lru_get_promotes_to_mru() {
        let mut c = route_cache::RouteCache::<u32>::new(4);
        c.insert(1, 10);
        c.insert(2, 20);
        c.insert(3, 30);
        // Order LRU→MRU: 1, 2, 3
        assert_eq!(c.order(), vec![1, 2, 3]);
        // Touch key 1: it should move to MRU.
        let _ = c.get(1);
        assert_eq!(c.order(), vec![2, 3, 1]);
    }

    #[test]
    fn route_lru_insert_existing_key_updates_and_promotes() {
        let mut c = route_cache::RouteCache::<u32>::new(4);
        c.insert(1, 10);
        c.insert(2, 20);
        c.insert(1, 11); // update + promote to MRU
        assert_eq!(c.get(1), Some(11));
        assert_eq!(c.order(), vec![2, 1]);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn route_lru_evicts_lru_at_capacity() {
        let mut c = route_cache::RouteCache::<u32>::new(3);
        c.insert(1, 10);
        c.insert(2, 20);
        c.insert(3, 30);
        c.insert(4, 40); // forces eviction of 1 (LRU)
        assert_eq!(c.len(), 3);
        assert_eq!(c.get(1), None, "1 should have been evicted");
        assert_eq!(c.order(), vec![2, 3, 4]);
    }

    #[test]
    fn route_lru_recency_preserved_under_mixed_access() {
        // Touch promotes; new insert evicts the genuinely least-recently-used.
        let mut c = route_cache::RouteCache::<u32>::new(3);
        c.insert(1, 10);
        c.insert(2, 20);
        c.insert(3, 30);
        let _ = c.get(1); // 1 → MRU; LRU order now: 2, 3, 1
        c.insert(4, 40); // evict LRU=2
        assert_eq!(c.get(2), None);
        assert_eq!(c.order(), vec![3, 1, 4]);
    }

    #[test]
    fn route_lru_adversarial_flood_does_not_lock_out_hot_routes() {
        // The exact scenario that motivated the fix:
        // 1. An attacker (or a CDN with cache-busted hashes) hits the cache
        //    with `cap` distinct cold path hashes.
        // 2. A legitimate hot path is requested afterwards.
        // The OLD `if len < cap { insert }` would silently DROP the hot path
        // promotion forever. The new LRU evicts a cold entry instead.
        let cap = 8;
        let mut c = route_cache::RouteCache::<u32>::new(cap);
        for k in 0..(cap as u64) {
            c.insert(k, k as u32);
        }
        assert_eq!(c.len(), cap);
        // A new hot path arrives:
        c.insert(9999, 0xBEEF);
        assert_eq!(c.get(9999), Some(0xBEEF), "hot path must be cacheable");
        assert_eq!(c.len(), cap, "capacity bound must hold");
        // The LRU (key 0) is the one that was evicted, not the new one.
        assert_eq!(c.get(0), None);
    }

    #[test]
    fn route_lru_capacity_bound_holds_under_heavy_insert() {
        let cap = 16;
        let mut c = route_cache::RouteCache::<u32>::new(cap);
        for k in 0..1024u64 {
            c.insert(k, k as u32);
            assert!(c.len() <= cap, "capacity must never be exceeded");
        }
        // The most recently inserted `cap` keys must all be present.
        for k in (1024 - cap as u64)..1024 {
            assert_eq!(c.get(k), Some(k as u32));
        }
    }

    #[test]
    fn route_lru_node_recycling_stays_bounded() {
        // Repeated insert-then-evict cycles must not grow `nodes` unbounded.
        // The free-list recycles indices; this test exercises that path.
        let cap = 4;
        let mut c = route_cache::RouteCache::<u32>::new(cap);
        for k in 0..1000u64 {
            c.insert(k, k as u32);
        }
        assert_eq!(c.len(), cap);
        // Last 4 inserts must be the survivors, in MRU order.
        assert_eq!(c.order(), vec![996, 997, 998, 999]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn singleflight_concurrent_waiters_all_observe_completion() {
        // Many waiters subscribe at varying times; some before send, some
        // after. None must hang.
        let (tx, _) = tokio::sync::watch::channel(false);
        let mut tasks = Vec::new();
        for i in 0..32 {
            let mut rx = tx.subscribe();
            tasks.push(tokio::spawn(async move {
                // Stagger subscription/poll order to exercise both pre- and
                // post-completion subscribers on a multi-thread runtime.
                for _ in 0..(i % 4) {
                    tokio::task::yield_now().await;
                }
                rx.wait_for(|v| *v)
                    .await
                    .expect("waiter must observe completion");
            }));
        }
        // Yield a few times so some waiters have polled and parked, while
        // others have not yet subscribed.
        for _ in 0..2 {
            tokio::task::yield_now().await;
        }
        let _ = tx.send(true);

        // Bounded join: if any waiter hangs, the test times out. Without
        // the watch fix, the post-send subscribers would never resolve.
        let join_all = async {
            for t in tasks {
                t.await.unwrap();
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), join_all)
            .await
            .expect("no waiter must hang");
    }
}
