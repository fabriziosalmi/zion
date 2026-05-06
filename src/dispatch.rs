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

use crate::audit::AuditEvent;
use crate::proxy::ZionBody;
use crate::{
    cache, config, health, logging, metrics, observability, proxy, security, waf, AppState,
};
use crate::{
    empty_response, generate_request_id, inject_security_headers, text_response, REQUEST_COUNTER,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "auth")]
use crate::auth;

use crate::config::ResolvedRoute;
use http_body_util::Limited;

const MAX_URI_LEN: usize = 8192;
const MAX_CACHEABLE_BODY: usize = 50 * 1024 * 1024;

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
}

pub(crate) async fn process_request(
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
        return Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED));
    }

    // Gate: 0-RTT replay protection (RFC 8470 — 425 Too Early).
    // TLS 1.3 early data is inherently replay-vulnerable. Only idempotent
    // methods (GET/HEAD) are safe — state-changing methods could be replayed
    // by a network adversary capturing the ClientHello + early data.
    if is_early_data && !matches!(*req.method(), hyper::Method::GET | hyper::Method::HEAD) {
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
            let body = metrics::METRICS.render();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
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
        // FNV hash of path for O(1) thread-local lookup
        let path_hash = {
            use std::hash::{Hash, Hasher};
            let mut h = fnv::FnvHasher::default();
            path.hash(&mut h);
            h.finish()
        };

        // Thread-local cache hit (~5ns) — touch promotes to MRU
        let cached = ROUTE_CACHE.with(|cache| cache.borrow_mut().get(path_hash));

        if let Some(route) = cached {
            route
        } else {
            // Radix tree fallback (~30ns)
            match cfg.router.at(path) {
                Ok(m) => {
                    let route = m.value.clone();
                    ROUTE_CACHE.with(|cache| {
                        cache.borrow_mut().insert(path_hash, route.clone());
                    });
                    route
                }
                Err(_) => return Ok(empty_response(StatusCode::NOT_FOUND)),
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
    // Select the healthy upstream with the lowest latency.
    let target_upstream_url =
        match health::select_best_upstream(&cfg.health_map, &rule.upstream_url) {
            Some(url) => url,
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
                                return Ok(text_response(
                                    StatusCode::UNAUTHORIZED,
                                    "token expired",
                                ));
                            }
                            Err(_) => {
                                return Ok(empty_response(StatusCode::FORBIDDEN));
                            }
                        }
                    }
                    None => {
                        return Ok(text_response(
                            StatusCode::UNAUTHORIZED,
                            "invalid authorization",
                        ));
                    }
                }
            }
            None => {
                return Ok(text_response(
                    StatusCode::UNAUTHORIZED,
                    "authorization required",
                ));
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

        if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
            let (parts, body) = req.into_parts();

            // Borrow content-type from parts.headers — no String allocation needed.
            // The header lives in `parts` which is alive through this scope.
            let ct: Option<&str> = parts
                .headers
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());

            let max_body_bytes = (waf_profile.max_body_mb * 1_048_576) as usize;
            let limited = Limited::new(body, max_body_bytes);
            let body_bytes = match BodyExt::collect(limited).await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(text_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body too large",
                    ))
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
        let mut resp = proxy::proxy_websocket(req, on_upgrade, &dyn_scheme, &dyn_authority).await?;
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
            config::RouteMode::Standard | config::RouteMode::Websocket => {
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
            "request",
        );
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
async fn handle_static_cache(
    req: Request<ZionBody>,
    state: Arc<AppState>,
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    dyn_scheme: &hyper::http::uri::Scheme,
    dyn_authority: &hyper::http::uri::Authority,
    xff_mode: proxy::XffMode,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Use full path+query as cache key to prevent cache poisoning:
    // /api?user=alice and /api?user=bob must NOT share a cache entry.
    let cache_key = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| req.uri().path());

    // RAM hit — zero-copy serve with preserved Content-Type and Content-Encoding
    if let Some(hit) = state.static_cache.get(cache_key) {
        let mut builder = Response::builder()
            .status(hit.meta.status)
            .header("Cache-Control", CACHE_CONTROL_IMMUTABLE);
        if let Some(ct) = &hit.meta.content_type {
            builder = builder.header(hyper::header::CONTENT_TYPE, ct.clone());
        }
        if let Some(ce) = &hit.meta.content_encoding {
            builder = builder.header(hyper::header::CONTENT_ENCODING, ce.clone());
        }
        return Ok(builder
            .body(Full::new(hit.body).map_err(|never| match never {}).boxed())
            .unwrap());
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
        if let Some(hit) = state.static_cache.get(path_owned.as_ref()) {
            metrics::METRICS
                .cache_hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut builder = Response::builder()
                .status(hit.meta.status)
                .header("Cache-Control", CACHE_CONTROL_IMMUTABLE);
            if let Some(ct) = &hit.meta.content_type {
                builder = builder.header(hyper::header::CONTENT_TYPE, ct.clone());
            }
            if let Some(ce) = &hit.meta.content_encoding {
                builder = builder.header(hyper::header::CONTENT_ENCODING, ce.clone());
            }
            return Ok(builder
                .body(Full::new(hit.body).map_err(|never| match never {}).boxed())
                .unwrap());
        }
        // Cache miss even after wait — fall through to fetch from upstream
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
            // tx drops at end of scope → channel closed → waiters get Err
            return Err(e);
        }
    };

    // Only cache 200 OK responses
    if resp.status() == StatusCode::OK {
        let (parts, body) = resp.into_parts();

        // S-04: Skip caching if upstream uses content negotiation or personalization.
        // Caching content-negotiated responses with path-only key would serve wrong
        // content types or personalized data to other clients.
        let has_unsafe_vary = parts
            .headers
            .get(hyper::header::VARY)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                // Check for content-negotiation headers that make path-only
                // caching unsafe. Use exact token matching to avoid false positives:
                // "Accept-Encoding" is safe (cache stores raw bytes), but "Accept"
                // means the upstream varies on media type which IS unsafe.
                let v_lower = v.to_ascii_lowercase();
                v_lower.split(',').any(|token| {
                    let t = token.trim();
                    t == "accept" || t == "negotiate" || t == "authorization" || t == "cookie"
                }) || v_lower == "*"
            })
            .unwrap_or(false);

        if has_unsafe_vary {
            // Stream the body straight to the client without caching.
            // Drop the inflight sender (no `true` sent): waiters fall through
            // to a fresh fetch, since cache will not be populated for this key.
            state.inflight.remove(&path_owned);
            let resp = Response::from_parts(parts, body.map_err(hyper::Error::from).boxed());
            return Ok(resp);
        }

        // Preserve Content-Type and Content-Encoding for cache (S-05 fix).
        // Without Content-Encoding, gzip-compressed bodies are served garbled.
        let content_type = parts.headers.get(hyper::header::CONTENT_TYPE).cloned();
        let content_encoding = parts.headers.get(hyper::header::CONTENT_ENCODING).cloned();
        let meta = cache::CachedMeta {
            content_type,
            content_encoding,
            status: parts.status,
        };

        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(16);
        let stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
        let stream_body = http_body_util::StreamBody::new(stream);

        let state_clone = state.clone();
        let path_clone = path_owned.clone();
        let meta_clone = meta.clone();
        let tx_clone = tx.clone();

        let (cache_ttl, cache_max) = match &rule.cache {
            Some(cp) => (cp.ttl_seconds, cp.max_entries),
            None => (31_536_000, 10_000),
        };

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
                    cache_ttl,
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
        resp.headers_mut().insert(
            "Cache-Control",
            hyper::header::HeaderValue::from_static(CACHE_CONTROL_IMMUTABLE),
        );
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
