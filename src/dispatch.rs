use crate::proxy::ZionBody;
use crate::{cache, config, health, logging, metrics, proxy, security, waf, AppState};
use crate::{
    empty_response, generate_request_id, inject_security_headers, text_response, REQUEST_COUNTER,
};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "auth")]
use crate::auth;

use crate::config::ResolvedRoute;
use http_body_util::combinators::BoxBody;
use http_body_util::Limited;

const MAX_URI_LEN: usize = 8192;
const MAX_CACHEABLE_BODY: usize = 50 * 1024 * 1024;

const CACHE_CONTROL_IMMUTABLE: &str = "public, max-age=31536000, immutable";

#[inline]
fn check_rate_limit(state: &AppState, ip: std::net::IpAddr) -> bool {
    security::check_rate_limit(
        state.rate_limit_rps,
        state.rate_limit_window,
        &state.rate_map,
        ip,
    )
}

pub(crate) async fn process_request(
    mut req: Request<ZionBody>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
    is_early_data: bool,
) -> Result<Response<ZionBody>, hyper::Error> {
    let request_start = std::time::Instant::now();

    // ── Pre-routing security gates (zero-cost, before any processing) ──

    // Gate: URI length (reject oversized URIs before routing)
    if req.uri().path().len() > MAX_URI_LEN {
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
        return Ok(empty_response(StatusCode::from_u16(425).unwrap()));
    }

    // ── Resolve real client IP (proxy-aware) ──
    // When trusted_proxies is configured, extract the real client IP from
    // X-Forwarded-For using the rightmost-untrusted-hop algorithm.
    // This prevents rate limit bypass and internal-only gate evasion when
    // Zion is behind ALB/Cloudflare/nginx.
    let client_ip = state.trusted_proxies.resolve_client_ip(
        remote_addr.ip(),
        req.headers()
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok()),
    );

    // Gate: per-IP rate limit (zero cost when disabled)
    // Placed BEFORE health endpoints so /healthz can't bypass rate limiting for DDoS.
    if !check_rate_limit(&state, client_ip) {
        metrics::METRICS
            .rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(empty_response(StatusCode::TOO_MANY_REQUESTS));
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
                .body(
                    Full::new(body)
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap());
        }
    }

    // ── Radix tree lookup ──
    let rule = {
        let path = req.uri().path();
        match state.router.at(path) {
            Ok(m) => m.value.clone(),
            Err(_) => return Ok(empty_response(StatusCode::NOT_FOUND)),
        }
    };

    // ── CORS (Per-Route) ──
    let req_origin: Option<String> = if rule.cors.is_some() {
        req.headers()
            .get(hyper::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned())
    } else {
        None
    };

    if let Some(ref cors) = rule.cors {
        if let Some(ref origin_str) = req_origin {
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
                // Origin not in allowed list — block state-changing methods (CSRF prevention).
                if matches!(
                    *req.method(),
                    hyper::Method::POST
                        | hyper::Method::PUT
                        | hyper::Method::PATCH
                        | hyper::Method::DELETE
                ) {
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
        match health::select_best_upstream(&state.health_map, &rule.upstream_url) {
            Some(url) => url,
            None => {
                metrics::METRICS.record_status(503);
                return Ok(text_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "upstream unavailable",
                ));
            }
        };

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
        let uri_str = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or_else(|| req.uri().path());
        if let waf::WafVerdict::Deny(reason) = waf::validate_uri(uri_str) {
            metrics::METRICS
                .waf_denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            metrics::METRICS.record_status(400);
            logging::info("waf", &format!("URI denied: {} ({})", reason, uri_str));
            return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
        }

        if matches!(method, "POST" | "PUT" | "PATCH") {
            // Extract content-type before consuming req
            let ct_owned: Option<String> = req
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned());

            let (parts, body) = req.into_parts();

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

            let verdict =
                waf::validate_request(method, ct_owned.as_deref(), &body_bytes, waf_profile);
            if let waf::WafVerdict::Deny(_) = verdict {
                metrics::METRICS
                    .waf_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics::METRICS.record_status(400);
                return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
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
            if let waf::WafVerdict::Deny(_) = verdict {
                metrics::METRICS
                    .waf_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics::METRICS.record_status(400);
                return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
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
    // Preserve incoming traceparent or generate a new one.
    // Forward to upstream for distributed tracing (Jaeger, Tempo, etc.)
    if !req.headers().contains_key("traceparent") {
        // Generate: version-trace_id-parent_id-flags (00-{32hex}-{16hex}-01)
        // Use SystemTime for entropy (not elapsed() which is ~0ns at this point)
        let ts_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let seq = REQUEST_COUNTER.load(std::sync::atomic::Ordering::Relaxed);
        let trace_id = format!("{:016x}{:016x}", ts_us, seq);
        let span_id = format!("{:016x}", seq);
        let traceparent = format!("00-{}-{}-01", trace_id, span_id);
        if let Ok(val) = hyper::header::HeaderValue::from_str(&traceparent) {
            req.headers_mut().insert("traceparent", val);
        }
    }

    // Pre-extract X-Request-ID for response echo (before req is consumed)
    let request_id_val = req.headers().get("X-Request-ID").cloned();

    // Pre-compute CORS allow origin before state is consumed
    let cors_allow_origin: Option<hyper::header::HeaderValue> = req_origin
        .as_deref()
        .and_then(|o| rule.cors.as_ref().and_then(|c| c.check_origin(o)));

    // --- Dispatch by mode ---
    let mut resp = if rule.cache.is_some() {
        handle_static_cache(
            req,
            state.clone(),
            &rule,
            remote_addr,
            &dyn_scheme,
            &dyn_authority,
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
                )
                .await?
            }
            config::RouteMode::SseStream => {
                proxy::proxy_pass_stream(
                    &state.http_client,
                    req,
                    &dyn_scheme,
                    &dyn_authority,
                    Some(remote_addr),
                    "https",
                )
                .await?
            }
            config::RouteMode::Standard | config::RouteMode::Websocket => {
                proxy::proxy_pass(
                    &state.http_client,
                    req,
                    &dyn_scheme,
                    &dyn_authority,
                    Some(remote_addr),
                    "https",
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

    // Record request duration histogram
    metrics::METRICS
        .request_duration
        .observe(request_start.elapsed());

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
) -> Result<Response<ZionBody>, hyper::Error> {
    // Use full path+query as cache key to prevent cache poisoning:
    // /api?user=alice and /api?user=bob must NOT share a cache entry.
    let cache_key = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| req.uri().path());

    // RAM hit — zero-copy serve with preserved Content-Type
    if let Some(hit) = state.static_cache.get(cache_key) {
        let mut builder = Response::builder()
            .status(hit.meta.status)
            .header("Cache-Control", CACHE_CONTROL_IMMUTABLE);
        if let Some(ct) = &hit.meta.content_type {
            builder = builder.header(hyper::header::CONTENT_TYPE, ct.clone());
        }
        return Ok(builder
            .body(Full::new(hit.body).map_err(|never| match never {}).boxed())
            .unwrap());
    }

    // Need to own cache key before consuming req
    let path_owned = cache_key.to_owned();

    // RAM miss — fetch from upstream
    let resp = proxy::proxy_pass(
        &state.http_client,
        req,
        dyn_scheme,
        dyn_authority,
        Some(remote_addr),
        "https",
    )
    .await?;

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
            // Stream the body straight to the client without dropping back to RAM allocation!
            let resp = Response::from_parts(parts, body.map_err(hyper::Error::from).boxed());
            return Ok(resp);
        }

        // Preserve Content-Type for cache (S-05 fix)
        let content_type = parts.headers.get(hyper::header::CONTENT_TYPE).cloned();
        let meta = cache::CachedMeta {
            content_type,
            status: parts.status,
        };

        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(16);
        let stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
        let stream_body = http_body_util::StreamBody::new(stream);

        let state_clone = state.clone();
        let path_clone = path_owned.clone();
        let meta_clone = meta.clone();

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
                            // Client disconnected abruptly. Abort buffering
                            return;
                        }
                    }
                    Some(Err(e)) => {
                        // Upstream chunking failed, forward the error and bail out
                        let _ = sender.send(Err(e)).await;
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
            }
        });

        let mut resp = Response::from_parts(parts, stream_body.boxed());
        resp.headers_mut().insert(
            "Cache-Control",
            hyper::header::HeaderValue::from_static(CACHE_CONTROL_IMMUTABLE),
        );
        return Ok(resp);
    }

    Ok(resp)
}

/// Check if an IP is internal — delegates to security module.
#[inline]
fn is_internal_ip(ip: &std::net::IpAddr) -> bool {
    security::is_internal_ip(ip)
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
}
