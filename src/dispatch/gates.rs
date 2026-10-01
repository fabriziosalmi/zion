// SPDX-License-Identifier: Apache-2.0
//! The request pipeline's gates, in the order they run.
//!
//! `process_request_inner` used to hold every pre-routing check inline, so the
//! order — which is most of the security value — was implicit in 250 lines of
//! control flow and could not be unit-tested. Here each gate is one small function
//! and the order is DATA: [`PRE_ROUTING`]. A gate returns `Some(response)` to answer
//! the request itself, or `None` to let it continue.
//!
//! The order is pinned twice: by `PRE_ROUTING_ORDER` below, and behaviourally by
//! `gate_order_tests` (each case trips two gates and asserts which one answers).
//! Changing either without the other fails a test.

use super::{check_rate_limit, early_data_rejected, MAX_URI_LEN};
use crate::http_util::{
    empty_response, inject_security_headers, method_not_allowed, text_response,
};
use crate::metrics;
use crate::proxy::ZionBody;
use crate::routing::ResolvedRoute;
use crate::state::{AppState, ResolvedAppConfig};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
use super::deny_or_tarpit;

/// What every pre-routing gate can see besides the request itself.
pub(super) struct PreCtx {
    /// The config snapshot this request runs under (one generation, start to end).
    pub(super) cfg: Arc<ResolvedAppConfig>,
    /// The client address after trusted-proxy resolution.
    pub(super) client_ip: IpAddr,
    /// The TCP peer (kept for gates that need the raw peer, not the resolved client).
    #[allow(dead_code)]
    pub(super) remote_addr: SocketAddr,
    /// The request arrived as TLS 1.3 early data (0-RTT).
    pub(super) is_early_data: bool,
}

/// One pre-routing gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Gate {
    /// Drop client-supplied identity headers (a mutation, never answers).
    ScrubIdentityHeaders,
    /// Drop client-supplied routing / host override headers unless the peer is a trusted
    /// proxy (a mutation, never answers).
    ScrubOverrideHeaders,
    /// 414 for an oversized URI.
    UriLength,
    /// Rewrite the path to its normalized form (mutation; 400 if it cannot be rebuilt).
    NormalizePath,
    /// 405 for a method outside the whitelist.
    Method,
    /// 425 for a state-changing method in early data.
    EarlyData,
    /// 508 for a request whose `Via` already names this process (it has looped).
    LoopDetection,
    /// 429 once the client's per-IP budget is spent.
    RateLimit,
    /// Sovereign enforcement: deny an opted-in IP class.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    SovereignClass,
    /// JA4 per-fingerprint route restriction.
    #[cfg(feature = "tls-fingerprint")]
    TlsFingerprint,
    /// AIMP mesh reputation: a header, or an optional deny.
    #[cfg(feature = "sovereign-aimp")]
    MeshScore,
}

/// The gates, in the order they run. Before the built-in endpoints and before route
/// lookup. The rate limiter stays ahead of `/healthz` and `/metrics` so neither is a
/// way around it.
pub(super) const PRE_ROUTING: &[Gate] = &[
    Gate::ScrubIdentityHeaders,
    Gate::ScrubOverrideHeaders,
    Gate::UriLength,
    Gate::NormalizePath,
    Gate::Method,
    Gate::EarlyData,
    Gate::LoopDetection,
    Gate::RateLimit,
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    Gate::SovereignClass,
    #[cfg(feature = "tls-fingerprint")]
    Gate::TlsFingerprint,
    #[cfg(feature = "sovereign-aimp")]
    Gate::MeshScore,
];

/// Run [`PRE_ROUTING`] until one gate answers.
pub(super) async fn run_pre_routing(
    ctx: &PreCtx,
    state: &Arc<AppState>,
    req: &mut Request<ZionBody>,
) -> Option<Response<ZionBody>> {
    for gate in PRE_ROUTING {
        let answer = match gate {
            Gate::ScrubIdentityHeaders => {
                super::scrub_reserved_identity_headers(req.headers_mut());
                None
            }
            Gate::ScrubOverrideHeaders => {
                if !ctx.cfg.trusted_proxies.is_trusted(&ctx.remote_addr.ip()) {
                    crate::security::scrub_client_override_headers(req.headers_mut());
                }
                None
            }
            Gate::UriLength => uri_length(req),
            Gate::NormalizePath => normalize_path(req),
            Gate::Method => method_whitelist(req),
            Gate::EarlyData => early_data(ctx, req),
            Gate::LoopDetection => loop_detection(req),
            Gate::RateLimit => rate_limit(ctx, state),
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            Gate::SovereignClass => sovereign_class(ctx, state, req).await,
            #[cfg(feature = "tls-fingerprint")]
            Gate::TlsFingerprint => tls_fingerprint(ctx, req),
            #[cfg(feature = "sovereign-aimp")]
            Gate::MeshScore => mesh_score(ctx, state, req).await,
        };
        if answer.is_some() {
            return answer;
        }
    }
    None
}

/// Gate: URI length.
fn uri_length(req: &Request<ZionBody>) -> Option<Response<ZionBody>> {
    // Gate: URI length (reject oversized URIs before routing).
    // Check full path+query, not just path — an attacker could send a short
    // path with an enormous query string to consume memory downstream.
    let uri_len = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().len())
        .unwrap_or_else(|| req.uri().path().len());
    if uri_len > MAX_URI_LEN {
        return Some(empty_response(StatusCode::URI_TOO_LONG));
    }
    None
}

/// Gate: normalize the request path (RFC 3986 §6.2.2) before anything decides from it.
/// Routing, `internal_only`, the WAF and auth profiles, the cache key and the path sent
/// upstream must all read the same path, or `/open/../internal/x` matches the open route
/// and still reaches `/internal/x` (see `uri_norm`). The query string is left as written.
fn normalize_path(req: &mut Request<ZionBody>) -> Option<Response<ZionBody>> {
    crate::uri_norm::rewrite_request(req)
        .err()
        .map(|()| empty_response(StatusCode::BAD_REQUEST))
}

/// Gate: HTTP method whitelist.
fn method_whitelist(req: &Request<ZionBody>) -> Option<Response<ZionBody>> {
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
        return Some(method_not_allowed(
            "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
        ));
    }
    None
}

/// Gate: 0-RTT replay protection.
fn early_data(ctx: &PreCtx, req: &Request<ZionBody>) -> Option<Response<ZionBody>> {
    let is_early_data = ctx.is_early_data;
    // Gate: 0-RTT replay protection (RFC 8470 — 425 Too Early).
    // TLS 1.3 early data is inherently replay-vulnerable. Only idempotent
    // methods (GET/HEAD) are safe — state-changing methods could be replayed
    // by a network adversary capturing the ClientHello + early data.
    if early_data_rejected(is_early_data, req.method()) {
        // SAFETY: 425 "Too Early" (RFC 8470) is a valid HTTP status code in
        // the 100..1000 range that hyper accepts. The literal `425` is a
        // compile-time constant; `from_u16` rejects only out-of-range u16s.
        return Some(empty_response(StatusCode::from_u16(425).unwrap()));
    }
    None
}

/// Gate: a request that already went through this process is bouncing between hops
/// (an upstream that points back at us); refuse it instead of feeding the loop.
fn loop_detection(req: &Request<ZionBody>) -> Option<Response<ZionBody>> {
    if !crate::via::is_loop(req.headers()) {
        return None;
    }
    metrics::METRICS
        .loops_detected
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Some(empty_response(StatusCode::LOOP_DETECTED))
}

/// Gate: per-IP rate limit.
fn rate_limit(ctx: &PreCtx, state: &Arc<AppState>) -> Option<Response<ZionBody>> {
    let client_ip = ctx.client_ip;
    // Gate: per-IP rate limit (zero cost when disabled)
    // Placed BEFORE health endpoints so /healthz can't bypass rate limiting for DDoS.
    if !check_rate_limit(&state, client_ip) {
        metrics::METRICS
            .rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Some(empty_response(StatusCode::TOO_MANY_REQUESTS));
    }
    None
}

/// Gate: sovereign IP classification and enforcement.
#[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
async fn sovereign_class(
    ctx: &PreCtx,
    state: &Arc<AppState>,
    req: &mut Request<ZionBody>,
) -> Option<Response<ZionBody>> {
    let (cfg, client_ip) = (&ctx.cfg, ctx.client_ip);
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
                return Some(deny_or_tarpit(&cfg.enforce, StatusCode::FORBIDDEN).await);
            }
            if cfg.sovereign_log_classification && ip_class != sovereign::IpClass::Unknown {
                tracing::info!(
                    target: "sovereign",
                    ip = %state.redact.ip_label(client_ip),
                    class = ip_class.as_str(),
                    "classified",
                );
            }
        }
    }
    None
}

/// Gate: JA4 per-fingerprint route restriction.
#[cfg(feature = "tls-fingerprint")]
fn tls_fingerprint(ctx: &PreCtx, req: &Request<ZionBody>) -> Option<Response<ZionBody>> {
    let cfg = &ctx.cfg;
    // ── JA4 per-fingerprint route restriction (#27 follow-up) ──
    //
    // Request-level policy, so the deny is HTTP-level: the handshake already
    // happened, and on HTTP/2 dropping the connection would kill unrelated
    // in-flight requests — 403, like the sovereign enforcement gate above.
    // The `X-Client-TLS-JA4` header is Zion's OWN attestation (any inbound
    // copy is stripped and the verified value re-injected at the listener —
    // see `tls_fp::apply_headers`), so trusting it here is sound. Like every
    // pre-routing gate, this early return never reaches the access log; the
    // `zion_tls_fp_route_denied` metric is the operator signal. Policy, mode
    // handling, metric, and (debug) logging all live in `route_gate` — and
    // note the gate covers the WHOLE request surface reaching dispatch
    // (built-in /metrics included). /healthz and /readyz are exempt INSIDE
    // route_gate: HTTP/3 bridges into dispatch directly (quic.rs), so the
    // health exemption must be the gate's own property, not an accident of
    // the :443 listener fast path.
    #[cfg(feature = "tls-fingerprint")]
    if let Some(fp) = cfg.tls_fingerprint.as_ref() {
        if let Some(ja4) = req
            .headers()
            .get(crate::tls_fp::HDR_JA4)
            .and_then(|v| v.to_str().ok())
        {
            if fp.route_gate(ja4, req.uri().path()) == crate::tls_fp::GateDecision::Reject {
                return Some(empty_response(StatusCode::FORBIDDEN));
            }
        }
    }
    None
}

/// Gate: AIMP mesh reputation (header, plus an optional deny).
#[cfg(feature = "sovereign-aimp")]
async fn mesh_score(
    ctx: &PreCtx,
    state: &Arc<AppState>,
    req: &mut Request<ZionBody>,
) -> Option<Response<ZionBody>> {
    let client_ip = ctx.client_ip;
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    let cfg = &ctx.cfg;
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
                return Some(deny_or_tarpit(&cfg.enforce, StatusCode::FORBIDDEN).await);
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
    None
}

/// The built-in endpoints: `/healthz`, `/readyz`, `/metrics`, `/_zion/snapshot.json`,
/// `/_zion/cache/purge`. They are answered here, after the pre-routing gates and
/// before route lookup.
pub(super) fn builtin_endpoint(
    ctx: &PreCtx,
    state: &Arc<AppState>,
    req: &Request<ZionBody>,
) -> Option<Response<ZionBody>> {
    let (cfg, client_ip) = (&ctx.cfg, ctx.client_ip);
    // ── Built-in health endpoints (no routing, no upstream) ──
    {
        let path = req.uri().path();
        if path == "/healthz" {
            return Some(text_response(StatusCode::OK, "ok"));
        }
        if path == "/readyz" {
            return Some(text_response(StatusCode::OK, "ready"));
        }
        // S-02 FIX: /metrics restricted to internal IPs only.
        // Without this, the built-in handler takes precedence over the route
        // config's internal_only flag, exposing metrics to external clients.
        if path == "/metrics" {
            if !cfg.internal_networks.contains(&client_ip) {
                return Some(empty_response(StatusCode::FORBIDDEN));
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
            let body = metrics::METRICS.render_with_upstreams(openmetrics, &state.cfg().health_map);
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", content_type)
                    .body(Full::new(body).map_err(|never| match never {}).boxed())
                    .unwrap(),
            );
        }
        // Live JSON snapshot — what `zion top` and dashboards consume.
        // Same internal-only gate as /metrics: never expose to the world.
        if path == "/_zion/snapshot.json" {
            if !cfg.internal_networks.contains(&client_ip) {
                return Some(empty_response(StatusCode::FORBIDDEN));
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
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .header("Cache-Control", "no-store")
                    .body(Full::new(body).map_err(|never| match never {}).boxed())
                    .unwrap(),
            );
        }
        // Cache purge — flush the in-RAM cache so a deploy can invalidate
        // immediately instead of waiting out the TTL. Internal-only + POST
        // (mutating). `?prefix=/path` purges matching keys; no prefix = all.
        if path == "/_zion/cache/purge" {
            if !cfg.internal_networks.contains(&client_ip) {
                return Some(empty_response(StatusCode::FORBIDDEN));
            }
            if *req.method() != hyper::Method::POST {
                return Some(method_not_allowed("POST"));
            }
            let prefix = req.uri().query().and_then(|q| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("prefix="))
                    .map(|p| p.to_string())
            });
            // `?tag=a,b` (repeatable): purge by `Surrogate-Key` tag.
            let has_tag_param = req
                .uri()
                .query()
                .is_some_and(|q| q.split('&').any(|kv| kv.starts_with("tag=")));
            let tags: Vec<String> = req
                .uri()
                .query()
                .map(|q| {
                    q.split('&')
                        .filter_map(|kv| kv.strip_prefix("tag="))
                        .flat_map(|v| v.split(','))
                        .filter(|t| !t.is_empty())
                        .map(percent_decode)
                        .collect()
                })
                .unwrap_or_default();
            // `?tag=` with nothing in it is a mistake, not a request to flush everything.
            if has_tag_param && tags.is_empty() {
                return Some(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "text/plain; charset=utf-8")
                        .body(
                            Full::new(Bytes::from_static(b"empty tag\n"))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .unwrap(),
                );
            }
            let (removed, scope) = if !tags.is_empty() {
                let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
                (
                    state.static_cache.purge_tags(&refs),
                    format!(
                        "{{\"tags\":{}}}",
                        serde_json::to_string(&tags).unwrap_or_default()
                    ),
                )
            } else {
                match &prefix {
                    Some(p) => (state.static_cache.purge_prefix(p), format!("{p:?}")),
                    None => (state.static_cache.purge_all(), "\"all\"".to_string()),
                }
            };
            crate::logging::info("cache", &format!("purge scope={scope} removed={removed}"));
            let body = Bytes::from(format!("{{\"purged\":{removed},\"scope\":{scope}}}\n"));
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .header("Cache-Control", "no-store")
                    .body(Full::new(body).map_err(|never| match never {}).boxed())
                    .unwrap(),
            );
        }
    }
    None
}

/// Per-route CORS. Returns the `Access-Control-Allow-Origin` value to put on the
/// response later, and `Some(response)` when the gate answers itself (a preflight,
/// or a refused origin).
pub(super) fn cors_gate(
    rule: &ResolvedRoute,
    req: &Request<ZionBody>,
) -> (
    Option<hyper::header::HeaderValue>,
    Option<Response<ZionBody>>,
) {
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
        // An origin is present: reuse the `cors_allow_origin` computed above
        // instead of calling `check_origin` (and re-lowercasing the origin) a
        // second time per request.
        if req_origin.is_some() {
            match cors_allow_origin.as_ref() {
                Some(allow_origin) => {
                    // Pre-flight OPTIONS — respond immediately without proxying.
                    if *req.method() == hyper::Method::OPTIONS {
                        let mut resp = empty_response(StatusCode::NO_CONTENT);
                        let h = resp.headers_mut();
                        h.insert(
                            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                            allow_origin.clone(),
                        );
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
                        return (None, Some(resp));
                    }
                }
                None => {
                    // Origin present but not allowed — block state-changing
                    // methods AND preflight.
                    if *req.method() == hyper::Method::OPTIONS
                        || matches!(
                            *req.method(),
                            hyper::Method::POST
                                | hyper::Method::PUT
                                | hyper::Method::PATCH
                                | hyper::Method::DELETE
                        )
                    {
                        return (None, Some(empty_response(StatusCode::FORBIDDEN)));
                    }
                }
            }
        }
    }
    (cors_allow_origin, None)
}

/// Per-route `internal_only`.
pub(super) fn internal_only(
    rule: &ResolvedRoute,
    cfg: &ResolvedAppConfig,
    client_ip: IpAddr,
) -> Option<Response<ZionBody>> {
    // --- Gate: internal_only ---
    if rule.internal_only && !cfg.internal_networks.contains(&client_ip) {
        return Some(empty_response(StatusCode::FORBIDDEN));
    }
    None
}

/// `%XX` decoding for a query value (`+` is left alone: tags are not form-encoded). Invalid
/// escapes are kept as written.
pub(super) fn percent_decode(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(n) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(n);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The order of the pre-routing gates, as data. Reordering two of them is a
    /// change to what a request is refused for first; do it on purpose, here.
    #[test]
    fn pre_routing_order() {
        let always = [
            Gate::ScrubIdentityHeaders,
            Gate::ScrubOverrideHeaders,
            Gate::UriLength,
            Gate::NormalizePath,
            Gate::Method,
            Gate::EarlyData,
            Gate::LoopDetection,
            Gate::RateLimit,
        ];
        assert_eq!(&PRE_ROUTING[..always.len()], &always);
        // optional gates come after the always-on ones, in this order
        let rest: Vec<Gate> = PRE_ROUTING[always.len()..].to_vec();
        let expected: Vec<Gate> = vec![
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            Gate::SovereignClass,
            #[cfg(feature = "tls-fingerprint")]
            Gate::TlsFingerprint,
            #[cfg(feature = "sovereign-aimp")]
            Gate::MeshScore,
        ];
        assert_eq!(rest, expected);
    }

    #[test]
    fn percent_decode_handles_escapes_and_leaves_the_rest_alone() {
        assert_eq!(percent_decode("post-1"), "post-1");
        assert_eq!(percent_decode("a%2Fb%3Ac"), "a/b:c");
        assert_eq!(percent_decode("100%"), "100%", "a trailing % is kept");
        assert_eq!(percent_decode("%zz%4"), "%zz%4", "invalid escapes are kept");
        assert_eq!(percent_decode("a+b"), "a+b", "tags are not form-encoded");
        assert_eq!(percent_decode("caf%C3%A9"), "café");
        assert_eq!(
            percent_decode("é%"),
            "é%",
            "multibyte text is not sliced mid-character"
        );
    }
}
