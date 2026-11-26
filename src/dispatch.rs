// SPDX-License-Identifier: Apache-2.0
//! Request dispatch — the per-request state machine.
//!
//! Sits between the TLS listener and the upstream/cache. For each
//! accepted request it walks the pipeline:
//!
//!   1. security gates (URI length, method whitelist, rate limiter,
//!      CORS pre-flight) — the rate limiter deliberately runs BEFORE the
//!      built-in endpoints below, so a request that reaches THIS
//!      pipeline cannot use `/healthz` to dodge it. (The :443 h1/h2
//!      listener separately answers health probes on its own fast path
//!      in accept.rs, before this pipeline, and unrated by design:
//!      liveness checks must answer even when the box is saturated. A
//!      target with userinfo is no probe there: it comes on to this
//!      pipeline's gate.)
//!   2. built-in endpoints (`/healthz`, `/readyz`, `/metrics`,
//!      `/_zion/snapshot.json`)
//!   3. radix routing → `Arc<ResolvedRoute>`
//!   4. WAF pipeline (content-type, size, structural validation,
//!      entropy, Aho-Corasick scan)
//!   5. cache lookup or upstream proxy
//!   6. response hardening (security headers, hop-by-hop strip)
//!
//! Hot path: zero allocation in the common case. Everything that turns
//! a `Request` into a `Response` lives here or is called from here.
//!
//! Feature gating: the sovereign classification + enforcement path
//! (`deny_or_tarpit`, the enforce gate) is compiled in only under
//! `feature = "geo-ita"` or `feature = "geo-eu"`. A default-feature binary
//! does NOT run it — keep that in mind before chasing an enforcement bug in a
//! build that never included the code.

use crate::audit;
use crate::audit::AuditEvent;
use crate::bulkhead;
use crate::http_util::{
    empty_response, generate_request_id, inject_security_headers, text_response, CacheControl,
    HEX_DIGITS,
};
use crate::http_util::{ReqBody, ZionBody};
use crate::pool;
use crate::state::AppState;
use crate::state::ResolvedAppConfig;
use crate::{
    breaker, cache, config, health, logging, metrics, observability, proxy, security, uri_norm,
    vary, waf,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::routing::ResolvedRoute;
use crate::upstream_body::read_capped;

mod body_gate;
mod cached;
mod gates;
mod route;
mod telemetry;
mod waf_gate;
pub(crate) use gates::{path_shape, uri_too_long, virtual_patch};

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

/// Maximum allowed URI length (bytes). Requests exceeding this are dropped before routing —
/// prevents buffer overflow probes and log pollution.
const MAX_URI_LEN: usize = 8192;
/// Largest cacheable body for a route with no cache profile of its own; profiles set
/// theirs with `max_object_mb`.
const DEFAULT_MAX_OBJECT_BYTES: usize = 50 * 1024 * 1024;

/// Per-frame idle timeout while reading a request body on the streaming WAF
/// path: if no body frame arrives within this window the client is trickling
/// (slow-read / slowloris-body) and we evict it with 408. This bounds the idle
/// time *between* reads rather than total upload time, so a legit large upload
/// over a slow-but-steady link is not penalised. The HTTP/3 listener waits as long
/// for the end of a body declared empty.
pub(crate) const BODY_FRAME_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Total timeout for buffering a request body on the non-streaming path (the
/// smaller default bodies). A trickled body trips this long before a legit
/// upload near `max_body_mb` would.
const BODY_COLLECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// What a failed read of the request body means. `read_capped` reports overflow as a
/// `BodyTooLarge`; anything else is the client's stream breaking (reset,
/// malformed chunked framing, a connection that dropped). Telling them apart keeps
/// `413` meaning "too large", and the cause goes to the log because the response
/// only says what the client needs to know.
fn body_read_failure(
    e: &(dyn std::error::Error + Send + Sync + 'static),
) -> (StatusCode, &'static str) {
    if e.is::<crate::upstream_body::BodyTooLarge>() {
        (StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
    } else {
        (StatusCode::BAD_REQUEST, "request body read error")
    }
}

/// Log why a request body could not be read, at most a few lines every ten seconds:
/// a client can break an upload as often as it likes.
fn log_body_failure(remote: &SocketAddr, method: &str, path: &str, what: &str) {
    static LOG: logging::Throttle = logging::Throttle::new(5, 10);
    if LOG.allow() {
        logging::warn(
            "body",
            &format!("request body not read: {what} remote={remote} method={method} path={path}"),
        );
    }
}

const CACHE_CONTROL_IMMUTABLE: &str = "public, max-age=31536000, immutable";

#[inline]
fn check_rate_limit(state: &AppState, ip: std::net::IpAddr) -> bool {
    let cfg = state.cfg();
    security::check_rate_limit(
        cfg.rate_limit_rps,
        cfg.rate_limit_window,
        cfg.rate_limit_max_tracked_ips,
        &state.limiters.rate_map,
        &state.limiters.rate_sweep,
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
        remote_ip: Some(state.redact.ip_label(remote_addr.ip()).to_string()),
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
    req: Request<ReqBody>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
    is_early_data: bool,
) -> Result<Response<ZionBody>, hyper::Error> {
    let client_request_id = req.headers().get("X-Request-ID").cloned();
    let mut resp = process_request_inner(req, state, remote_addr, is_early_data).await?;
    // Record status ONCE per request, for every outcome. This is the single
    // choke point every response flows through, so counting here — instead of
    // at each `return` inside the pipeline — means the pre-routing security
    // rejects (414/405/425/429/403 and the auth 401/403) are counted too.
    // Previously those returned before the inner recording site, so an attack
    // that tripped a gate was invisible in `/metrics` and undercounted
    // `requests_total`. `record_status` must fire exactly once per request, so
    // the inner call sites are removed in favour of this one.
    metrics::METRICS.record_status(resp.status().as_u16());
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

/// Render a 16-byte W3C trace id as 32 lowercase hex chars — the join key that
/// links an access-log line and a signed audit record to the distributed trace.
fn trace_id_to_hex(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for &b in bytes {
        s.push(HEX_DIGITS[(b >> 4) as usize] as char);
        s.push(HEX_DIGITS[(b & 0xF) as usize] as char);
    }
    s
}

/// Strip the headers only Zion's own pipeline may set: the authenticated identity
/// (`X-Auth-*`, re-injected by the auth gate) and the mesh reputation (`X-Zion-Mesh-Score`,
/// re-injected by the mesh gate). Any inbound copy is a spoof attempt, whoever the peer is.
/// The list lives in [`crate::reserved_headers`].
pub(crate) fn scrub_reserved_identity_headers(headers: &mut hyper::HeaderMap) {
    crate::reserved_headers::scrub(headers, crate::reserved_headers::Asserter::Pipeline);
}

/// Run the whole pipeline for one request. See [`process_request`] for what wraps it.
async fn process_request_inner(
    mut req: Request<ReqBody>,
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

    // ── Resolve real client IP (proxy-aware) ──
    // When trusted_proxies is configured, extract the real client IP from
    // X-Forwarded-For using the rightmost-untrusted-hop algorithm.
    // This prevents rate limit bypass and internal-only gate evasion when
    // Zion is behind ALB/Cloudflare/nginx.
    let client_ip = cfg
        .trusted_proxies
        .resolve_client_ip(remote_addr.ip(), req.headers());
    // SocketAddr wrapper for proxy::proxy_pass*, which extracts only the IP.
    // The port is irrelevant for forwarding headers — using 0 is safe.
    // We intentionally pass the *resolved* client IP (not the TCP peer)
    // so XffMode::Rewrite emits the trusted real-client value rather than
    // the upstream proxy's address.
    let forward_addr = SocketAddr::new(client_ip, 0);

    // ── Pre-routing security gates (zero-cost, before any processing) ──
    // The gates and their ORDER live in `gates::PRE_ROUTING`; the order is pinned
    // by `gates::tests::pre_routing_order` and `gate_order_tests`. The rate
    // limiter runs before the built-in endpoints, so `/healthz` cannot dodge it.
    let ctx = gates::PreCtx {
        cfg: cfg.clone(),
        client_ip,
        remote_addr,
        is_early_data,
    };
    if let Some(resp) = gates::run_pre_routing(&ctx, &state, &mut req).await {
        return Ok(resp);
    }

    // ── Built-in endpoints (no routing, no upstream) ──
    if let Some(resp) = gates::builtin_endpoint(&ctx, &state, &req) {
        return Ok(resp);
    }

    let Some(rule) = route::resolve(&cfg, &req) else {
        return Ok(empty_response(StatusCode::NOT_FOUND));
    };

    // ── CORS (per-route): a preflight or a refused origin answers here ──
    let (cors_allow_origin, cors_answer) = gates::cors_gate(&rule, &req);
    if let Some(resp) = cors_answer {
        return Ok(resp);
    }

    // --- Gate: internal_only ---
    if let Some(resp) = gates::internal_only(&rule, &cfg, client_ip) {
        return Ok(resp);
    }

    // --- Gate: what the path may carry on this route (`;`, `%2F`) ---
    if let Some(resp) = gates::path_shape(&cfg, &rule, &req) {
        return Ok(resp);
    }

    // --- Gate: request headers and cookies the route refuses or strips ---
    if let Some(resp) = rule.headers.apply(req.headers_mut()) {
        return Ok(resp);
    }

    // --- Gate: the route's own restrictions (deny_paths, methods, content_types) ---
    if let Some(resp) = rule.restrictions.as_ref().and_then(|r| r.check(&req)) {
        return Ok(resp);
    }

    // --- Gate: virtual-patch CVE shields (#698), always-on, independent of any WAF profile ---
    if let Some(resp) = gates::virtual_patch(&cfg, &state, remote_addr, &req) {
        return Ok(resp);
    }

    // --- Upstream: health check + latency routing (B-04) ---
    let (dyn_scheme, dyn_authority) = match route::select_upstream(&cfg, &rule) {
        Ok(target) => target,
        Err(resp) => return Ok(resp),
    };

    // --- Gate: Auth (JWT/OIDC) ---
    #[cfg(feature = "auth")]
    if let Some(resp) = gates::bearer_auth(&rule, &mut req) {
        return Ok(resp);
    }

    // --- Gate: WAF ---
    req = match waf_gate::run(&rule, &state, remote_addr, req).await {
        Ok(req) => req,
        Err(resp) => return Ok(resp),
    };

    // --- Gate: the body (max_body_mb without a WAF, require_content_length) ---
    req = match body_gate::run(&rule, remote_addr, req).await {
        Ok(req) => req,
        Err(resp) => return Ok(resp),
    };

    mark_request_for_forwarding(&mut req, &rule);

    // --- Gate: WebSocket upgrade detection ---
    // Check for Upgrade: websocket on ANY route (or explicit websocket mode)
    let is_websocket = rule.mode == config::RouteMode::Websocket
        || req
            .headers()
            .get(hyper::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

    let mut admission = match admit(&cfg, &rule, is_websocket) {
        Ok(admission) => admission,
        Err(resp) => return Ok(resp),
    };

    if is_websocket {
        return websocket_upgrade(
            req,
            &cfg,
            &dyn_scheme,
            &dyn_authority,
            forward_addr,
            &admission.breaker_up,
            admission.breaker_probe.take(),
        )
        .await;
    }

    let trace = telemetry::stamp(&mut req);

    // The root span for this request (#640), built from the trace/span id `stamp()` just
    // decided -- BEFORE `trace` is moved into the tail below, from a borrow that ends as
    // soon as this call returns. Everything from here to the response is one `async move`
    // block so it can be `.instrument()`ed as a whole: a span only covers the future it
    // wraps, and the dispatch/compression/record steps below are what the span is FOR.
    #[cfg(feature = "otel")]
    let span = telemetry::otel_span(&trace);

    let tail = async move {
        let access = telemetry::capture(&cfg, &state, &req);

        // Capture what response compression needs before `req` is moved into the
        // dispatch, and only for a route that asks for it (ADR-0025). Other routes pay
        // nothing.
        let compress_ctx = rule.compress.as_ref().map(|_| {
            (
                req.method().clone(),
                req.headers()
                    .get(hyper::header::ACCEPT_ENCODING)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_owned()),
            )
        });

        // --- Dispatch by mode ---
        let resp = dispatch_by_mode(
            req,
            &state,
            &cfg,
            &rule,
            remote_addr,
            forward_addr,
            &dyn_scheme,
            &dyn_authority,
            admission.breaker_up.clone(),
        )
        .await?;
        let mut resp = finish_response(resp, &rule, admission);

        // Downstream response compression (ADR-0025): off unless the route enabled it
        // and the request/response negotiate a coding.
        if let Some((method, accept_encoding)) = &compress_ctx {
            resp = crate::compress::apply(
                resp,
                rule.compress.as_ref(),
                method,
                accept_encoding.as_deref(),
                cfg.compress_max_concurrent,
            );
        }

        let request_elapsed = request_start.elapsed();
        telemetry::record(
            &state,
            &cfg,
            remote_addr,
            &resp,
            request_elapsed,
            &trace,
            &access,
        );

        // CORS: add Access-Control-Allow-Origin on actual requests
        if let Some(allow) = cors_allow_origin {
            resp.headers_mut()
                .insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
        }

        // X-Request-ID on response (echo from request for client correlation)
        if let Some(rid) = trace.request_id {
            resp.headers_mut().insert("X-Request-ID", rid);
        }

        advertise_alt_svc(resp.headers_mut());

        Ok(resp)
    };

    #[cfg(feature = "otel")]
    {
        use tracing::Instrument;
        tail.instrument(span).await
    }
    #[cfg(not(feature = "otel"))]
    tail.await
}

/// `Alt-Svc`: zion's own HTTP/3 advertisement with `--features http3`, none without it. Either
/// way the origin's is not passed on: it names the origin's alternatives, and a client would take
/// them for zion's own authority. (The cache does not store it for that reason, so a hit and a
/// miss agree.) Every answer that came from an upstream goes through here, the WebSocket
/// handshake's included: an upstream that declines the upgrade answers with its own headers.
fn advertise_alt_svc(headers: &mut hyper::HeaderMap) {
    #[cfg(feature = "http3")]
    headers.insert(hyper::header::ALT_SVC, crate::quic::ALT_SVC_H3.clone());
    #[cfg(not(feature = "http3"))]
    headers.remove(hyper::header::ALT_SVC);
}

/// Mark the request with what the forwarding paths need to know about its route.
fn mark_request_for_forwarding(req: &mut Request<ReqBody>, rule: &ResolvedRoute) {
    // `[upstream.x] preserve_host` (ADR-0024): mark the request once here, where the route
    // is known; the forwarding hygiene every proxy path shares reads the mark.
    if rule.preserve_host {
        req.extensions_mut().insert(proxy::PreserveHost);
    }
    // The upstream's own TLS settings, for the path that opens its own connection (the
    // WebSocket upgrade); the pooled clients get them through `client_spec`.
    if let Some(tls) = &rule.upstream_tls {
        req.extensions_mut()
            .insert(proxy::UpstreamTlsMark(tls.clone()));
    }
    // `[upstream.x] request_timeout_ms`, carried the same way.
    if let Some(t) = rule.request_timeout() {
        req.extensions_mut().insert(t);
    }
}

/// What a request holds while it is being served: the bulkhead slot, the circuit breaker (when the
/// route has one) and the half-open probe token, if this request is the probe.
struct Admission {
    bulkhead_permit: Option<bulkhead::Permit>,
    breaker_up: Option<Arc<health::UpstreamHealth>>,
    breaker_probe: Option<breaker::ProbeToken>,
}

/// Take the bulkhead slot and ask the circuit breaker. `Err` is the 503 that ends the request.
// The Err is the response itself, built once on a rejection: boxing it would add an allocation to
// every shed request for nothing.
#[allow(clippy::result_large_err)]
fn admit(
    cfg: &ResolvedAppConfig,
    rule: &ResolvedRoute,
    is_websocket: bool,
) -> Result<Admission, Response<ZionBody>> {
    // --- Circuit breaker (opt-in, `[upstream.x] circuit_breaker`) ---
    // After auth and the WAF, so an unauthenticated or hostile request can neither learn that
    // the circuit is open nor use up its probe. Resolved from THIS request's config snapshot
    // (`cfg`), so a reload mid-request cannot swap in another generation's breaker. WebSocket
    // handshakes and plain proxied routes are gated here; cached routes consult it inside
    // `handle_static_cache`, where a stale copy can stand in for the upstream.
    // --- Bulkhead (opt-in, `[upstream.x] max_in_flight`) ---
    // Taken before the circuit breaker, so a shed request never counts as an upstream failure or
    // spends a half-open probe, and after auth and the WAF, so a hostile request cannot use up
    // slots. Held until the response body has been sent. Only requests that go to the upstream
    // on every call are counted: cache hits, WebSocket upgrades (long-lived) and static routes
    // are not.
    let mut bulkhead_permit: Option<bulkhead::Permit> = None;
    if rule.max_in_flight > 0
        && !is_websocket
        && rule.cache.is_none()
        && matches!(
            rule.mode,
            config::RouteMode::SseStream | config::RouteMode::Standard
        )
    {
        if let Some(name) = &rule.upstream_name {
            match bulkhead::counter(name).try_acquire(rule.max_in_flight) {
                Some(p) => bulkhead_permit = Some(p),
                None => return Err(upstream_busy_response()),
            }
        }
    }

    let breaker_up = breaker_entry(&cfg, &rule);
    let mut breaker_probe: Option<breaker::ProbeToken> = None;
    if let Some(entry) = &breaker_up {
        let gated_here = is_websocket
            || (rule.cache.is_none()
                && matches!(
                    rule.mode,
                    config::RouteMode::SseStream | config::RouteMode::Standard
                ));
        if gated_here {
            match breaker_admit(entry) {
                Ok(probe) => breaker_probe = probe,
                Err(ms) => return Err(circuit_open_response(ms)),
            }
        }
    }

    Ok(Admission {
        bulkhead_permit,
        breaker_up,
        breaker_probe,
    })
}

/// The WebSocket upgrade: the handshake goes to the upstream and the connection is then tunnelled.
async fn websocket_upgrade(
    mut req: Request<ReqBody>,
    cfg: &ResolvedAppConfig,
    dyn_scheme: &hyper::http::uri::Scheme,
    dyn_authority: &hyper::http::uri::Authority,
    forward_addr: SocketAddr,
    breaker_up: &Option<Arc<health::UpstreamHealth>>,
    breaker_probe: Option<breaker::ProbeToken>,
) -> Result<Response<ZionBody>, hyper::Error> {
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
        cfg.ws_limits,
    )
    .await?;
    if let Some(entry) = &breaker_up {
        breaker_record(entry, resp.status(), breaker_probe);
    }
    inject_security_headers(&mut resp);
    // An upstream that declines the upgrade answers with its own headers (a `400`, a `426`, a
    // `200`), its `Alt-Svc` among them; the `101` is zion's own.
    advertise_alt_svc(resp.headers_mut());
    Ok(resp)
}

/// Hand the request to the handler its route calls for.
#[allow(clippy::too_many_arguments)]
async fn dispatch_by_mode(
    req: Request<ReqBody>,
    state: &Arc<AppState>,
    cfg: &ResolvedAppConfig,
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    forward_addr: SocketAddr,
    dyn_scheme: &hyper::http::uri::Scheme,
    dyn_authority: &hyper::http::uri::Authority,
    breaker_up: Option<Arc<health::UpstreamHealth>>,
) -> Result<Response<ZionBody>, hyper::Error> {
    let resp = if rule.cache.is_some() {
        cached::handle(
            req,
            state.clone(),
            &rule,
            forward_addr,
            &dyn_scheme,
            &dyn_authority,
            cfg.xff_mode,
            breaker_up.clone(),
        )
        .await?
    } else {
        match &rule.mode {
            config::RouteMode::StaticCache => {
                cached::handle(
                    req,
                    state.clone(),
                    &rule,
                    remote_addr,
                    &dyn_scheme,
                    &dyn_authority,
                    cfg.xff_mode,
                    breaker_up.clone(),
                )
                .await?
            }
            config::RouteMode::SseStream => {
                proxy::proxy_pass_stream(
                    &state.client_for(rule.client_spec()),
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
                    &state.client_for(rule.client_spec()),
                    req,
                    &rule.upstream_url,
                    &dyn_scheme,
                    &dyn_authority,
                    &cfg.health_map,
                    rule.load_balancing,
                    Some(forward_addr),
                    "https",
                    cfg.xff_mode,
                )
                .await?
            }
            config::RouteMode::Websocket => {
                proxy::proxy_pass(
                    &state.client_for(rule.client_spec()),
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
                    crate::static_files::serve(
                        dir,
                        tail,
                        rule.spa_fallback,
                        rule.precompressed,
                        req.method(),
                        req.headers(),
                        // The client the request resolves to (behind a trusted proxy, the one
                        // the proxy names) holds the response's share of the static budget.
                        crate::static_budget::Client {
                            ip: forward_addr.ip(),
                            via_trusted_proxy: cfg
                                .trusted_proxies
                                .is_trusted(&remote_addr.ip().to_canonical()),
                        },
                    )
                    .await
                }
                // Unreachable (resolve_route requires serve_dir) — fail CLOSED
                // rather than serve the process CWD if a future refactor slips.
                None => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
            },
        }
    };
    Ok(resp)
}

/// Everything done to a response before it leaves: the bulkhead slot rides with the body, the
/// breaker hears what the upstream answered, and the headers Zion owns are set.
fn finish_response(
    mut resp: Response<ZionBody>,
    rule: &ResolvedRoute,
    admission: Admission,
) -> Response<ZionBody> {
    let Admission {
        mut bulkhead_permit,
        breaker_up,
        mut breaker_probe,
    } = admission;

    if let Some(permit) = bulkhead_permit.take() {
        resp = bulkhead::attach(resp, permit);
    }

    // Cached routes record inside `handle_static_cache`, where the origin is actually asked.
    if rule.cache.is_none()
        && matches!(
            rule.mode,
            config::RouteMode::SseStream | config::RouteMode::Standard
        )
    {
        if let Some(entry) = &breaker_up {
            breaker_record(entry, resp.status(), breaker_probe.take());
        }
    }

    // `Surrogate-Key` is an origin→cache instruction, not for clients.
    resp.headers_mut().remove("surrogate-key");

    // Inject security headers on all responses
    inject_security_headers(&mut resp);

    // Per-route CSP: if the route has a csp value, inject it.
    // Otherwise, upstream CSP is passed through unmodified.
    if let Some(ref csp_val) = rule.csp {
        resp.headers_mut()
            .insert(hyper::header::CONTENT_SECURITY_POLICY, csp_val.clone());
    }

    resp
}

/// The health entry whose circuit breaker guards this route, if it has one: the route's
/// upstream has a single endpoint and a `circuit_breaker` is configured on it.
fn breaker_entry(
    cfg: &ResolvedAppConfig,
    rule: &ResolvedRoute,
) -> Option<Arc<health::UpstreamHealth>> {
    if rule.upstream_url.len() != 1 || rule.mode == config::RouteMode::Static {
        return None;
    }
    cfg.health_map
        .get(&rule.upstream_url[0])
        .filter(|h| h.breaker.is_configured())
        .cloned()
}

/// Does a circuit breaker guard this route's upstream? The `:80` ACME fallback forwards on its
/// own, without the admission stage, so such a route is served through the HTTPS pipeline.
pub(crate) fn has_circuit_breaker(cfg: &ResolvedAppConfig, rule: &ResolvedRoute) -> bool {
    breaker_entry(cfg, rule).is_some()
}

/// The upstream is at `max_in_flight`: refuse at once rather than queue.
fn upstream_busy_response() -> Response<ZionBody> {
    let mut resp = text_response(StatusCode::SERVICE_UNAVAILABLE, "upstream busy");
    resp.headers_mut().insert(
        hyper::header::RETRY_AFTER,
        hyper::header::HeaderValue::from_static("1"),
    );
    resp.headers_mut().insert(
        "X-Zion-Bulkhead",
        hyper::header::HeaderValue::from_static("full"),
    );
    resp
}

/// What an open circuit answers: 503 at once, with `Retry-After`.
fn circuit_open_response(retry_after_ms: u64) -> Response<ZionBody> {
    let mut resp = text_response(StatusCode::SERVICE_UNAVAILABLE, "upstream circuit open");
    let secs = retry_after_ms.div_ceil(1000).max(1);
    if let Ok(v) = hyper::header::HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut().insert(hyper::header::RETRY_AFTER, v);
    }
    resp.headers_mut().insert(
        "X-Zion-Circuit",
        hyper::header::HeaderValue::from_static("open"),
    );
    resp
}

/// Ask the circuit whether a request may go to the upstream. `Err` is the number of
/// milliseconds to advertise in `Retry-After` for the 503 ([`circuit_open_response`]); `Ok`
/// carries the probe token when this request is the half-open probe (hand it back to
/// [`breaker_record`]).
fn breaker_admit(entry: &health::UpstreamHealth) -> Result<Option<breaker::ProbeToken>, u64> {
    match entry.breaker.check(breaker::now_ms()) {
        breaker::Check::Allow => Ok(None),
        breaker::Check::Probe(t) => Ok(Some(t)),
        breaker::Check::Reject { retry_after_ms } => Err(retry_after_ms),
    }
}

/// Report what a request that reached the upstream got back.
fn breaker_record(
    entry: &health::UpstreamHealth,
    status: StatusCode,
    probe: Option<breaker::ProbeToken>,
) {
    entry.breaker.record(
        !breaker::is_failure(status.as_u16()),
        breaker::now_ms(),
        probe,
    );
}

/// The paths a response names in `Location` / `Content-Location` that are on the same
/// origin as the request (RFC 9111 §4.4): a relative reference, or an absolute one
/// whose authority is the request's own host. Anything pointing elsewhere is ignored,
/// so a response can only ever evict URIs in its own origin's space.
fn named_same_origin_paths(headers: &hyper::HeaderMap, request_host: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for name in [hyper::header::LOCATION, hyper::header::CONTENT_LOCATION] {
        for v in headers.get_all(&name) {
            let Some(uri) = v.to_str().ok().and_then(|s| s.parse::<hyper::Uri>().ok()) else {
                continue;
            };
            let same_origin = match uri.authority() {
                None => true,
                Some(a) => request_host.is_some_and(|h| a.as_str().eq_ignore_ascii_case(h)),
            };
            if same_origin && !uri.path().is_empty() {
                out.push(uri.path().to_string());
            }
        }
    }
    out
}

/// The key a request's cache entry lives under: its primary key, or — when that key's
/// responses are known to vary — the secondary key for this request's varied headers.
/// `None` when a varied header value is too long to key on.
fn lookup_key(state: &AppState, primary: &str, headers: &hyper::HeaderMap) -> Option<String> {
    filed_key(state, primary, headers).map(|(key, _)| key)
}

/// [`lookup_key`], with the `Vary` rule the key was built from: `None` when the primary key does
/// not vary, and the key is the primary key itself. An entry found under that key was filed under
/// that rule: the key holds the rule's names ([`vary::variant_key`]), and an entry is only ever
/// stored or renewed under a key built from the `Vary` of the response it holds. This is the rule
/// an answer that would renew or replace the entry is held to ([`same_vary_shape`]), and not the
/// one [`cache::StaticCache::vary`] holds for the primary key when the origin answers: another
/// request may have filed a response under a new `Vary` in between (a request that missed while
/// this one waited on a fetch, or while its revalidation was on its way to the origin).
fn filed_key(
    state: &AppState,
    primary: &str,
    headers: &hyper::HeaderMap,
) -> Option<(String, Option<Arc<vary::VaryRule>>)> {
    match state.static_cache.vary.get(primary) {
        Some(rule) => Some((
            vary::variant_key(primary, &rule.names, headers)?,
            Some(rule),
        )),
        None => Some((primary.to_string(), None)),
    }
}

/// Response headers have the `Vary` of the entry they would renew or replace: `filed` is the rule
/// that entry was found under ([`filed_key`], read when the request looked the entry up; `None`:
/// the key does not vary).
/// True when neither varies, or both vary on the same request headers ([`vary::policy`] lists them
/// lower-cased, sorted and once each, `Accept-Encoding` aside). Any other `Vary` (a name more or
/// less, `*`, a credential header) says the origin now chooses the response by other request
/// headers than the entry's key holds: renewed under that key, the answer one client's request
/// selected, its per-user headers with it, would be served to every client the key matches. One
/// test for the three answers that update an entry: the background refresh's `200` and `304`
/// ([`run_swr_refresh`]) and the foreground revalidation's `304` ([`revalidated`]).
fn same_vary_shape(headers: &hyper::HeaderMap, filed: Option<&[String]>) -> bool {
    match (vary::policy(headers), filed) {
        (vary::VaryPolicy::None, None) => true,
        (vary::VaryPolicy::Keyed(names), Some(filed)) => names == filed,
        _ => false,
    }
}

/// The lines of field `name` among an entry's stored headers, as the header readers take them.
fn stored_lines(meta: &cache::CachedMeta, name: hyper::header::HeaderName) -> hyper::HeaderMap {
    meta.headers
        .iter()
        .filter(|(stored, _)| *stored == name)
        .cloned()
        .collect()
}

/// Everything a background stale-while-revalidate refresh needs, owned so it can
/// outlive the request that triggered it.
struct SwrRefresh {
    state: Arc<AppState>,
    key: Arc<str>,
    /// `key` is a shared identity entry (#484): an encoded refresh must not overwrite it.
    identity_entry: bool,
    /// The `Vary` rule `key` was built from when the request found the entry ([`filed_key`];
    /// `None`: it does not vary): the rule the entry was filed under, which the refresh's answer
    /// is held to. Not read again when the origin answers: a `200` that another request filed
    /// under a new `Vary` in between made a `304` with that `Vary` renew this entry, under a key
    /// the origin no longer selects by, with the headers of the client the refresh went for.
    filed: Option<Arc<vary::VaryRule>>,
    stale: cache::CacheHit,
    request: Request<ReqBody>,
    /// The request that found the entry stale carried `Authorization`. The refresh does not
    /// send it ([`swr_request`]), but the origin may still answer for that client: the refresh
    /// has the same target and the client's other headers (an application token in a header of
    /// its own, the client's address in `X-Forwarded-For`). So the answer is held to the
    /// RFC 9111 §3.5 opt-in as the foreground one is.
    req_authenticated: bool,
    /// The upstream's HTTP client (connect deadline, HTTP/1-only, keepalive).
    client_spec: crate::proxy::ClientSpec,
    scheme: hyper::http::uri::Scheme,
    authority: hyper::http::uri::Authority,
    remote_addr: SocketAddr,
    xff_mode: proxy::XffMode,
    cache_ttl: u64,
    cache_max: usize,
    max_object: usize,
    /// `tag_epoch` when the refresh was scheduled (see `StaticCache::insert_tagged`).
    tag_epoch: u64,
    /// The upstream's circuit breaker, if it has one.
    breaker: Option<Arc<health::UpstreamHealth>>,
}

/// A request header a background refresh does not send ([`swr_request`]): the caller's
/// credentials, its preconditions and `Range` (the stored validators are sent instead), the
/// framing of a body the refresh does not have, and what zion asserts about the caller (the
/// [`Asserter::Pipeline`](crate::reserved_headers::Asserter::Pipeline) and
/// [`Asserter::Transport`](crate::reserved_headers::Asserter::Transport) reserved headers).
/// `name` is lower-case, as hyper and [`vary::policy`] keep names. One list, so that what an
/// entry may be refreshed without ([`refresh_sends_what_it_varies_on`]) is what the refresh
/// leaves out.
fn swr_drops(name: &str) -> bool {
    use crate::reserved_headers::{Asserter, RESERVED_HEADERS};
    matches!(
        name,
        "authorization"
            | "cookie"
            | "proxy-authorization"
            | "if-none-match"
            | "if-modified-since"
            | "if-match"
            | "if-unmodified-since"
            | "if-range"
            | "range"
            | "content-length"
            | "transfer-encoding"
    ) || RESERVED_HEADERS.iter().any(|(reserved, asserter)| {
        matches!(asserter, Asserter::Pipeline | Asserter::Transport) && *reserved == name
    })
}

/// A background refresh of an entry filed under `filed` (the rule it was found under,
/// [`filed_key`]; `None`: it does not vary) reaches the origin with every header that entry is
/// keyed on. Not when the entry is a variant whose `Vary` names a header the refresh leaves out
/// ([`swr_drops`]): the origin would answer the refresh for a request without it (no
/// `X-Auth-Subject`, no TLS fingerprint), and that other representation would be stored under this
/// variant's key. Such an entry is revalidated in the foreground instead, with the client's own
/// request. The rule is the one the refresh's answer is then held to ([`SwrRefresh::filed`]), not
/// one read again: a rule read again could be another, with no such header in it, while the
/// answer is matched against the one with it.
fn refresh_sends_what_it_varies_on(filed: Option<&vary::VaryRule>) -> bool {
    filed.is_none_or(|rule| !rule.names.iter().any(|name| swr_drops(name)))
}

/// The request a background refresh sends: the same target and content
/// negotiation as the one that found the entry stale, but NOT the caller's
/// credentials. The refresh is on behalf of the cache, not of that client, so
/// `Authorization` / `Cookie` / `Proxy-Authorization` and any conditional or range
/// header are dropped (the stored validators are added when it is sent), and so is what zion
/// itself asserts about the caller: the identity the auth gate established (`X-Auth-Subject`,
/// `X-Auth-Email`), the mesh score, the client certificate (`X-Client-Cert-*`) and the TLS
/// fingerprint (`X-Client-TLS-*`). With them the origin answered the refresh for that user,
/// without `Authorization`, and a per-user answer could become the shared entry. The list is
/// [`swr_drops`].
fn swr_request(req: &Request<ReqBody>) -> Request<ReqBody> {
    let mut out = Request::builder()
        .method(hyper::Method::GET)
        .uri(req.uri().clone())
        .version(req.version())
        .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .expect("a GET with a copied URI builds");
    // The refresh reaches the upstream with the same Host as the request it refreshes.
    if req.extensions().get::<proxy::PreserveHost>().is_some() {
        out.extensions_mut().insert(proxy::PreserveHost);
    }
    // ... and waits for the origin as long as that request would have.
    if let Some(t) = req.extensions().get::<proxy::RequestTimeout>() {
        out.extensions_mut().insert(*t);
    }
    for (name, value) in req.headers() {
        if !swr_drops(name.as_str()) {
            out.headers_mut().append(name.clone(), value.clone());
        }
    }
    out
}

/// Start a background refresh of a stale entry, at most one per key (the
/// singleflight map) and at most [`MAX_SWR_REFRESHES`] at a time. When either
/// limit says no, nothing is started and the caller still serves the stale copy.
fn spawn_swr_refresh(job: SwrRefresh) {
    use std::sync::atomic::Ordering::Relaxed;
    // An open (or half-open) circuit means the upstream is not to be contacted, background
    // refresh included. A refresh only LOOKS at the circuit: it never takes the half-open
    // probe slot, which belongs to a foreground request that can report its outcome.
    if let Some(entry) = &job.breaker {
        if entry.breaker.is_open() {
            metrics::METRICS
                .cache_swr_refresh_skipped
                .fetch_add(1, Relaxed);
            return;
        }
    }
    let Some(permit) = SWR_BUDGET.try_acquire() else {
        metrics::METRICS
            .cache_swr_refresh_skipped
            .fetch_add(1, Relaxed);
        return;
    };
    let (tx, inserted) = job
        .state
        .inflight
        .get_or_insert_with(job.key.clone(), || tokio::sync::watch::channel(false).0);
    if !inserted {
        return; // a fetch or refresh for this key is already running
    }
    tokio::spawn(async move {
        let _permit = permit;
        // The whole refresh (headers and body) gets at least the default; an upstream given
        // a longer `request_timeout_ms` is not cut short here before it could answer.
        let budget = job
            .request
            .extensions()
            .get::<proxy::RequestTimeout>()
            .map_or(SWR_REFRESH_TIMEOUT, |t| t.0.max(SWR_REFRESH_TIMEOUT));
        let outcome = tokio::time::timeout(budget, run_swr_refresh(&job))
            .await
            .unwrap_or(Refresh::Failed);
        // Marked before the registration goes: a request that finds no refresh running finds
        // the mark, and revalidates in the foreground instead of starting the same refresh again.
        if outcome == Refresh::Refused {
            job.state.static_cache.refuse_refresh(&job.key, &job.stale);
        }
        let ok = outcome == Refresh::Renewed;
        if ok {
            metrics::METRICS.cache_swr_refreshes.fetch_add(1, Relaxed);
        } else {
            metrics::METRICS
                .cache_swr_refresh_failures
                .fetch_add(1, Relaxed);
        }
        // Published before the registration goes, and with `send_replace` (see
        // `Fetching::stored`); when the refresh failed the sender is dropped unpublished
        // and waiters fetch for themselves.
        if ok {
            tx.send_replace(true);
        }
        job.state.inflight.remove(&job.key);
    });
}

/// How a background refresh ended ([`run_swr_refresh`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refresh {
    /// The entry was renewed by a `304` or replaced by a `200`.
    Renewed,
    /// The origin was not reached, gave no answer in time or not the whole body, or answered with
    /// a 5xx, a `429` or a `408`; or a tag purge ran meanwhile, and what becomes of the entry is
    /// the purge's to say. The entry keeps its stale-while-revalidate window: the origin is failing
    /// or shedding load for every client, and the stale copy served at once is what the window, and
    /// stale-if-error, are for.
    Failed,
    /// The origin answered, and the answer cannot renew or replace the entry: another status (a
    /// `401` or `403` to a refresh without what zion asserts about the client, [`swr_drops`]), a
    /// `304` that could not have been stored itself (a `Set-Cookie` on a refresh that sent no
    /// `Cookie`, no §3.5 opt-in after an `Authorization` request) or over the header bound, a `200`
    /// that may not be stored. The next background refresh would be sent the same way and get the
    /// same answer: the entry is marked ([`cache::StaticCache::refuse_refresh`]) and the next
    /// request revalidates it in the foreground with its own headers. Left in its window, it was
    /// served stale until the window closed, whatever the origin had since, and each request after
    /// the previous refresh ended started another one.
    Refused,
}

/// One refresh: a conditional GET with the stored validators. A `304` revives the
/// stored body; a cacheable `200` replaces it. An answer whose `Vary` is not the one the entry
/// was filed under does neither, and takes the stale entry out ([`same_vary_shape`],
/// [`Revalidation::vary_changed`]). Any other answer that does neither ends the entry's
/// stale-while-revalidate window ([`Refresh::Refused`]); a failure to get one, a 5xx, a `429` or
/// a `408` leaves it as it is ([`Refresh::Failed`]): it is no longer served stale once outside its
/// window.
async fn run_swr_refresh(job: &SwrRefresh) -> Refresh {
    let mut req = swr_request(&job.request);
    add_conditional_headers(req.headers_mut(), &job.stale.meta);
    let resp = match proxy::proxy_pass(
        &job.state.client_for(job.client_spec.clone()),
        req,
        &job.scheme,
        &job.authority,
        Some(job.remote_addr),
        "https",
        job.xff_mode,
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            if let Some(entry) = &job.breaker {
                entry.breaker.record(false, breaker::now_ms(), None);
            }
            return Refresh::Failed;
        }
    };
    if let Some(entry) = &job.breaker {
        // No probe token: a refresh counts toward the failure window while the circuit is
        // closed, and is ignored when it is not.
        breaker_record(entry, resp.status(), None);
    }
    // `proxy_pass` answers an origin it could not reach, or that did not answer in time, with a
    // 5xx of its own. A `429` or a `408` is the origin, or a rate limiter in front of it, shedding
    // load or giving up on this one request: no answer about the entry, and the next refresh can
    // get another. Taken for a refusal, it ended the window, and every request for the entry went
    // to the origin in the foreground, at the rate the clients came, while it asked for fewer.
    if resp.status().is_server_error()
        || matches!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS | StatusCode::REQUEST_TIMEOUT
        )
    {
        return Refresh::Failed;
    }
    // It refreshes ONE entry, filed under the `Vary` rule it was found under (none when it does
    // not vary): an answer with another `Vary` belongs to other keys.
    let filed = job.filed.as_ref().map(|rule| rule.names.as_slice());

    if resp.status() == StatusCode::NOT_MODIFIED {
        // The 304's headers update the stored ones (RFC 9111 §4.3.4). A result too large to
        // keep, or a 304 that could not have been stored itself, leaves the entry as it is. It
        // is judged with the triggering request's `Authorization` (see `SwrRefresh`). One whose
        // `Vary` is not the entry's takes the entry out (see `Revalidation::vary_changed`).
        let rv = revalidated(
            &job.stale.meta,
            resp.headers(),
            job.req_authenticated,
            job.cache_ttl,
            filed,
        );
        // Counted only when the bound is what kept it out (see `Revalidation::too_large`).
        if rv.too_large() {
            job.state.static_cache.count_too_large();
        }
        if rv.vary_changed {
            job.state
                .static_cache
                .remove_unchanged(&job.key, &job.stale);
        }
        if !rv.renews() {
            return Refresh::Refused;
        }
        // Not revived if a tag purge ran since this refresh was scheduled (it may have removed
        // the very entry being revalidated).
        if !job.state.static_cache.refresh_checked(
            &job.key,
            job.stale.body.clone(),
            rv.meta,
            rv.ttl,
            rv.initial_age,
            job.cache_max,
            job.tag_epoch,
        ) {
            return Refresh::Failed;
        }
        metrics::METRICS
            .cache_revalidations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Refresh::Renewed;
    }
    if resp.status() != StatusCode::OK {
        return Refresh::Refused;
    }

    let (parts, body) = resp.into_parts();
    // If the origin's Vary no longer matches what the entry was keyed on, the new body belongs
    // to a different key: it is not stored, and the stale entry, which the origin no longer
    // selects by that key, is taken out as after such a 304, so that the next request misses and
    // its `200` files the response under the new `Vary`. Whether the body could be stored at all
    // does not change that.
    if !same_vary_shape(&parts.headers, filed) {
        job.state
            .static_cache
            .remove_unchanged(&job.key, &job.stale);
        return Refresh::Refused;
    }
    let initial_age = upstream_age(&parts.headers);
    let ttl = origin_freshness(&parts.headers)
        .map(|o| o.min(job.cache_ttl))
        .unwrap_or(job.cache_ttl);
    // Held to the §3.5 opt-in when the triggering request carried `Authorization`.
    if !is_shared_cacheable(job.req_authenticated, &parts.headers, ttl, initial_age) {
        return Refresh::Refused;
    }
    // A shared identity entry is found by every Accept-Encoding: an encoded body must
    // never replace it (it would reach clients that did not accept that encoding).
    if job.identity_entry && !shareable_identity(&parts.headers) {
        return Refresh::Refused;
    }
    // Headers too large to keep: not stored (see `cached_meta`).
    let Some(meta) = cached_meta(parts.status, &parts.headers) else {
        job.state.static_cache.count_too_large();
        return Refresh::Refused;
    };
    let collected = match http_body_util::Limited::new(body, job.max_object)
        .collect()
        .await
    {
        Ok(collected) => collected,
        // A body over the profile's `max_object_mb` is an answer that cannot be stored; one the
        // origin did not finish sending is a failure to get an answer.
        Err(e) if e.is::<http_body_util::LengthLimitError>() => return Refresh::Refused,
        Err(_) => return Refresh::Failed,
    };
    // The refreshed response may carry new tags; one that cannot be tracked is not stored.
    let Ok(tags) = cache::surrogate_keys(&parts.headers) else {
        return Refresh::Refused;
    };
    match job.state.static_cache.insert_tagged(
        &job.key,
        collected.to_bytes(),
        meta,
        ttl,
        initial_age,
        job.cache_max,
        &tags,
        job.tag_epoch,
    ) {
        cache::TagStore::Stored => Refresh::Renewed,
        cache::TagStore::PurgedMeanwhile => Refresh::Failed,
        // The entry under the key went with it (`insert_tagged`): nothing is left to mark.
        cache::TagStore::IndexFull => {
            metrics::METRICS
                .cache_tag_uncached
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Refresh::Refused
        }
    }
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
/// of being ignored in favour of the profile's blanket TTL. Every `Cache-Control` line counts
/// ([`CacheControl`]): `public` on one line and `max-age=0` on the next is a lifetime of 0.
fn origin_freshness(headers: &hyper::HeaderMap) -> Option<u64> {
    let cc = CacheControl::of(headers);
    // s-maxage wins for shared caches; only then fall back to max-age.
    cc.seconds("s-maxage").or_else(|| cc.seconds("max-age"))
}

/// Longest `stale-while-revalidate` window honoured, whatever the origin asks for.
const MAX_SWR_SECS: u64 = 86_400;

/// Most stale-while-revalidate refreshes running at once, across all keys. One
/// refresh per key is already guaranteed by the singleflight map; this bounds the
/// total so a burst of distinct expiring keys cannot spawn unbounded origin traffic.
const MAX_SWR_REFRESHES: usize = 64;

/// How long a background refresh may run before it is abandoned (longer when the upstream's
/// `request_timeout_ms` is).
const SWR_REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A bounded budget of concurrent refreshes.
struct SwrBudget {
    active: std::sync::atomic::AtomicUsize,
    max: usize,
}

static SWR_BUDGET: SwrBudget = SwrBudget {
    active: std::sync::atomic::AtomicUsize::new(0),
    max: MAX_SWR_REFRESHES,
};

/// A slot in a [`SwrBudget`]; released on drop (also on panic/abort).
struct SwrPermit(&'static SwrBudget);

impl SwrBudget {
    fn try_acquire(&'static self) -> Option<SwrPermit> {
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        let mut cur = self.active.load(Acquire);
        loop {
            if cur >= self.max {
                return None;
            }
            match self
                .active
                .compare_exchange_weak(cur, cur + 1, AcqRel, Acquire)
            {
                Ok(_) => return Some(SwrPermit(self)),
                Err(seen) => cur = seen,
            }
        }
    }
}

impl Drop for SwrPermit {
    fn drop(&mut self) {
        self.0
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// True when the response's `Cache-Control` forbids serving it stale without
/// validation: `must-revalidate`, `proxy-revalidate`, or `s-maxage` (which carries
/// the proxy-revalidate semantics for a shared cache, RFC 9111 §5.2.2.10). Matches
/// whole directive names, not substrings.
fn forbids_stale(headers: &hyper::HeaderMap) -> bool {
    CacheControl::of(headers)
        .directives()
        .any(|d| d.is("must-revalidate") || d.is("proxy-revalidate") || d.is("s-maxage"))
}

/// `stale-while-revalidate=N` (RFC 5861 §3) from a response's `Cache-Control`, every line of
/// it, in seconds, capped at [`MAX_SWR_SECS`]. `0` when absent or unparsable.
fn origin_swr(headers: &hyper::HeaderMap) -> u64 {
    CacheControl::of(headers)
        .seconds("stale-while-revalidate")
        .map_or(0, |secs| secs.min(MAX_SWR_SECS))
}

/// Test hook: `origin_swr` over a bare `Cache-Control` value.
#[cfg(test)]
pub(crate) fn origin_swr_for_tests(cache_control: &str) -> u64 {
    let mut h = hyper::HeaderMap::new();
    h.insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_str(cache_control).unwrap(),
    );
    origin_swr(&h)
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

    // A response that sets a cookie starts or alters a session: its body and its cookie are
    // for that client, so it is never stored in the shared cache (what nginx and Varnish do
    // by default). The client that triggered it still gets the response, cookie included.
    if resp_headers.contains_key(hyper::header::SET_COOKIE) {
        return false;
    }

    // Every `Cache-Control` line: `max-age=300` on one and `private` on the next is private.
    let cc = CacheControl::of(resp_headers);

    // §3.2 / §5.2.2: origin forbids shared storage. Matched anywhere in the list, not only as
    // a whole directive, so that an unusual spelling still refuses (as nginx and Varnish do).
    if cc.mentions("private") || cc.mentions("no-store") || cc.mentions("no-cache") {
        return false;
    }

    // §3.5: a response to an authenticated request is storable in a shared
    // cache ONLY when the origin explicitly allows it, with a whole directive: an extension
    // whose name merely contains `public` is not an opt-in.
    if req_authenticated && !(cc.has("public") || cc.has("s-maxage") || cc.has("must-revalidate")) {
        return false;
    }

    // §4.1: a response that varies is stored under a secondary key built from the
    // request headers it names (see `vary`). Only `Vary: *` and varied credential
    // headers (per-user responses) remain unstorable.
    !matches!(vary::policy(resp_headers), vary::VaryPolicy::Uncacheable)
}

/// The client refuses an unencoded body (RFC 9110 §12.5.3): `identity;q=0`, or `*;q=0`
/// without an explicit `identity` entry.
fn refuses_identity(headers: &hyper::HeaderMap) -> bool {
    let raw = headers
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let q_of = |tok: &str| -> Option<(String, f32)> {
        let mut it = tok.split(';');
        let name = it.next()?.trim().to_string();
        if name.is_empty() {
            return None;
        }
        let q = it
            .find_map(|p| p.trim().strip_prefix("q=").map(str::to_string))
            .and_then(|q| q.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        Some((name, q))
    };
    let codings: Vec<(String, f32)> = raw.split(',').filter_map(q_of).collect();
    match codings.iter().find(|(n, _)| n == "identity") {
        Some((_, q)) => *q <= 0.0,
        None => codings.iter().any(|(n, q)| n == "*" && *q <= 0.0),
    }
}

/// The response is the same bytes for every `Accept-Encoding`: no content coding, and the
/// origin did not say it chose the response by `Accept-Encoding` (a `Vary` naming it, or `*`).
fn shareable_identity(headers: &hyper::HeaderMap) -> bool {
    let varies_on_ae = headers
        .get_all(hyper::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| {
            let t = t.trim();
            t == "*" || t.eq_ignore_ascii_case("accept-encoding")
        });
    !varies_on_ae && !is_encoded(headers)
}

/// The response body is encoded (`Content-Encoding` other than `identity`).
fn is_encoded(headers: &hyper::HeaderMap) -> bool {
    headers
        .get_all(hyper::header::CONTENT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|c| {
            let c = c.trim();
            !c.is_empty() && !c.eq_ignore_ascii_case("identity")
        })
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

/// Which of an entry's stored origin headers an answer from the cache replays.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Replay {
    /// All of them: an answer with the stored body or a slice of it.
    All,
    /// A `304` to a client's conditional request (RFC 9110 §15.4.5): of what a `200` would
    /// carry, the fields that guide the client's cache, `Cache-Control`, `Content-Location`,
    /// `Date`, `Expires` and `Vary` (`ETag` and `Last-Modified` come from their own fields; a
    /// `Date` is set when the answer is sent if the origin sent none). Not the representation's
    /// other metadata: the client keeps what it stored with the `200` (RFC 9111 §4.3.4).
    NotModified,
}

/// The headers a `304` from the cache replays, see [`Replay::NotModified`].
const NOT_MODIFIED_REPLAYS: [hyper::header::HeaderName; 5] = [
    hyper::header::CACHE_CONTROL,
    hyper::header::CONTENT_LOCATION,
    hyper::header::DATE,
    hyper::header::EXPIRES,
    hyper::header::VARY,
];

const X_ZION_CACHE: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("x-zion-cache");

/// Digests computed over a message's content, the whole stored body: a `206` or `416` from the
/// cache does not carry them (see [`ranged_hit_response`]).
const WHOLE_CONTENT_DIGESTS: [hyper::header::HeaderName; 2] = [
    hyper::header::HeaderName::from_static("content-digest"),
    hyper::header::HeaderName::from_static("content-md5"),
];

/// An answer from a cache entry: the origin's end-to-end headers the entry kept
/// ([`cache::CachedMeta::headers`]), so that it carries what the miss carried, then the ones
/// this answer sets, each replacing a stored one of the same name:
///
/// - `Cache-Control`: the origin's, as on the miss; when the origin sent none, the entry's
///   lifetime as `public, max-age=N` (`immutable` for a year), which is what the miss carried;
/// - `X-Zion-Cache: <disposition>`, and `Age` (RFC 9111 §4.2.3: since the origin made it, the
///   upstream `Age` included), so a downstream cache does not restart the clock; the origin's
///   `Date` is one of the stored headers, so `Expires` minus `Date` stays the lifetime it gave;
/// - `Content-Type`, `Content-Encoding` (not on a `304`), `ETag` and `Last-Modified`, as the
///   origin sent them.
///
/// The response pipeline then does to it what it does to the miss (security headers, the
/// route's CSP, CORS, compression), so a hit and a miss leave with the same set of headers.
fn from_cache(
    hit: &cache::CacheHit,
    status: StatusCode,
    disposition: &'static str,
    replay: Replay,
    body: Bytes,
) -> Response<ZionBody> {
    use hyper::header;
    let meta = &hit.meta;
    let mut resp = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.reserve(meta.headers.len() + 8);
    for (name, value) in &meta.headers {
        if replay == Replay::All || NOT_MODIFIED_REPLAYS.contains(name) {
            h.append(name.clone(), value.clone());
        }
    }
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(
            header::CACHE_CONTROL,
            profile_cache_control(hit.max_age_secs),
        );
    }
    h.insert(X_ZION_CACHE, header::HeaderValue::from_static(disposition));
    h.insert(header::AGE, header::HeaderValue::from(hit.age_secs));
    if replay == Replay::All {
        if let Some(ct) = &meta.content_type {
            h.insert(header::CONTENT_TYPE, ct.clone());
        }
        if let Some(ce) = &meta.content_encoding {
            h.insert(header::CONTENT_ENCODING, ce.clone());
        }
    }
    // The validators the client echoes back (If-None-Match / If-Range), as the origin sent them.
    if let Some(etag) = &meta.etag {
        h.insert(header::ETAG, etag.clone());
    }
    if let Some(lm) = &meta.last_modified {
        h.insert(header::LAST_MODIFIED, lm.clone());
    }
    resp
}

/// Serve a stored body with the given `X-Zion-Cache` disposition. `HIT` = a
/// fresh hit; `REVALIDATED` = a stale entry the origin confirmed with a 304
/// (RFC 9111 §4.3), served without re-downloading; `STALE` = stale served on an
/// origin error (§4.2.4 stale-if-error); `STALE-WHILE-REVALIDATE` = stale served
/// while a refresh runs (RFC 5861). Headers: see [`from_cache`].
fn cache_response(mut hit: cache::CacheHit, disposition: &'static str) -> Response<ZionBody> {
    let body = std::mem::take(&mut hit.body);
    let mut resp = from_cache(&hit, hit.meta.status, disposition, Replay::All, body);
    // A fresh hit answers `Range` itself (see `ranged_hit_response`): say so.
    if disposition == "HIT" && hit.meta.status == StatusCode::OK {
        resp.headers_mut().insert(
            hyper::header::ACCEPT_RANGES,
            hyper::header::HeaderValue::from_static("bytes"),
        );
    }
    resp
}

/// Answer a `Range` request from a fresh cached `200` (RFC 9110 §14): one satisfiable byte range
/// becomes a `206` with a zero-copy slice of the stored body, an unsatisfiable one a `416`.
/// `None` means "serve the whole representation" — no `Range`, a unit or form we do not handle
/// (multi-range, malformed), an `If-Range` that does not match, a non-`GET`, or a stored status
/// other than 200. Preconditions (`If-None-Match`/`If-Modified-Since` → 304) run before this.
fn ranged_hit_response(
    hit: &cache::CacheHit,
    method: &hyper::Method,
    headers: &hyper::HeaderMap,
) -> Option<Response<ZionBody>> {
    use crate::static_files::{self, RangeOutcome};
    if *method != hyper::Method::GET || hit.meta.status != StatusCode::OK {
        return None;
    }
    // exactly one `Range` field: several lines are a combined (multi-range or malformed) request,
    // and `get` would only look at the first
    if headers.get_all(hyper::header::RANGE).iter().count() != 1 {
        return None;
    }
    if !static_files::if_range_allows_stored(
        headers,
        hit.meta.etag.as_ref(),
        hit.meta.last_modified.as_ref(),
    ) {
        return None;
    }
    let total = hit.body.len() as u64;
    let (status, content_range, body) =
        match static_files::parse_range(headers.get(hyper::header::RANGE), total) {
            RangeOutcome::Full => return None,
            RangeOutcome::Unsatisfiable => (
                StatusCode::RANGE_NOT_SATISFIABLE,
                format!("bytes */{total}"),
                Bytes::new(),
            ),
            RangeOutcome::Satisfiable(start, end) => (
                StatusCode::PARTIAL_CONTENT,
                format!("bytes {start}-{end}/{total}"),
                hit.body.slice(start as usize..=end as usize),
            ),
        };
    // The stored origin headers, as on a whole hit (see `from_cache`), but for the digests of
    // the whole content: they do not describe a part of it (RFC 9530 §2; `Content-MD5`, RFC
    // 1864), and a client that checks one would reject the part. `Repr-Digest`, over the
    // representation, stays.
    let mut resp = from_cache(hit, status, "HIT", Replay::All, body);
    let h = resp.headers_mut();
    for whole_content in WHOLE_CONTENT_DIGESTS {
        h.remove(whole_content);
    }
    h.insert(
        hyper::header::ACCEPT_RANGES,
        hyper::header::HeaderValue::from_static("bytes"),
    );
    // `bytes a-b/n` and `bytes */n` are digits, `-`, `/` and `*`: always a valid value.
    if let Ok(range) = hyper::header::HeaderValue::from_str(&content_range) {
        h.insert(hyper::header::CONTENT_RANGE, range);
    }
    Some(resp)
}

#[inline]
fn cache_hit_response(hit: cache::CacheHit) -> Response<ZionBody> {
    cache_response(hit, "HIT")
}

/// Every way a **fresh** hit leaves the cache, in RFC 9110 §13.2.2 order: a matching precondition
/// (`If-None-Match` / `If-Modified-Since`) is a `304`, else a satisfiable `Range` is a `206` (or a
/// `416`), else the whole object. One function so no exit (`only-if-cached` included) can skip a step.
fn fresh_hit_response(
    hit: cache::CacheHit,
    method: &hyper::Method,
    headers: &hyper::HeaderMap,
) -> Response<ZionBody> {
    if client_conditional_hit(headers, &hit.meta) {
        return not_modified_response(&hit);
    }
    if let Some(partial) = ranged_hit_response(&hit, method, headers) {
        return partial;
    }
    cache_hit_response(hit)
}

/// Seed a conditional GET for origin revalidation (RFC 9111 §4.3.1) from a stale entry's stored
/// validators, and from nothing else. The client's own preconditions (`If-None-Match`,
/// `If-Modified-Since`, `If-Match`, `If-Unmodified-Since`, `If-Range`) are removed first, and its
/// `Range` with them (without its `If-Range`, a `Range` would ask for a part of whatever the origin
/// now has). Only overwriting the ones the entry has a validator for left the rest in: the
/// client's `If-None-Match: *` beside zion's `If-Modified-Since`, for an entry with no `ETag`, is
/// evaluated first by the origin (RFC 9110 §13.2.2) and matches any representation, so its `304`
/// renewed an entry the origin had since changed, for every client. The foreground revalidation
/// and the background refresh both send what this leaves. The origin prefers `If-None-Match` when
/// both are present (RFC 9110 §13.1.3).
fn add_conditional_headers(headers: &mut hyper::HeaderMap, meta: &cache::CachedMeta) {
    for client_own in [
        hyper::header::IF_NONE_MATCH,
        hyper::header::IF_MODIFIED_SINCE,
        hyper::header::IF_MATCH,
        hyper::header::IF_UNMODIFIED_SINCE,
        hyper::header::IF_RANGE,
        hyper::header::RANGE,
    ] {
        headers.remove(client_own);
    }
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
/// revalidation", so they're folded together. Every `Cache-Control` line of the request counts.
fn parse_request_cache_control(headers: &hyper::HeaderMap) -> (bool, bool, bool) {
    let cc = CacheControl::of(headers);
    (
        cc.has("no-store"),
        cc.has("no-cache") || cc.seconds("max-age") == Some(0),
        cc.has("only-if-cached"),
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

/// Does a client conditional request match this cached entry — i.e. can we
/// answer 304 Not Modified? Thin adapter over the shared
/// [`crate::http_conditional::is_not_modified`] decision (RFC 9110 §13.1),
/// sourcing the validators from the cached representation's metadata so the 304
/// semantics stay identical to the static file server's.
fn client_conditional_hit(req_headers: &hyper::HeaderMap, meta: &cache::CachedMeta) -> bool {
    crate::http_conditional::is_not_modified(
        req_headers,
        meta.etag.as_ref(),
        meta.last_modified.as_ref(),
    )
}

/// 304 Not Modified from a cache hit, no body: the validators, and of the stored origin headers
/// those RFC 9110 §15.4.5 lists for a 304 (`Cache-Control`, `Content-Location`, `Date`,
/// `Expires`, `Vary`; see [`Replay::NotModified`]).
fn not_modified_response(hit: &cache::CacheHit) -> Response<ZionBody> {
    from_cache(
        hit,
        StatusCode::NOT_MODIFIED,
        "HIT",
        Replay::NotModified,
        Bytes::new(),
    )
}

/// Every line of a field as one value, the lines joined with `, ` (RFC 9110 §5.3 makes them one
/// list), for a field an entry keeps in a slot of its own. `Content-Encoding: gzip` then
/// `Content-Encoding: br` is a body that went through both codings: keeping the first line
/// only had a hit tell the client to gunzip a brotli stream.
fn every_line(
    headers: &hyper::HeaderMap,
    name: hyper::header::HeaderName,
) -> Option<hyper::header::HeaderValue> {
    let mut lines = headers.get_all(name).iter();
    let first = lines.next()?;
    let mut rest = lines.peekable();
    if rest.peek().is_none() {
        return Some(first.clone());
    }
    let mut joined = first.as_bytes().to_vec();
    for line in rest {
        joined.extend_from_slice(b", ");
        joined.extend_from_slice(line.as_bytes());
    }
    // Valid lines joined by `, ` are a valid value; were one ever refused, the first line stays.
    Some(hyper::header::HeaderValue::from_bytes(&joined).unwrap_or_else(|_| first.clone()))
}

/// The metadata an entry keeps of the origin's response, headers included
/// ([`cache::end_to_end_headers`]); `None` when those headers are more than an entry may hold
/// ([`cache::MAX_STORED_HEADER_BYTES`]): such a response is served, not stored.
fn cached_meta(status: StatusCode, headers: &hyper::HeaderMap) -> Option<cache::CachedMeta> {
    use hyper::header;
    let meta = cache::CachedMeta {
        // Preserve Content-Type and Content-Encoding (S-05): without Content-Encoding,
        // gzip-compressed bodies are served garbled. Every line of each.
        content_type: every_line(headers, header::CONTENT_TYPE),
        content_encoding: every_line(headers, header::CONTENT_ENCODING),
        status,
        // Validators for conditional requests (client If-None-Match → 304) and revalidation.
        etag: headers.get(header::ETAG).cloned(),
        last_modified: headers.get(header::LAST_MODIFIED).cloned(),
        stale_while_revalidate_secs: origin_swr(headers),
        must_revalidate: forbids_stale(headers),
        headers: cache::end_to_end_headers(headers),
    };
    meta.headers_fit().then_some(meta)
}

/// What a `304` from the origin makes of the entry it revalidated (RFC 9111 §4.3.4).
struct Revalidation {
    /// The entry as the 304 updated it: what the answer to this request carries, and what the
    /// entry becomes when it is renewed.
    meta: cache::CachedMeta,
    /// Its freshness lifetime, capped by the profile.
    ttl: u64,
    /// The 304's `Age`.
    initial_age: u64,
    /// The updated headers fit in an entry ([`cache::CachedMeta::headers_fit`]).
    fits: bool,
    /// The 304 may update the shared entry: it could have been stored itself
    /// ([`is_shared_cacheable`] on it), and the entry it makes has the `Vary` the entry was filed
    /// under ([`same_vary_shape`] on [`Self::meta`]).
    shareable: bool,
    /// The entry the 304 makes has another `Vary` than the one the entry was filed under: the
    /// origin now chooses this response by other request headers, and says so only for the
    /// client it answered. The entry is not renewed, and the stale entry is taken out
    /// ([`cache::StaticCache::remove_unchanged`]): the next request misses, and the `200` it gets
    /// files the response under the new `Vary` (`plan_storage`), where a `304` cannot.
    vary_changed: bool,
    /// The 304's `Set-Cookie` lines. An entry never keeps one ([`cache::end_to_end_headers`]),
    /// so they are not in [`Self::meta`]: they go on this client's answer alone.
    set_cookie: Vec<hyper::header::HeaderValue>,
}

impl Revalidation {
    /// The entry is renewed with [`Self::meta`]; otherwise the answer is served from it and
    /// the entry is left as it was, stale (or taken out, see [`Self::vary_changed`]).
    fn renews(&self) -> bool {
        self.fits && self.shareable
    }

    /// The header bound alone kept the 304 from renewing the entry: what `zion_cache_too_large`
    /// counts. A 304 that could not renew it anyway (not shareable, or under another `Vary`) is
    /// not counted however many headers it brought.
    fn too_large(&self) -> bool {
        !self.fits && self.shareable
    }
}

/// The entry `stored` once the origin answered its revalidation with a `304` carrying
/// `not_modified` (RFC 9111 §4.3.4): the 304's headers replace the stored ones of the same name
/// and the rest are kept ([`cache::CachedMeta::updated_by`]); a 304 with a `Cache-Control` also
/// sets the stale-serving rules again.
///
/// The lifetime is that of the updated response, so from the 304's `Cache-Control` or, when it
/// sent none, from the stored one: a bare `304` used to renew an entry the origin gave
/// `max-age=60` for the whole profile TTL, while its hits said `max-age=60`.
///
/// The 304 is the answer to this request, sent with its `Cookie` and `Authorization`: it
/// updates the shared entry only when it could have been stored itself, as a `200` is
/// ([`is_shared_cacheable`]: no `Set-Cookie`, no `private` / `no-store` / `no-cache`, the
/// §3.5 opt-in on the 304 itself when the request carried `Authorization`, a `Vary` zion can key
/// on, and fresh), and when the entry it makes keeps the `Vary` the entry was filed under
/// (`filed`, the rule the entry was found under, [`filed_key`]; see [`same_vary_shape`]): the 304's own, or the
/// stored one when the 304 sends none. Otherwise one user's `304` (`private`, with that user's
/// `X-Account`) became the entry every other user was served; and so did a public one that says
/// the origin now varies on a header the entry's key does not hold (`Vary: X-Auth-Subject` on an
/// entry filed under none), renewed under the old key with that user's headers.
fn revalidated(
    stored: &cache::CachedMeta,
    not_modified: &hyper::HeaderMap,
    req_authenticated: bool,
    cache_ttl: u64,
    filed: Option<&[String]>,
) -> Revalidation {
    let mut meta = stored.updated_by(not_modified);
    if not_modified.contains_key(hyper::header::CACHE_CONTROL) {
        meta.stale_while_revalidate_secs = origin_swr(not_modified);
        meta.must_revalidate = forbids_stale(not_modified);
    }
    // The 304's `Date` replaced the stored one. A 304 without one (an origin with no clock,
    // RFC 9110 §6.6.1) still confirmed the response now, and the answer says `Age` from the 304:
    // with the stored `Date` beside it, a downstream cache would take the response for as old
    // as that `Date`. Without one, the answer is dated when it is sent.
    if !not_modified.contains_key(hyper::header::DATE) {
        meta.headers
            .retain(|(name, _)| *name != hyper::header::DATE);
    }
    let ttl = origin_freshness(&stored_lines(&meta, hyper::header::CACHE_CONTROL))
        .map(|o| o.min(cache_ttl))
        .unwrap_or(cache_ttl);
    let initial_age = upstream_age(not_modified);
    // Judged on the entry the 304 makes: a 304 that sends no `Vary` keeps the stored one.
    let same_vary = same_vary_shape(&stored_lines(&meta, hyper::header::VARY), filed);
    let shareable =
        same_vary && is_shared_cacheable(req_authenticated, not_modified, ttl, initial_age);
    let fits = meta.headers_fit();
    let set_cookie = not_modified
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .cloned()
        .collect();
    Revalidation {
        meta,
        ttl,
        initial_age,
        fits,
        shareable,
        vary_changed: !same_vary,
        set_cookie,
    }
}

/// The `Cache-Control` of an answer for one client alone: `private`, then, of the entry's
/// directives (every line), those a private cache obeys that only hold it back or give the
/// origin's own lifetime: `no-store`, `no-cache`, `must-revalidate`, `no-transform` and
/// `max-age`. Never `public` or `s-maxage`, which tell a shared cache it may keep the answer.
fn one_client_cache_control(meta: &cache::CachedMeta) -> hyper::header::HeaderValue {
    use std::fmt::Write as _;
    let lines = stored_lines(meta, hyper::header::CACHE_CONTROL);
    let cc = CacheControl::of(&lines);
    let mut value = String::from("private");
    for directive in ["no-store", "no-cache", "must-revalidate", "no-transform"] {
        if cc.has(directive) {
            value.push_str(", ");
            value.push_str(directive);
        }
    }
    if let Some(secs) = cc.seconds("max-age") {
        let _ = write!(value, ", max-age={secs}");
    }
    // Directive names and digits: always a valid value.
    hyper::header::HeaderValue::from_str(&value)
        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("private"))
}

/// A cache field that a cache in front of zion obeys in place of `Cache-Control`, so a `private`
/// in `Cache-Control` says nothing to a cache that reads it:
///
/// - the targeted fields of RFC 9213 (a cache they target ignores `Cache-Control` and `Expires`,
///   §2.2): `CDN-Cache-Control`, for every CDN that implements it (§3), and one per CDN or vendor,
///   named by the §2.4 convention with the suffix `-Cache-Control` (`Cloudflare-CDN-Cache-Control`,
///   `Vercel-CDN-Cache-Control`, `Netlify-CDN-Cache-Control`, `Akamai-Cache-Control`): any name
///   that ends in `-cache-control` (`Cache-Control` itself does not);
/// - `Surrogate-Control`, the W3C Edge Architecture field (Fastly, Varnish);
/// - `Edge-Control`, Akamai's older field;
/// - `X-Accel-Expires`, which nginx `proxy_cache` ranks above `Cache-Control`.
///
/// A pattern, not a list: each CDN names its own targeted field, and a list of the three names
/// known when it was written missed `Vercel-CDN-Cache-Control` and `Akamai-Cache-Control`. RFC
/// 9213 §2.4 says the `-Cache-Control` suffix MUST NOT be used on its own to identify targeted
/// fields: it is only a convention. zion uses it only to leave such fields off an answer that is
/// `private`, never to obey one (it reads none of them for its own caching), so a name the pattern
/// takes by mistake costs that one answer a field. An answer for one client alone carries none
/// of them ([`revalidated_response`]): a CDN that reads one would keep that client's answer, the
/// 304's per-user headers and `Set-Cookie` included, for every client. The entry keeps them, and
/// a shared answer from it (a hit, a `REVALIDATED` that renewed it) still carries them. `name` is
/// lower-case, as hyper keeps names.
fn is_targeted_cache_field(name: &hyper::header::HeaderName) -> bool {
    let name = name.as_str();
    name.ends_with("-cache-control")
        || matches!(
            name,
            "surrogate-control" | "edge-control" | "x-accel-expires"
        )
}

/// The answer to a request whose revalidation the origin confirmed with a `304`: the stored body
/// with the entry as the 304 updated it, marked `REVALIDATED`, with the 304's `Age` and the
/// lifetime it gave (as on the next hit, not those of the stale lookup: an `Age` past the
/// `max-age` made a downstream cache take the answer as stale on arrival).
///
/// A 304 that could not update the shared entry ([`Revalidation::shareable`]) answered this
/// client alone, its headers included, and so is this answer: it says `private`
/// ([`one_client_cache_control`]) whatever the 304 or the entry said, and carries the 304's
/// `Set-Cookie`. With the entry's `public, max-age=60`, or the `public, max-age=<lifetime>` of a
/// hit when neither had a `Cache-Control`, a shared cache downstream could keep, for every client,
/// a response zion has just judged to be one client's (with that user's headers); and the
/// `Set-Cookie` that made the 304 one client's was dropped, so the client lost the cookie the
/// origin rotated, and a downstream cache that does not store a response with a `Set-Cookie`
/// stored this one. Nor does it carry the entry's targeted cache fields
/// ([`is_targeted_cache_field`]): a CDN in front of zion obeys those instead of `Cache-Control`,
/// and its `CDN-Cache-Control: max-age=600` would have it keep this client's answer for everyone,
/// whatever the `private`.
fn revalidated_response(stale: cache::CacheHit, rv: Revalidation) -> Response<ZionBody> {
    let one_client = (!rv.shareable).then(|| (one_client_cache_control(&rv.meta), rv.set_cookie));
    let hit = cache::CacheHit {
        meta: Arc::new(rv.meta),
        age_secs: rv.initial_age,
        max_age_secs: rv.ttl,
        ..stale
    };
    let mut resp = cache_response(hit, "REVALIDATED");
    if let Some((cache_control, set_cookie)) = one_client {
        let h = resp.headers_mut();
        h.insert(hyper::header::CACHE_CONTROL, cache_control);
        let targeted: Vec<hyper::header::HeaderName> = h
            .keys()
            .filter(|name| is_targeted_cache_field(name))
            .cloned()
            .collect();
        for name in targeted {
            h.remove(name);
        }
        for cookie in set_cookie {
            h.append(hyper::header::SET_COOKIE, cookie);
        }
    }
    resp
}

/// A request's place in the singleflight map: it became the fetcher for `key`, and other
/// requests for that key wait on `tx`. Dropping it takes the registration out and closes
/// the channel, which is what wakes the waiters when the fetch stored nothing; and it is
/// dropped whichever way the fetch ends, the request future being dropped mid-fetch
/// included (hyper does that when the client goes away).
pub(crate) struct Fetching {
    state: Arc<AppState>,
    key: Arc<str>,
    tx: tokio::sync::watch::Sender<bool>,
}

impl Fetching {
    #[cfg(test)]
    pub(crate) fn for_tests(
        state: Arc<AppState>,
        key: Arc<str>,
        tx: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        Self { state, key, tx }
    }

    /// The response is in the cache: tell the waiters to read it there. Published before
    /// the registration goes, so a request arriving in between finds `true`.
    ///
    /// `send_replace`, not `send`: `send` stores nothing when no receiver exists, and none
    /// does until a second request arrives (the channel is created without one). A request
    /// that took this sender out of the map just before it was removed, and subscribed just
    /// after a `send`, saw `false` on a channel nobody would ever write to again.
    pub(crate) fn stored(self) {
        self.tx.send_replace(true);
    }
}

impl Drop for Fetching {
    fn drop(&mut self) {
        // Only this fetch's own registration: by the time a streamed body ends, another
        // request may have registered under the same key.
        self.state
            .inflight
            .remove_if(&self.key, |tx| tx.same_channel(&self.tx));
    }
}

// Thread-local route LRU: `dispatch/route_cache.rs`.
mod route_cache;
pub(crate) use route_cache::route_cache_key;

// ==========================================================================
// TESTS
// ==========================================================================

#[cfg(test)]
mod tests {
    /// An oversize body is `413`; a body that broke on the way is `400`, not `413`.
    #[tokio::test]
    async fn a_broken_body_is_not_reported_as_too_large() {
        use http_body_util::{BodyExt, Full};
        let over: crate::http_util::ReqBody = Full::new(bytes::Bytes::from(vec![0u8; 100]))
            .map_err(|never| match never {})
            .boxed();
        let e = crate::upstream_body::read_capped(over, 10)
            .await
            .expect_err("100 bytes over a cap of 10");
        assert_eq!(
            super::body_read_failure(e.as_ref()).0,
            hyper::StatusCode::PAYLOAD_TOO_LARGE
        );

        let broken = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "stream reset");
        let (status, msg) = super::body_read_failure(&broken);
        assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(msg, "request body read error");
    }

    /// A background refresh waits for the origin as long as the request it refreshes would
    /// have (`[upstream.x] request_timeout_ms`), and marks nothing when the default applies.
    #[test]
    fn a_background_refresh_keeps_the_upstream_request_timeout() {
        use http_body_util::{BodyExt, Full};
        let request = || {
            hyper::Request::builder()
                .uri("/a")
                .body(
                    Full::new(bytes::Bytes::new())
                        .map_err(|n| match n {})
                        .boxed(),
                )
                .unwrap()
        };
        let mark = crate::proxy::RequestTimeout(std::time::Duration::from_millis(250));
        let mut marked = request();
        marked.extensions_mut().insert(mark);
        assert_eq!(
            super::swr_request(&marked)
                .extensions()
                .get::<crate::proxy::RequestTimeout>(),
            Some(&mark)
        );
        assert!(super::swr_request(&request())
            .extensions()
            .get::<crate::proxy::RequestTimeout>()
            .is_none());
    }

    #[test]
    fn route_cache_clear_empties_it_and_it_stays_usable() {
        let mut c = route_cache::RouteCache::<u32>::new(3);
        for k in 0..3u64 {
            put(&mut c, k, k as u32 + 10);
        }
        assert_eq!(hit(&mut c, 1), Some(11));
        c.clear();
        assert!((0..3u64).all(|k| hit(&mut c, k).is_none()), "cleared");
        // refills to capacity and evicts normally afterwards
        for k in 10..14u64 {
            put(&mut c, k, k as u32);
        }
        assert!(
            hit(&mut c, 10).is_none(),
            "the LRU entry was evicted past capacity"
        );
        assert_eq!(hit(&mut c, 13), Some(13));
    }

    #[test]
    fn a_set_cookie_response_is_not_storable_even_if_public() {
        let mut h = hdr(
            hyper::header::CACHE_CONTROL,
            "public, max-age=600, s-maxage=600",
        );
        assert!(
            is_shared_cacheable(false, &h, TTL, 0),
            "control: storable without the cookie"
        );
        h.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static("sid=1; HttpOnly"),
        );
        assert!(
            !is_shared_cacheable(false, &h, TTL, 0),
            "Set-Cookie wins over public / s-maxage"
        );
    }

    #[test]
    fn forbids_stale_matches_directive_names_only() {
        let h = |v: &str| hdr(hyper::header::CACHE_CONTROL, v);
        for yes in [
            "must-revalidate",
            "public, max-age=10, Must-Revalidate",
            "proxy-revalidate",
            "max-age=10, s-maxage=60",
            "s-maxage=0",
        ] {
            assert!(forbids_stale(&h(yes)), "{yes}");
        }
        for no in [
            "public, max-age=60",
            "max-age=60, stale-while-revalidate=30",
            "x-must-revalidate-not",
            "no-store-s-maxage-ish",
            "",
        ] {
            assert!(!forbids_stale(&h(no)), "{no}");
        }
        assert!(!forbids_stale(&hyper::HeaderMap::new()));
    }

    #[test]
    fn swr_budget_is_bounded_and_released() {
        static B: SwrBudget = SwrBudget {
            active: std::sync::atomic::AtomicUsize::new(0),
            max: 3,
        };
        let held: Vec<_> = (0..3)
            .map(|_| B.try_acquire().expect("within budget"))
            .collect();
        assert!(B.try_acquire().is_none(), "a 4th refresh must be refused");
        drop(held);
        let again: Vec<_> = (0..3)
            .map(|_| B.try_acquire().expect("slots released"))
            .collect();
        assert_eq!(again.len(), 3);
        drop(again);
        assert_eq!(B.active.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    use super::*;
    use crate::security::is_internal_ip;

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

    // ── Cache-Control split across field lines (RFC 9110 §5.3) ──
    // hyper's HTTP/1 client keeps each upstream field line as its own value
    // (`headers.append`), so two lines reach these functions as two values. RFC 9110
    // §5.3 makes them equivalent to one comma-joined line.

    /// `Cache-Control: <first>` then `Cache-Control: <second>`, as hyper builds it.
    fn split_cc(first: &str, second: &str) -> hyper::HeaderMap {
        let mut h = hdr(hyper::header::CACHE_CONTROL, first);
        h.append(hyper::header::CACHE_CONTROL, second.parse().unwrap());
        h
    }

    #[test]
    fn a_later_cache_control_line_forbids_shared_storage() {
        for forbid in ["private", "no-store", "no-cache"] {
            let joined = hdr(
                hyper::header::CACHE_CONTROL,
                &format!("max-age=300, {forbid}"),
            );
            assert!(
                !is_shared_cacheable(false, &joined, TTL, 0),
                "control: one line `max-age=300, {forbid}` is refused"
            );
            let split = split_cc("max-age=300", forbid);
            assert!(
                !is_shared_cacheable(false, &split, TTL, 0),
                "two lines `max-age=300` + `{forbid}` must be refused like the joined line, \
                 but is_shared_cacheable stored it"
            );
        }
        // control: two lines that forbid nothing are stored
        assert!(is_shared_cacheable(
            false,
            &split_cc("max-age=300", "public"),
            TTL,
            0
        ));
    }

    #[test]
    fn a_later_private_line_is_honoured_for_an_authenticated_request() {
        let joined = hdr(hyper::header::CACHE_CONTROL, "public, max-age=300, private");
        assert!(
            !is_shared_cacheable(true, &joined, TTL, 0),
            "control: joined line refused"
        );
        let split = split_cc("public, max-age=300", "private");
        assert!(
            !is_shared_cacheable(true, &split, TTL, 0),
            "authenticated request: `public, max-age=300` + `private` on two lines was stored"
        );
        // an opt-in on the second line is an opt-in
        assert!(is_shared_cacheable(
            true,
            &split_cc("max-age=300", "public"),
            TTL,
            0
        ));
    }

    #[test]
    fn an_authenticated_response_opts_in_with_a_whole_directive_only() {
        for not_opt_in in [
            "max-age=300, x-public-ish",
            "nonpublic",
            "x-s-maxage-like=5",
        ] {
            let h = hdr(hyper::header::CACHE_CONTROL, not_opt_in);
            assert!(
                !is_shared_cacheable(true, &h, TTL, 0),
                "`{not_opt_in}` is not a §3.5 opt-in"
            );
        }
    }

    #[test]
    fn origin_freshness_reads_every_cache_control_line() {
        assert_eq!(
            origin_freshness(&hdr(hyper::header::CACHE_CONTROL, "public, max-age=0")),
            Some(0),
            "control: joined line"
        );
        assert_eq!(
            origin_freshness(&split_cc("public", "max-age=0")),
            Some(0),
            "`public` + `max-age=0` on two lines: lifetime 0, not the profile TTL"
        );
        assert_eq!(
            origin_freshness(&split_cc("max-age=60", "s-maxage=600")),
            Some(600),
            "s-maxage on the second line wins"
        );
        assert_eq!(
            origin_freshness(&split_cc("max-age=300", "max-age=0")),
            Some(0),
            "two different lifetimes: stale (RFC 9111 §4.2.1)"
        );
    }

    #[test]
    fn origin_swr_reads_every_cache_control_line() {
        let mut joined = hyper::HeaderMap::new();
        joined.insert(
            hyper::header::CACHE_CONTROL,
            "max-age=60, stale-while-revalidate=30".parse().unwrap(),
        );
        assert_eq!(origin_swr(&joined), 30, "control: joined line");
        assert_eq!(
            origin_swr(&split_cc("max-age=60", "stale-while-revalidate=30")),
            30,
            "`stale-while-revalidate=30` on a second line is read"
        );
    }

    #[test]
    fn a_request_cache_control_line_after_the_first_counts() {
        for (second, want) in [
            ("no-store", (true, false, false)),
            ("no-cache", (false, true, false)),
            ("max-age=0", (false, true, false)),
            ("only-if-cached", (false, false, true)),
        ] {
            assert_eq!(
                parse_request_cache_control(&split_cc("max-stale=5", second)),
                want,
                "request `max-stale=5` + `{second}` on two lines"
            );
        }
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
    fn bypass_per_user_vary_but_key_the_rest() {
        // §4.1: per-user `Vary` (`*`, Cookie, Authorization) is never stored; every
        // other varied header gets a secondary key, `Accept-Encoding` being part of the
        // primary key already.
        for v in [
            "Cookie",
            "Authorization",
            "*",
            "Accept-Encoding, Cookie",
            "Accept-Language, Authorization",
        ] {
            let h = hdr(hyper::header::VARY, v);
            assert!(!is_shared_cacheable(false, &h, TTL, 0), "unsafe vary: {v}");
        }
        // Everything else is stored under a secondary key (see `vary`), and
        // Accept-Encoding is part of the primary key.
        for v in [
            "Accept-Encoding",
            "accept-encoding",
            "Accept-Encoding, accept-encoding",
            "Accept",
            "Accept-Language",
            "User-Agent",
            "Accept-Encoding, Accept-Language",
            "Origin",
        ] {
            let h = hdr(hyper::header::VARY, v);
            assert!(is_shared_cacheable(false, &h, TTL, 0), "keyed vary: {v}");
        }
    }

    #[test]
    fn identity_is_refused_only_when_excluded() {
        let refuses = |v: &str| {
            let mut h = hyper::HeaderMap::new();
            if !v.is_empty() {
                h.insert(hyper::header::ACCEPT_ENCODING, v.parse().unwrap());
            }
            refuses_identity(&h)
        };
        for v in [
            "",
            "gzip",
            "gzip, br",
            "*",
            "identity",
            "gzip;q=0",
            "identity;q=0.5",
        ] {
            assert!(!refuses(v), "{v:?} accepts identity");
        }
        for v in [
            "identity;q=0",
            "gzip, identity;q=0",
            "IDENTITY; q=0.0",
            "*;q=0",
            "gzip, *;q=0",
        ] {
            assert!(refuses(v), "{v:?} refuses identity");
        }
        // an explicit identity entry wins over `*;q=0`
        assert!(!refuses("*;q=0, identity"));
    }

    #[test]
    fn only_an_unencoded_response_not_chosen_by_encoding_is_shared() {
        let shared = |hs: &[(&str, &str)]| {
            let mut h = hyper::HeaderMap::new();
            for (k, v) in hs {
                h.append(
                    hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }
            shareable_identity(&h)
        };
        assert!(shared(&[]));
        assert!(shared(&[("content-encoding", "identity")]));
        assert!(shared(&[("vary", "Accept-Language")]));
        assert!(!shared(&[("content-encoding", "gzip")]));
        assert!(!shared(&[("content-encoding", "identity, br")]));
        assert!(!shared(&[("vary", "Origin, accept-encoding")]));
        assert!(!shared(&[("vary", "Origin"), ("vary", "Accept-Encoding")]));
        assert!(!shared(&[("vary", "*")]));
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

    // ── What an answer from the cache carries of the origin's headers ──

    /// The headers an upload origin sends with an SVG: what makes it inert in a browser
    /// (`Content-Disposition`, `Content-Security-Policy`), and the rest a hit must keep too.
    /// The `Cache-Control` is written as `profile_cache_control` never writes it, so that a
    /// hit carrying one made up from the entry's lifetime (60 s here too) fails.
    fn upload_origin_headers() -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in [
            ("content-type", "image/svg+xml"),
            ("cache-control", "max-age=60, public"),
            ("content-security-policy", "sandbox"),
            ("content-disposition", "attachment; filename=\"upload.svg\""),
            ("vary", "Accept-Language"),
            ("link", "</a.css>; rel=preload"),
            ("link", "</b.js>; rel=preload"),
            ("expires", "Thu, 01 Jan 2099 00:00:00 GMT"),
            ("content-location", "/media/upload.svg"),
            ("etag", "\"u1\""),
            ("content-length", "10"),
            ("date", "Thu, 01 Jan 2026 00:00:00 GMT"),
        ] {
            h.append(
                hyper::header::HeaderName::from_static(k),
                hyper::header::HeaderValue::from_static(v),
            );
        }
        h
    }

    /// [`revalidated`] for an entry filed under its own `Vary`, as one stored from a `200` is.
    fn revalidated_as_filed(
        stored: &cache::CachedMeta,
        not_modified: &hyper::HeaderMap,
        req_authenticated: bool,
        cache_ttl: u64,
    ) -> Revalidation {
        let filed = match vary::policy(&stored_lines(stored, hyper::header::VARY)) {
            vary::VaryPolicy::Keyed(names) => Some(names),
            _ => None,
        };
        revalidated(
            stored,
            not_modified,
            req_authenticated,
            cache_ttl,
            filed.as_deref(),
        )
    }

    fn stored_hit(origin: &hyper::HeaderMap) -> cache::CacheHit {
        cache::CacheHit {
            body: Bytes::from_static(b"0123456789"),
            meta: Arc::new(cached_meta(StatusCode::OK, origin).expect("fits")),
            age_secs: 5,
            max_age_secs: 60,
            refresh_refused: false,
        }
    }

    fn values(resp: &Response<ZionBody>, name: &str) -> Vec<String> {
        resp.headers()
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    fn request(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    /// The headers of `origin` an answer with the stored body must carry, each as many times
    /// as the origin sent it: all of them but what is recomputed for each answer. `Date` is the
    /// origin's.
    fn assert_carries_the_origin_headers(resp: &Response<ZionBody>, origin: &hyper::HeaderMap) {
        for name in origin.keys() {
            if name.as_str() == "content-length" {
                continue;
            }
            let want: Vec<String> = origin
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect();
            assert_eq!(
                values(resp, name.as_str()),
                want,
                "{name} on a {} from the cache",
                resp.status()
            );
        }
    }

    #[test]
    fn a_hit_carries_the_origin_headers_once_and_its_own_cache_headers() {
        let origin = upload_origin_headers();
        let resp = fresh_hit_response(
            stored_hit(&origin),
            &hyper::Method::GET,
            &hyper::HeaderMap::new(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_carries_the_origin_headers(&resp, &origin);
        assert_eq!(values(&resp, "x-zion-cache"), ["HIT"]);
        assert_eq!(values(&resp, "age"), ["5"]);
        assert_eq!(values(&resp, "accept-ranges"), ["bytes"]);
        assert!(
            values(&resp, "content-length").is_empty(),
            "recomputed when the answer is sent"
        );
        // When the origin made it: with `Expires`, the lifetime it gave, and with `Age`, how old
        // it is. A `Date` of now beside `Age: 5` counted the 5 s twice.
        assert_eq!(values(&resp, "date"), ["Thu, 01 Jan 2026 00:00:00 GMT"]);
        // The stale and revalidated answers carry them too.
        for disposition in ["STALE", "REVALIDATED", "STALE-WHILE-REVALIDATE"] {
            let resp = cache_response(stored_hit(&origin), disposition);
            assert_carries_the_origin_headers(&resp, &origin);
            assert_eq!(values(&resp, "x-zion-cache"), [disposition]);
        }
    }

    #[test]
    fn a_hit_without_an_origin_cache_control_carries_the_entry_lifetime_as_the_miss_did() {
        let mut origin = upload_origin_headers();
        origin.remove(hyper::header::CACHE_CONTROL);
        let resp = cache_response(stored_hit(&origin), "HIT");
        assert_eq!(values(&resp, "cache-control"), ["public, max-age=60"]);
        assert_eq!(values(&resp, "content-security-policy"), ["sandbox"]);
    }

    /// A ranged answer carries the origin's headers but the digests of the whole content: a
    /// `206` of ten bytes with the whole file's `Content-Digest` is rejected as corrupt by a
    /// client that checks it (RFC 9530 §2). `Repr-Digest` describes the representation and stays.
    #[test]
    fn a_ranged_hit_carries_the_origin_headers_but_the_whole_content_digests() {
        let mut origin = upload_origin_headers();
        for (k, v) in [
            ("content-digest", "sha-256=:d2hvbGUgZmlsZQ==:"),
            ("content-md5", "Q2hlY2sgSW50ZWdyaXR5IQ=="),
            ("repr-digest", "sha-256=:d2hvbGUgZmlsZQ==:"),
        ] {
            origin.append(
                hyper::header::HeaderName::from_static(k),
                hyper::header::HeaderValue::from_static(v),
            );
        }
        let mut for_a_part = origin.clone();
        for_a_part.remove("content-digest");
        for_a_part.remove("content-md5");
        let get = &hyper::Method::GET;
        let whole = fresh_hit_response(stored_hit(&origin), get, &hyper::HeaderMap::new());
        assert_carries_the_origin_headers(&whole, &origin);
        let partial = fresh_hit_response(
            stored_hit(&origin),
            get,
            &request(&[("range", "bytes=0-3")]),
        );
        assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
        assert_carries_the_origin_headers(&partial, &for_a_part);
        for whole_content in ["content-digest", "content-md5"] {
            assert!(
                values(&partial, whole_content).is_empty(),
                "{whole_content} on a 206"
            );
        }
        assert_eq!(values(&partial, "content-range"), ["bytes 0-3/10"]);
        assert_eq!(values(&partial, "accept-ranges"), ["bytes"]);
        assert_eq!(values(&partial, "x-zion-cache"), ["HIT"]);

        let unsatisfiable = fresh_hit_response(
            stored_hit(&origin),
            get,
            &request(&[("range", "bytes=50-")]),
        );
        assert_eq!(unsatisfiable.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_carries_the_origin_headers(&unsatisfiable, &for_a_part);
        assert!(values(&unsatisfiable, "content-digest").is_empty());
        assert_eq!(values(&unsatisfiable, "content-range"), ["bytes */10"]);
    }

    /// Every `Content-Encoding` line is a coding the body went through, and every
    /// `Content-Type` line is part of the one value a browser reads: a hit says all of them,
    /// joined, as one line (RFC 9110 §5.3), and not the first alone.
    #[test]
    fn a_hit_carries_every_content_encoding_and_content_type_line() {
        let origin = request(&[
            ("content-encoding", "gzip"),
            ("content-encoding", "br"),
            ("content-type", "text/plain"),
            ("content-type", "text/html"),
            ("cache-control", "max-age=60"),
        ]);
        let resp = cache_response(stored_hit(&origin), "HIT");
        assert_eq!(values(&resp, "content-encoding"), ["gzip, br"]);
        assert_eq!(values(&resp, "content-type"), ["text/plain, text/html"]);
        let one = request(&[("content-encoding", "gzip")]);
        let resp = cache_response(stored_hit(&one), "HIT");
        assert_eq!(
            values(&resp, "content-encoding"),
            ["gzip"],
            "one line as it was"
        );
    }

    #[test]
    fn a_304_from_the_cache_carries_the_headers_rfc_9110_lists_for_it() {
        let origin = upload_origin_headers();
        let resp = fresh_hit_response(
            stored_hit(&origin),
            &hyper::Method::GET,
            &request(&[("if-none-match", "\"u1\"")]),
        );
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        // RFC 9110 §15.4.5: Cache-Control, Content-Location, Date, ETag, Expires, Vary.
        assert_eq!(values(&resp, "cache-control"), ["max-age=60, public"]);
        assert_eq!(values(&resp, "content-location"), ["/media/upload.svg"]);
        assert_eq!(values(&resp, "date"), ["Thu, 01 Jan 2026 00:00:00 GMT"]);
        assert_eq!(values(&resp, "etag"), ["\"u1\""]);
        assert_eq!(values(&resp, "expires"), ["Thu, 01 Jan 2099 00:00:00 GMT"]);
        assert_eq!(values(&resp, "vary"), ["Accept-Language"]);
        assert_eq!(values(&resp, "x-zion-cache"), ["HIT"]);
        // ... and not the representation's other metadata: the client keeps what it stored.
        for absent in ["content-type", "content-security-policy", "link"] {
            assert!(values(&resp, absent).is_empty(), "{absent} on a 304");
        }
    }

    #[test]
    fn a_revalidating_304_updates_the_entry_and_a_too_large_result_is_not_kept() {
        let origin = upload_origin_headers();
        let stored = cached_meta(StatusCode::OK, &origin).unwrap();
        let not_modified = request(&[
            ("cache-control", "public, max-age=120, must-revalidate"),
            ("x-new", "1"),
        ]);
        let rv = revalidated_as_filed(&stored, &not_modified, false, 3600);
        assert!(rv.fits && rv.shareable && rv.renews());
        assert_eq!(rv.ttl, 120);
        assert!(
            rv.meta.must_revalidate,
            "the 304's Cache-Control sets the rules"
        );
        let resp = cache_response(
            cache::CacheHit {
                meta: Arc::new(rv.meta),
                ..stored_hit(&origin)
            },
            "REVALIDATED",
        );
        assert_eq!(
            values(&resp, "cache-control"),
            ["public, max-age=120, must-revalidate"]
        );
        assert_eq!(values(&resp, "x-new"), ["1"]);
        assert_eq!(values(&resp, "content-security-policy"), ["sandbox"]);

        let huge = "x".repeat(cache::MAX_STORED_HEADER_BYTES);
        let rv = revalidated_as_filed(&stored, &request(&[("x-huge", huge.as_str())]), false, 3600);
        assert!(!rv.fits && !rv.renews(), "over the bound: served, not kept");
        assert!(cached_meta(StatusCode::OK, &request(&[("x-huge", huge.as_str())])).is_none());
    }

    /// RFC 9111 §4.3.4: the entry's lifetime after a `304` is that of the updated response, so
    /// the stored `Cache-Control` when the 304 sent none, not the profile TTL.
    #[test]
    fn a_bare_304_keeps_the_lifetime_the_origin_gave_the_entry() {
        let stored = cached_meta(StatusCode::OK, &upload_origin_headers()).unwrap(); // max-age=60
        let bare = request(&[("etag", "\"u1\"")]);
        let ttl = |stored: &cache::CachedMeta, not_modified: &hyper::HeaderMap| {
            revalidated_as_filed(stored, not_modified, false, 3600).ttl
        };
        assert_eq!(
            ttl(&stored, &bare),
            60,
            "the stored max-age, not the profile's 3600"
        );
        assert_eq!(
            ttl(&stored, &request(&[("cache-control", "max-age=120")])),
            120
        );
        assert_eq!(
            ttl(&stored, &request(&[("cache-control", "max-age=99999")])),
            3600,
            "capped by the profile"
        );
        let mut no_cc = upload_origin_headers();
        no_cc.remove(hyper::header::CACHE_CONTROL);
        let stored_no_cc = cached_meta(StatusCode::OK, &no_cc).unwrap();
        assert_eq!(
            ttl(&stored_no_cc, &bare),
            3600,
            "no lifetime anywhere: the profile's"
        );
        let rv = revalidated_as_filed(&stored, &request(&[("age", "7")]), false, 3600);
        assert_eq!((rv.ttl, rv.initial_age), (60, 7), "the 304's Age");
    }

    /// A `304` answers the request that was sent, with the client's `Cookie` and
    /// `Authorization`: it renews the shared entry only when it could have been stored itself.
    #[test]
    fn a_304_that_could_not_be_stored_itself_does_not_renew_the_entry() {
        let stored = cached_meta(StatusCode::OK, &upload_origin_headers()).unwrap();
        let shareable = |authenticated: bool, pairs: &[(&str, &str)]| {
            revalidated_as_filed(&stored, &request(pairs), authenticated, 3600).shareable
        };
        // what may update it
        assert!(
            shareable(false, &[("etag", "\"u1\"")]),
            "a bare 304, anonymous"
        );
        assert!(shareable(
            false,
            &[("cache-control", "max-age=60"), ("x-new", "1")]
        ));
        assert!(
            shareable(true, &[("cache-control", "public, max-age=60")]),
            "opted in"
        );
        // what may not
        for (authenticated, pairs) in [
            (
                false,
                &[
                    ("cache-control", "private, max-age=60"),
                    ("x-account", "alice"),
                ][..],
            ),
            (
                false,
                &[
                    ("cache-control", "max-age=60"),
                    ("cache-control", "no-store"),
                ],
            ),
            (false, &[("cache-control", "no-cache")]),
            (false, &[("set-cookie", "sid=alice")]),
            (false, &[("vary", "Cookie")]),
            (false, &[("cache-control", "max-age=0")]),
            (false, &[("age", "61")]),
            // §3.5: the opt-in must be on the 304 itself, not inherited from the stored entry
            (true, &[("etag", "\"u1\""), ("x-account", "alice")]),
            (true, &[("cache-control", "max-age=60")]),
        ] {
            let rv = revalidated_as_filed(&stored, &request(pairs), authenticated, 3600);
            assert!(
                !rv.shareable && !rv.renews(),
                "{pairs:?} (authenticated: {authenticated}) renewed the shared entry"
            );
        }
    }

    /// A `304` that answered one client alone is not labelled `public` for a shared cache
    /// downstream: with no `Cache-Control` in the 304 or the entry, a hit's `public,
    /// max-age=<lifetime>` went on alice's answer, her `X-Account` with it.
    #[test]
    fn a_304_that_answered_one_client_alone_is_not_marked_public() {
        let mut no_cc = upload_origin_headers();
        no_cc.remove(hyper::header::CACHE_CONTROL);
        let stale = || stored_hit(&no_cc);
        let hers = request(&[("etag", "\"u1\""), ("x-account", "alice")]);
        let rv = revalidated_as_filed(&stale().meta, &hers, true, 3600);
        assert!(!rv.shareable);
        let resp = revalidated_response(stale(), rv);
        assert_eq!(values(&resp, "x-zion-cache"), ["REVALIDATED"]);
        assert_eq!(values(&resp, "x-account"), ["alice"], "her own answer");
        assert_eq!(values(&resp, "cache-control"), ["private"]);
        // The same 304 to an anonymous request renews the entry, and its answer is what a hit
        // on the entry carries.
        let rv = revalidated_as_filed(&stale().meta, &hers, false, 3600);
        assert!(rv.renews());
        let resp = revalidated_response(stale(), rv);
        assert_eq!(values(&resp, "cache-control"), ["public, max-age=3600"]);
        // With a Cache-Control, the 304's or the entry's, the answer is `private` too, with what a
        // private cache obeys of it and never `public` or `s-maxage`.
        let with_cc = request(&[("cache-control", "max-age=30"), ("x-account", "alice")]);
        let rv = revalidated_as_filed(&stale().meta, &with_cc, true, 3600);
        assert!(!rv.shareable);
        let resp = revalidated_response(stale(), rv);
        assert_eq!(values(&resp, "cache-control"), ["private, max-age=30"]);
        let entrys = stored_hit(&upload_origin_headers()); // `max-age=60, public`
        let rv = revalidated_as_filed(&entrys.meta, &hers, true, 3600);
        let resp = revalidated_response(entrys, rv);
        assert_eq!(values(&resp, "cache-control"), ["private, max-age=60"]);
        for (lines, expected) in [
            (
                &[
                    "public, s-maxage=600, max-age=5",
                    "no-cache, must-revalidate",
                ][..],
                "private, no-cache, must-revalidate, max-age=5",
            ),
            (
                &["no-store, no-transform, stale-while-revalidate=30"],
                "private, no-store, no-transform",
            ),
            (
                &["public, s-maxage=600", "private=\"x-account\""],
                "private",
            ),
            (&["max-age=300", "max-age=60"], "private, max-age=0"),
        ] {
            let mut not_modified = request(&[("x-account", "alice")]);
            for line in lines {
                not_modified.append(hyper::header::CACHE_CONTROL, line.parse().unwrap());
            }
            let rv = revalidated_as_filed(&stale().meta, &not_modified, true, 3600);
            assert!(!rv.shareable, "{lines:?}");
            let resp = revalidated_response(stale(), rv);
            assert_eq!(values(&resp, "cache-control"), [expected], "{lines:?}");
        }
    }

    /// The `Set-Cookie` that made a `304` one client's goes to that client, on its answer alone:
    /// the entry never keeps one, so it was dropped, and the session cookie the origin rotated on
    /// the 304 never reached the client.
    #[test]
    fn a_304s_set_cookie_reaches_the_client_it_answered() {
        let stale = || stored_hit(&upload_origin_headers());
        let hers = request(&[
            ("set-cookie", "sid=rotated; HttpOnly"),
            ("set-cookie", "theme=dark"),
            ("x-session", "alice"),
        ]);
        let rv = revalidated_as_filed(&stale().meta, &hers, false, 3600);
        assert!(!rv.shareable && !rv.renews());
        assert!(
            !rv.meta
                .headers
                .iter()
                .any(|(name, _)| *name == hyper::header::SET_COOKIE),
            "an entry keeps no Set-Cookie"
        );
        let resp = revalidated_response(stale(), rv);
        assert_eq!(
            values(&resp, "set-cookie"),
            ["sid=rotated; HttpOnly", "theme=dark"]
        );
        assert_eq!(values(&resp, "cache-control"), ["private, max-age=60"]);
        // A shareable 304 has no Set-Cookie to pass on, and its answer is the entry's.
        let rv = revalidated_as_filed(&stale().meta, &request(&[("x-new", "1")]), false, 3600);
        assert!(rv.renews());
        let resp = revalidated_response(stale(), rv);
        assert!(values(&resp, "set-cookie").is_empty());
        assert_eq!(values(&resp, "cache-control"), ["max-age=60, public"]);
    }

    /// The one test of an answer's `Vary` against the rule its entry was filed under: neither
    /// varies, or both on the same names (in any case or order, `Accept-Encoding` aside).
    #[test]
    fn same_vary_shape_matches_only_the_rule_the_entry_was_filed_under() {
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let al = names(&["accept-language"]);
        let al_user = names(&["accept-language", "x-user"]);
        for (vary, filed, same) in [
            (&[][..], None, true),
            (&["Accept-Encoding"], None, true),
            (&["X-User"], None, false),
            (&["*"], None, false),
            (&["Cookie"], None, false),
            (&[], Some(&al), false),
            (&["Accept-Encoding"], Some(&al), false),
            (&["Accept-Language"], Some(&al), true),
            (&["accept-encoding, ACCEPT-LANGUAGE"], Some(&al), true),
            (&["Accept-Language", "X-User"], Some(&al), false),
            (&["X-User, Accept-Language"], Some(&al_user), true),
            (&["Accept-Language"], Some(&al_user), false),
            (&["Accept-Language, *"], Some(&al), false),
        ] {
            let mut h = hyper::HeaderMap::new();
            for line in vary {
                h.append(hyper::header::VARY, line.parse().unwrap());
            }
            assert_eq!(
                same_vary_shape(&h, filed.map(Vec::as_slice)),
                same,
                "Vary {vary:?} against {filed:?}"
            );
        }
    }

    /// A `304` whose `Vary` is not the one the entry was filed under does not renew it, whatever
    /// else it says, and asks for the entry to be taken out. It is judged on the entry it makes:
    /// a 304 without a `Vary` keeps the stored one.
    #[test]
    fn a_304_renews_an_entry_only_under_the_vary_it_was_filed_under() {
        let filed_as = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let unvaried = cached_meta(StatusCode::OK, &request(&[("etag", "\"f1\"")])).unwrap();
        let by_language = cached_meta(StatusCode::OK, &upload_origin_headers()).unwrap();
        let public = ("cache-control", "public, max-age=60");
        for (stored, filed, not_modified, renews) in [
            // what may renew it
            (&unvaried, None, &[public][..], true),
            (
                &unvaried,
                None,
                &[public, ("vary", "Accept-Encoding")],
                true,
            ),
            (
                &by_language,
                Some(filed_as(&["accept-language"])),
                &[public],
                true,
            ),
            (
                &by_language,
                Some(filed_as(&["accept-language"])),
                &[public, ("vary", "accept-language")],
                true,
            ),
            // the origin now chooses by another header: the scenario of alice's X-Account
            (
                &unvaried,
                None,
                &[public, ("vary", "X-User"), ("x-account", "alice")],
                false,
            ),
            (
                &by_language,
                Some(filed_as(&["accept-language"])),
                &[public, ("vary", "Accept-Language, X-User")],
                false,
            ),
            (
                &by_language,
                Some(filed_as(&["accept-language"])),
                &[public, ("vary", "Accept-Language"), ("vary", "X-User")],
                false,
            ),
            // the entry's own Vary, when the key's rule is another (it changed since)
            (&by_language, None, &[public], false),
        ] {
            let rv = revalidated(stored, &request(not_modified), true, 3600, filed.as_deref());
            assert_eq!(
                (rv.renews(), rv.shareable, rv.vary_changed),
                (renews, renews, !renews),
                "{not_modified:?} on an entry filed under {filed:?}"
            );
            let resp = revalidated_response(stored_hit(&upload_origin_headers()), rv);
            let cache_control = values(&resp, "cache-control");
            assert_eq!(
                cache_control[0].starts_with("private"),
                !renews,
                "{not_modified:?}: answered as {cache_control:?}"
            );
        }
        // Not renewed for a Set-Cookie: the entry is left stale, not taken out.
        let rv = revalidated_as_filed(&unvaried, &request(&[("set-cookie", "sid=x")]), false, 3600);
        assert!(!rv.renews() && !rv.vary_changed);
    }

    /// The cache fields a cache in front of zion obeys in place of `Cache-Control`
    /// ([`is_targeted_cache_field`]), each with a value of its own: the RFC 9213 targeted fields
    /// of four CDNs and Akamai's, `Surrogate-Control`, Akamai's `Edge-Control` and nginx's
    /// `X-Accel-Expires`.
    const TARGETED: [(&str, &str); 8] = [
        ("cdn-cache-control", "max-age=600"),
        ("cloudflare-cdn-cache-control", "max-age=601"),
        ("vercel-cdn-cache-control", "max-age=602"),
        ("netlify-cdn-cache-control", "max-age=603"),
        ("akamai-cache-control", "max-age=604"),
        ("surrogate-control", "max-age=605"),
        ("edge-control", "cache-maxage=606s"),
        ("x-accel-expires", "607"),
    ];

    /// Which fields count as one a cache in front of zion obeys in place of `Cache-Control`: the
    /// targeted fields by their `-Cache-Control` suffix, and three others by name. Not
    /// `Cache-Control` itself, nor the other fields about caching a downstream cache reads beside
    /// it.
    #[test]
    fn the_targeted_cache_fields_are_the_suffix_and_three_names() {
        for (name, _) in TARGETED {
            assert!(
                is_targeted_cache_field(&hyper::header::HeaderName::from_static(name)),
                "{name}"
            );
        }
        // A CDN that names its own field after these were written.
        assert!(is_targeted_cache_field(
            &hyper::header::HeaderName::from_static("examplecdn-cache-control")
        ));
        for name in [
            "cache-control",
            "expires",
            "pragma",
            "vary",
            "age",
            "surrogate-key",
            "cdn-loop",
            "x-cache",
            "cache-status",
        ] {
            assert!(
                !is_targeted_cache_field(&hyper::header::HeaderName::from_static(name)),
                "{name}"
            );
        }
    }

    /// The answer for one client alone does not carry the cache fields a CDN in front of zion
    /// obeys instead of `Cache-Control` (RFC 9213 §2.2): with them, its `private` was read by no
    /// CDN that has one, and the CDN kept alice's answer, her `Set-Cookie` and `X-Account`, for
    /// everyone. Its `Cache-Control` is the `private` one. The entry keeps them, and a shareable
    /// `REVALIDATED` answer and a hit carry them, each field as the origin sent it.
    #[test]
    fn a_one_client_answer_carries_none_of_the_cdns_own_cache_fields() {
        let mut origin = upload_origin_headers();
        for (k, v) in TARGETED {
            origin.append(
                hyper::header::HeaderName::from_static(k),
                hyper::header::HeaderValue::from_static(v),
            );
        }
        let stale = || stored_hit(&origin);
        // Each field by name, so that one an answer keeps shows up with its value.
        let carried = |resp: &Response<ZionBody>| -> Vec<(&str, Vec<String>)> {
            TARGETED
                .iter()
                .map(|(name, _)| (*name, values(resp, name)))
                .filter(|(_, v)| !v.is_empty())
                .collect()
        };
        let all: Vec<(&str, Vec<String>)> = TARGETED
            .iter()
            .map(|(name, value)| (*name, vec![value.to_string()]))
            .collect();
        let none = Vec::<(&str, Vec<String>)>::new();
        // One client's: a Set-Cookie, an authenticated request without the opt-in, another Vary.
        for (authenticated, pairs) in [
            (
                false,
                &[("set-cookie", "sid=rotated"), ("x-account", "alice")][..],
            ),
            (true, &[("x-account", "alice")]),
            (
                true,
                &[("cache-control", "public, max-age=60"), ("vary", "X-User")],
            ),
        ] {
            let rv = revalidated_as_filed(&stale().meta, &request(pairs), authenticated, 3600);
            assert!(!rv.shareable, "{pairs:?}");
            let kept: Vec<&str> = rv
                .meta
                .headers
                .iter()
                .map(|(name, _)| name.as_str())
                .filter(|name| TARGETED.iter().any(|(targeted, _)| name == targeted))
                .collect();
            assert_eq!(
                kept,
                TARGETED.map(|(name, _)| name),
                "{pairs:?}: the entry keeps them"
            );
            let resp = revalidated_response(stale(), rv);
            assert_eq!(
                values(&resp, "cache-control"),
                ["private, max-age=60"],
                "{pairs:?}"
            );
            assert_eq!(carried(&resp), none, "{pairs:?}");
        }
        // A targeted field the 304 brings goes too.
        let rv = revalidated_as_filed(
            &stale().meta,
            &request(&[
                ("set-cookie", "sid=x"),
                ("cdn-cache-control", "max-age=60"),
                ("akamai-cache-control", "max-age=60"),
            ]),
            false,
            3600,
        );
        assert_eq!(carried(&revalidated_response(stale(), rv)), none);
        // A shareable 304: its answer is the entry's, CDN fields included.
        let rv = revalidated_as_filed(&stale().meta, &request(&[("x-new", "1")]), false, 3600);
        assert!(rv.renews());
        let resp = revalidated_response(stale(), rv);
        assert_eq!(values(&resp, "x-zion-cache"), ["REVALIDATED"]);
        assert_eq!(values(&resp, "cache-control"), ["max-age=60, public"]);
        assert_eq!(carried(&resp), all);
        // A hit too.
        let hit = cache_response(stale(), "HIT");
        assert_eq!(values(&hit, "cache-control"), ["max-age=60, public"]);
        assert_eq!(carried(&hit), all);
    }

    /// A revalidation is conditional on what zion stored and on nothing of the client's: its own
    /// preconditions and its `Range` are taken out before zion's validators go in, for an entry
    /// with both validators, with one, and with the client sending none.
    #[test]
    fn a_revalidation_carries_the_stored_validators_and_none_of_the_clients() {
        let clients = [
            ("if-none-match", "*"),
            ("if-modified-since", "Sat, 01 Jan 2000 00:00:00 GMT"),
            ("if-match", "\"x\""),
            ("if-unmodified-since", "Sat, 01 Jan 2000 00:00:00 GMT"),
            ("if-range", "\"x\""),
            ("range", "bytes=0-0"),
            ("accept-language", "de"),
        ];
        let lm = "Thu, 01 Jan 2026 00:00:00 GMT";
        for (etag, last_modified) in [
            (Some("\"u1\""), Some(lm)),
            (None, Some(lm)),
            (Some("\"u1\""), None),
        ] {
            let mut origin = request(&[("cache-control", "max-age=60")]);
            if let Some(etag) = etag {
                origin.insert(hyper::header::ETAG, etag.parse().unwrap());
            }
            if let Some(lm) = last_modified {
                origin.insert(hyper::header::LAST_MODIFIED, lm.parse().unwrap());
            }
            let meta = cached_meta(StatusCode::OK, &origin).unwrap();
            for sent in [request(&clients), request(&[("accept-language", "de")])] {
                let mut h = sent;
                add_conditional_headers(&mut h, &meta);
                let get = |name: &str| h.get(name).map(|v| v.to_str().unwrap());
                assert_eq!(get("if-none-match"), etag, "{etag:?} {last_modified:?}");
                assert_eq!(get("if-modified-since"), last_modified);
                for name in ["if-match", "if-unmodified-since", "if-range", "range"] {
                    assert_eq!(get(name), None, "the client's {name}");
                }
                assert_eq!(get("accept-language"), Some("de"), "the rest is kept");
            }
        }
    }

    /// What an entry may not be refreshed in the background without is exactly what the refresh
    /// leaves out: one list, with every header zion asserts about the caller (the auth gate's
    /// identity, the mesh score, the client certificate, the TLS fingerprint) and the client's
    /// credentials and preconditions, and nothing a client's content negotiation needs.
    #[test]
    fn the_refresh_leaves_out_exactly_what_swr_drops_names() {
        use crate::reserved_headers::{Asserter, RESERVED_HEADERS};
        let mut names = vec![
            "authorization",
            "cookie",
            "proxy-authorization",
            "if-none-match",
            "if-modified-since",
            "if-match",
            "if-unmodified-since",
            "if-range",
            "range",
            "content-length",
            "transfer-encoding",
            "accept",
            "accept-language",
            "accept-encoding",
            "user-agent",
            "origin",
            "x-custom",
        ];
        names.extend(RESERVED_HEADERS.iter().map(|(name, _)| *name));
        let mut b = Request::builder().method(hyper::Method::GET).uri("/feed");
        for name in &names {
            b = b.header(*name, "1");
        }
        let req = b
            .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
            .unwrap();
        let out = swr_request(&req);
        for name in &names {
            assert_eq!(
                out.headers().contains_key(*name),
                !swr_drops(name),
                "{name}: sent by the refresh, or what an entry is checked against"
            );
        }
        for (name, asserter) in RESERVED_HEADERS {
            assert_eq!(
                swr_drops(name),
                asserter != Asserter::TrustedProxy,
                "{name} ({asserter:?})"
            );
        }
        for name in [
            "authorization",
            "cookie",
            "x-auth-subject",
            "x-client-tls-ja4",
        ] {
            assert!(swr_drops(name), "{name}");
        }
        for name in [
            "accept",
            "accept-language",
            "accept-encoding",
            "origin",
            "x-custom",
        ] {
            assert!(!swr_drops(name), "{name}");
        }
    }

    /// The entry keeps the origin's `Date` (with `Expires`, the lifetime it gave). A `304` that
    /// renews it brings its own; one without a `Date` leaves none, rather than the old one beside
    /// the 304's `Age`, which would make the answer as old as the first `200` downstream.
    #[test]
    fn a_304s_date_replaces_the_stored_one_and_a_304_without_one_leaves_none() {
        let stored = cached_meta(StatusCode::OK, &upload_origin_headers()).unwrap();
        let date = |meta: &cache::CachedMeta| -> Vec<String> {
            meta.headers
                .iter()
                .filter(|(name, _)| *name == hyper::header::DATE)
                .map(|(_, v)| v.to_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(date(&stored), ["Thu, 01 Jan 2026 00:00:00 GMT"], "kept");
        let rv = revalidated_as_filed(
            &stored,
            &request(&[("date", "Fri, 02 Jan 2026 00:00:00 GMT")]),
            false,
            3600,
        );
        assert_eq!(date(&rv.meta), ["Fri, 02 Jan 2026 00:00:00 GMT"]);
        let rv = revalidated_as_filed(&stored, &request(&[("etag", "\"u1\"")]), false, 3600);
        assert!(date(&rv.meta).is_empty(), "{:?}", date(&rv.meta));
    }

    /// The bound on what an entry keeps counts the fields of their own: a stored `ETag` near the
    /// bound and the headers a `304` adds go over it together.
    #[test]
    fn a_304_whose_headers_and_the_stored_etag_go_over_the_bound_is_not_kept() {
        let big_etag = format!("\"{}\"", "e".repeat(cache::MAX_STORED_HEADER_BYTES - 2_000));
        let stored = cached_meta(
            StatusCode::OK,
            &request(&[("etag", big_etag.as_str()), ("cache-control", "max-age=60")]),
        )
        .expect("fits on its own");
        let extra = "x".repeat(3_000);
        let rv = revalidated_as_filed(
            &stored,
            &request(&[("x-extra", extra.as_str())]),
            false,
            3600,
        );
        assert!(rv.shareable && !rv.fits && !rv.renews());
    }

    /// The background refresh is the cache's request, not the caller's: what zion asserts about
    /// the caller (the auth gate's identity, the mesh score, the verified client certificate)
    /// stays behind with the credentials.
    #[test]
    fn a_background_refresh_does_not_carry_what_zion_asserts_about_the_caller() {
        use crate::reserved_headers::{reserved, Asserter};
        let mut b = Request::builder().method(hyper::Method::GET).uri("/feed");
        let asserted: Vec<&str> = reserved(Asserter::Pipeline)
            .chain(reserved(Asserter::Transport))
            .collect();
        for name in &asserted {
            b = b.header(*name, "alice");
        }
        for (k, v) in [
            ("authorization", "Bearer alice"),
            ("cookie", "sid=alice"),
            ("if-none-match", "\"v0\""),
            ("accept-language", "de"),
            ("accept-encoding", "br"),
        ] {
            b = b.header(k, v);
        }
        let req = b
            .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
            .unwrap();
        let out = swr_request(&req);
        for name in asserted
            .iter()
            .chain(&["authorization", "cookie", "if-none-match"])
        {
            assert!(
                out.headers().get(*name).is_none(),
                "the refresh sends {name}"
            );
        }
        assert_eq!(out.headers().get("accept-language").unwrap(), "de");
        assert_eq!(out.headers().get("accept-encoding").unwrap(), "br");
    }

    #[test]
    fn client_conditional_304_matching() {
        let meta = |etag: Option<&str>, lm: Option<&str>| cache::CachedMeta {
            content_type: None,
            content_encoding: None,
            status: hyper::StatusCode::OK,
            etag: etag.map(|e| e.parse().unwrap()),
            last_modified: lm.map(|l| l.parse().unwrap()),
            stale_while_revalidate_secs: 0,
            must_revalidate: false,
            headers: Vec::new(),
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
        // If-Modified-Since (RFC 9110 13.1.3, #744): 304 when stored Last-Modified <= the date.
        let d = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert!(client_conditional_hit(
            &req(IF_MODIFIED_SINCE, d),
            &meta(None, Some(d))
        ));
        // A later date still means not modified since → 304.
        assert!(client_conditional_hit(
            &req(IF_MODIFIED_SINCE, "Mon, 07 Nov 1994 00:00:00 GMT"),
            &meta(None, Some(d))
        ));
        // An earlier date means it was modified since → not 304.
        assert!(!client_conditional_hit(
            &req(IF_MODIFIED_SINCE, "Sat, 05 Nov 1994 00:00:00 GMT"),
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

    #[test]
    fn trace_id_hex_is_32_lowercase_hex() {
        // All-zero and a known pattern → exact 32-hex, lowercase, matching the
        // W3C traceparent trace-id rendering used in the header.
        assert_eq!(trace_id_to_hex(&[0u8; 16]), "0".repeat(32));
        let bytes: [u8; 16] = [
            0x0a, 0xf7, 0x65, 0x19, 0x16, 0xcd, 0x43, 0xdd, 0x84, 0x48, 0xeb, 0x21, 0x1c, 0x80,
            0x31, 0x9c,
        ];
        let hex = trace_id_to_hex(&bytes);
        assert_eq!(hex, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(hex.len(), 32);
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn scrubs_client_spoofed_identity_headers() {
        // A client sends the reserved identity headers Zion owns — in mixed
        // case and duplicated. All copies must be gone after the scrub, so a
        // route with no auth profile (or a build without the auth gate) can
        // never forward a spoofed identity upstream.
        let mut h = hyper::HeaderMap::new();
        h.append("X-Auth-Subject", "attacker".parse().unwrap());
        h.append("x-auth-subject", "attacker2".parse().unwrap());
        h.insert("X-AUTH-EMAIL", "evil@example.com".parse().unwrap());
        h.insert("X-Forwarded-For", "203.0.113.1".parse().unwrap());

        scrub_reserved_identity_headers(&mut h);

        assert!(h.get("x-auth-subject").is_none(), "subject not stripped");
        assert!(h.get("x-auth-email").is_none(), "email not stripped");
        assert_eq!(
            h.get_all("x-auth-subject").iter().count(),
            0,
            "duplicate copies must all be removed"
        );
        // Unrelated headers are untouched.
        assert_eq!(
            h.get("x-forwarded-for").unwrap(),
            "203.0.113.1",
            "scrub must not touch other headers"
        );
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

    /// The LRU tests drive the cache by number: entry `k` is the hostless path `/k` in slot `k`.
    fn put(c: &mut route_cache::RouteCache<u32>, k: u64, v: u32) {
        c.insert(k, None, &format!("/{k}"), v);
    }

    fn hit(c: &mut route_cache::RouteCache<u32>, k: u64) -> Option<u32> {
        c.get(k, None, &format!("/{k}"))
    }

    #[test]
    fn route_lru_get_returns_inserted_value() {
        let mut c = route_cache::RouteCache::<u32>::new(4);
        put(&mut c, 1, 100);
        assert_eq!(hit(&mut c, 1), Some(100));
        assert_eq!(hit(&mut c, 2), None);
    }

    #[test]
    fn route_lru_get_promotes_to_mru() {
        let mut c = route_cache::RouteCache::<u32>::new(4);
        put(&mut c, 1, 10);
        put(&mut c, 2, 20);
        put(&mut c, 3, 30);
        // Order LRU→MRU: 1, 2, 3
        assert_eq!(c.order(), vec![1, 2, 3]);
        // Touch key 1: it should move to MRU.
        let _ = hit(&mut c, 1);
        assert_eq!(c.order(), vec![2, 3, 1]);
    }

    #[test]
    fn route_lru_insert_existing_key_updates_and_promotes() {
        let mut c = route_cache::RouteCache::<u32>::new(4);
        put(&mut c, 1, 10);
        put(&mut c, 2, 20);
        put(&mut c, 1, 11); // update + promote to MRU
        assert_eq!(hit(&mut c, 1), Some(11));
        assert_eq!(c.order(), vec![2, 1]);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn route_lru_evicts_lru_at_capacity() {
        let mut c = route_cache::RouteCache::<u32>::new(3);
        put(&mut c, 1, 10);
        put(&mut c, 2, 20);
        put(&mut c, 3, 30);
        put(&mut c, 4, 40); // forces eviction of 1 (LRU)
        assert_eq!(c.len(), 3);
        assert_eq!(hit(&mut c, 1), None, "1 should have been evicted");
        assert_eq!(c.order(), vec![2, 3, 4]);
    }

    #[test]
    fn route_lru_recency_preserved_under_mixed_access() {
        // Touch promotes; new insert evicts the genuinely least-recently-used.
        let mut c = route_cache::RouteCache::<u32>::new(3);
        put(&mut c, 1, 10);
        put(&mut c, 2, 20);
        put(&mut c, 3, 30);
        let _ = hit(&mut c, 1); // 1 → MRU; LRU order now: 2, 3, 1
        put(&mut c, 4, 40); // evict LRU=2
        assert_eq!(hit(&mut c, 2), None);
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
            put(&mut c, k, k as u32);
        }
        assert_eq!(c.len(), cap);
        // A new hot path arrives:
        put(&mut c, 9999, 0xBEEF);
        assert_eq!(
            hit(&mut c, 9999),
            Some(0xBEEF),
            "hot path must be cacheable"
        );
        assert_eq!(c.len(), cap, "capacity bound must hold");
        // The LRU (key 0) is the one that was evicted, not the new one.
        assert_eq!(hit(&mut c, 0), None);
    }

    #[test]
    fn route_lru_capacity_bound_holds_under_heavy_insert() {
        let cap = 16;
        let mut c = route_cache::RouteCache::<u32>::new(cap);
        for k in 0..1024u64 {
            put(&mut c, k, k as u32);
            assert!(c.len() <= cap, "capacity must never be exceeded");
        }
        // The most recently inserted `cap` keys must all be present.
        for k in (1024 - cap as u64)..1024 {
            assert_eq!(hit(&mut c, k), Some(k as u32));
        }
    }

    #[test]
    fn route_lru_node_recycling_stays_bounded() {
        // Repeated insert-then-evict cycles must not grow `nodes` unbounded.
        // The free-list recycles indices; this test exercises that path.
        let cap = 4;
        let mut c = route_cache::RouteCache::<u32>::new(cap);
        for k in 0..1000u64 {
            put(&mut c, k, k as u32);
        }
        assert_eq!(c.len(), cap);
        // Last 4 inserts must be the survivors, in MRU order.
        assert_eq!(c.order(), vec![996, 997, 998, 999]);
    }

    /// Two requests whose hash is the same slot are still two requests: a lookup returns only
    /// the value cached for its own `(host, path)`, never the one another request left in the
    /// slot. A hash-only hit served a path under another route's `internal_only`, auth and WAF
    /// policy, given a colliding pair (unseeded FNV, computable offline).
    #[test]
    fn route_lru_a_colliding_slot_is_a_miss_not_another_routes_value() {
        let mut c = route_cache::RouteCache::<u32>::new(4);
        c.insert(7, None, "/public", 1);
        assert_eq!(
            c.get(7, None, "/protected"),
            None,
            "another path, same slot"
        );
        assert_eq!(c.get(7, Some("a.example"), "/public"), None, "another host");
        assert_eq!(c.get(7, None, "/public"), Some(1), "the slot's own request");
        // the colliding request is resolved and cached: the slot is now its own
        c.insert(7, None, "/protected", 2);
        assert_eq!(c.get(7, None, "/protected"), Some(2));
        assert_eq!(c.get(7, None, "/public"), None);
        assert_eq!(c.len(), 1);
        // a host-scoped entry is not the hostless one either
        c.insert(8, Some("a.example"), "/x", 3);
        assert_eq!(c.get(8, None, "/x"), None);
        assert_eq!(c.get(8, Some("b.example"), "/x"), None);
        assert_eq!(c.get(8, Some("a.example"), "/x"), Some(3));
        // host and path are kept in one allocation: the same bytes split elsewhere differ
        c.insert(9, Some("ab"), "/x", 4);
        assert_eq!(c.get(9, Some("a"), "b/x"), None);
        assert_eq!(c.get(9, Some("ab/"), "x"), None);
        assert_eq!(c.get(9, None, "ab/x"), None);
        assert_eq!(c.get(9, Some("ab"), "/x"), Some(4));
    }

    /// The pair `gate_order_tests` uses for the end-to-end case really is one slot under the
    /// real hash, so that test exercises a collision and not two separate slots.
    #[test]
    fn the_crafted_route_cache_pair_collides_under_the_real_hash() {
        assert_eq!(
            route_cache_key(None, "/00b762d743310b77"),
            route_cache_key(None, "/ad7c78d3fbb7b504")
        );
    }

    /// Each entry keeps its key, so a key over the length cap is not kept: a flood of long
    /// distinct paths cannot make a worker thread hold 256 of them.
    #[test]
    fn route_lru_does_not_keep_a_key_over_the_length_cap() {
        let mut c = route_cache::RouteCache::<u32>::new(4);
        let cap = route_cache::ROUTE_CACHE_MAX_KEY_LEN;
        let at_cap = format!("/{}", "a".repeat(cap - 1));
        let over = format!("/{}", "a".repeat(cap));
        c.insert(1, None, &at_cap, 1);
        c.insert(2, None, &over, 2);
        c.insert(3, Some("h.example"), &at_cap, 3); // the host counts too
        assert_eq!(c.get(1, None, &at_cap), Some(1));
        assert_eq!(c.get(2, None, &over), None);
        assert_eq!(c.get(3, Some("h.example"), &at_cap), None);
        assert_eq!(c.len(), 1);
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
