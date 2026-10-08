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
//!      in main.rs, before this pipeline — unrated by design: liveness
//!      checks must answer even when the box is saturated.)
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
use crate::http_util::ZionBody;
use crate::http_util::{
    empty_response, generate_request_id, inject_security_headers, text_response, HEX_DIGITS,
    REQUEST_COUNTER,
};
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
use http_body_util::Limited;

mod gates;
mod route;
mod telemetry;
mod waf_gate;
pub(crate) use gates::uri_too_long;

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
/// over a slow-but-steady link is not penalised.
const BODY_FRAME_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Total timeout for buffering a request body on the non-streaming path (the
/// smaller default bodies). A trickled body trips this long before a legit
/// upload near `max_body_mb` would.
const BODY_COLLECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// What a failed read of the request body means. `Limited` reports overflow as a
/// `LengthLimitError`; anything else is the client's stream breaking (reset,
/// malformed chunked framing, a connection that dropped). Telling them apart keeps
/// `413` meaning "too large", and the cause goes to the log because the response
/// only says what the client needs to know.
fn body_read_failure(
    e: &(dyn std::error::Error + Send + Sync + 'static),
) -> (StatusCode, &'static str) {
    if e.downcast_ref::<http_body_util::LengthLimitError>()
        .is_some()
    {
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
    req: Request<ZionBody>,
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
    let access = telemetry::capture(&cfg, &state, &req);

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

    // Alt-Svc: advertise HTTP/3 to clients (zero cost if feature disabled)
    #[cfg(feature = "http3")]
    resp.headers_mut()
        .insert("Alt-Svc", crate::quic::ALT_SVC_H3.clone());

    Ok(resp)
}

/// Mark the request with what the forwarding paths need to know about its route.
fn mark_request_for_forwarding(req: &mut Request<ZionBody>, rule: &ResolvedRoute) {
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
    mut req: Request<ZionBody>,
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
    )
    .await?;
    if let Some(entry) = &breaker_up {
        breaker_record(entry, resp.status(), breaker_probe);
    }
    inject_security_headers(&mut resp);
    Ok(resp)
}

/// Hand the request to the handler its route calls for.
#[allow(clippy::too_many_arguments)]
async fn dispatch_by_mode(
    req: Request<ZionBody>,
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
        handle_static_cache(
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
                handle_static_cache(
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
    match state.static_cache.vary.get(primary) {
        Some(rule) => vary::variant_key(primary, &rule.names, headers),
        None => Some(primary.to_string()),
    }
}

/// Everything a background stale-while-revalidate refresh needs, owned so it can
/// outlive the request that triggered it.
struct SwrRefresh {
    state: Arc<AppState>,
    key: Arc<str>,
    /// `key` is a shared identity entry (#484): an encoded refresh must not overwrite it.
    identity_entry: bool,
    /// The primary key `key` was derived from (they are equal unless the key varies).
    primary_key: Arc<str>,
    stale: cache::CacheHit,
    request: Request<ZionBody>,
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

/// The request a background refresh sends: the same target and content
/// negotiation as the one that found the entry stale, but NOT the caller's
/// credentials. The refresh is on behalf of the cache, not of that client, so
/// `Authorization` / `Cookie` / `Proxy-Authorization` and any conditional or range
/// header are dropped (the stored validators are added when it is sent).
fn swr_request(req: &Request<ZionBody>) -> Request<ZionBody> {
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
        if matches!(
            *name,
            hyper::header::AUTHORIZATION
                | hyper::header::COOKIE
                | hyper::header::PROXY_AUTHORIZATION
                | hyper::header::IF_NONE_MATCH
                | hyper::header::IF_MODIFIED_SINCE
                | hyper::header::IF_MATCH
                | hyper::header::IF_UNMODIFIED_SINCE
                | hyper::header::IF_RANGE
                | hyper::header::RANGE
                | hyper::header::CONTENT_LENGTH
                | hyper::header::TRANSFER_ENCODING
        ) {
            continue;
        }
        out.headers_mut().append(name.clone(), value.clone());
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
        let ok = tokio::time::timeout(budget, run_swr_refresh(&job))
            .await
            .unwrap_or(false);
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

/// One refresh: a conditional GET with the stored validators. A `304` revives the
/// stored body; a cacheable `200` replaces it. Anything else leaves the stale entry
/// as it is (it is no longer served stale once outside its window).
async fn run_swr_refresh(job: &SwrRefresh) -> bool {
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
            return false;
        }
    };
    if let Some(entry) = &job.breaker {
        // No probe token: a refresh counts toward the failure window while the circuit is
        // closed, and is ignored when it is not.
        breaker_record(entry, resp.status(), None);
    }

    if resp.status() == StatusCode::NOT_MODIFIED {
        let initial_age = upstream_age(resp.headers());
        let ttl = origin_freshness(resp.headers())
            .map(|o| o.min(job.cache_ttl))
            .unwrap_or(job.cache_ttl);
        let mut meta = (*job.stale.meta).clone();
        if resp.headers().contains_key(hyper::header::CACHE_CONTROL) {
            meta.stale_while_revalidate_secs = origin_swr(resp.headers());
            meta.must_revalidate = forbids_stale(resp.headers());
        }
        // Not revived if a tag purge ran since this refresh was scheduled (it may have removed
        // the very entry being revalidated).
        if !job.state.static_cache.refresh_checked(
            &job.key,
            job.stale.body.clone(),
            meta,
            ttl,
            initial_age,
            job.cache_max,
            job.tag_epoch,
        ) {
            return false;
        }
        metrics::METRICS
            .cache_revalidations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return true;
    }
    if resp.status() != StatusCode::OK {
        return false;
    }

    let (parts, body) = resp.into_parts();
    let initial_age = upstream_age(&parts.headers);
    let ttl = origin_freshness(&parts.headers)
        .map(|o| o.min(job.cache_ttl))
        .unwrap_or(job.cache_ttl);
    // The refresh carries no credentials, so the request is not "authenticated".
    if !is_shared_cacheable(false, &parts.headers, ttl, initial_age) {
        return false;
    }
    // It refreshes ONE entry. If the origin's Vary no longer matches what that entry
    // was keyed on, the new body belongs to a different key: leave the old entry alone.
    let rule = job.state.static_cache.vary.get(&job.primary_key);
    let same_shape = match (vary::policy(&parts.headers), rule) {
        (vary::VaryPolicy::None, None) => true,
        (vary::VaryPolicy::Keyed(names), Some(rule)) => names == rule.names,
        _ => false,
    };
    // A shared identity entry is found by every Accept-Encoding: an encoded body must
    // never replace it (it would reach clients that did not accept that encoding).
    if !same_shape || (job.identity_entry && !shareable_identity(&parts.headers)) {
        return false;
    }
    let Ok(collected) = http_body_util::Limited::new(body, job.max_object)
        .collect()
        .await
    else {
        return false;
    };
    let meta = cache::CachedMeta {
        content_type: parts.headers.get(hyper::header::CONTENT_TYPE).cloned(),
        content_encoding: parts.headers.get(hyper::header::CONTENT_ENCODING).cloned(),
        status: parts.status,
        etag: parts.headers.get(hyper::header::ETAG).cloned(),
        last_modified: parts.headers.get(hyper::header::LAST_MODIFIED).cloned(),
        stale_while_revalidate_secs: origin_swr(&parts.headers),
        must_revalidate: forbids_stale(&parts.headers),
    };
    // The refreshed response may carry new tags; one that cannot be tracked is not stored.
    let Ok(tags) = cache::surrogate_keys(&parts.headers) else {
        return false;
    };
    let stored = job.state.static_cache.insert_tagged(
        &job.key,
        collected.to_bytes(),
        meta,
        ttl,
        initial_age,
        job.cache_max,
        &tags,
        job.tag_epoch,
    );
    if stored == cache::TagStore::IndexFull {
        metrics::METRICS
            .cache_tag_uncached
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    stored == cache::TagStore::Stored
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
    headers
        .get_all(hyper::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|d| {
            let name = d.split('=').next().unwrap_or("").trim();
            name.eq_ignore_ascii_case("must-revalidate")
                || name.eq_ignore_ascii_case("proxy-revalidate")
                || name.eq_ignore_ascii_case("s-maxage")
        })
}

/// `stale-while-revalidate=N` (RFC 5861 §3) from a response's `Cache-Control`, in
/// seconds, capped at [`MAX_SWR_SECS`]. `0` when absent or unparsable.
fn origin_swr(headers: &hyper::HeaderMap) -> u64 {
    let Some(cc) = headers
        .get(hyper::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    else {
        return 0;
    };
    for part in cc.to_ascii_lowercase().split(',') {
        if let Some(rest) = part.trim().strip_prefix("stale-while-revalidate") {
            if let Some(val) = rest.trim_start().strip_prefix('=') {
                if let Ok(secs) = val.trim().trim_matches('"').parse::<u64>() {
                    return secs.min(MAX_SWR_SECS);
                }
            }
        }
    }
    0
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

    // A response that sets a cookie starts or alters a session: its body is for that
    // client. Cached hits do not replay headers, but they would replay the body to
    // everyone, so it is never stored in the shared cache (what nginx and Varnish do by
    // default). The client that triggered it still gets the response, cookie included.
    if resp_headers.contains_key(hyper::header::SET_COOKIE) {
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
    // The validators the client echoes back (If-None-Match / If-Range), as the origin sent them.
    if let Some(etag) = &hit.meta.etag {
        builder = builder.header(hyper::header::ETAG, etag.clone());
    }
    if let Some(lm) = &hit.meta.last_modified {
        builder = builder.header(hyper::header::LAST_MODIFIED, lm.clone());
    }
    // A fresh hit answers `Range` itself (see `ranged_hit_response`): say so.
    if disposition == "HIT" && hit.meta.status == StatusCode::OK {
        builder = builder.header(hyper::header::ACCEPT_RANGES, "bytes");
    }
    builder
        .body(Full::new(hit.body).map_err(|never| match never {}).boxed())
        .unwrap()
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
    let mut builder = Response::builder()
        .header("Cache-Control", profile_cache_control(hit.max_age_secs))
        .header("X-Zion-Cache", "HIT")
        .header(hyper::header::AGE, hit.age_secs)
        .header(hyper::header::ACCEPT_RANGES, "bytes");
    if let Some(ct) = &hit.meta.content_type {
        builder = builder.header(hyper::header::CONTENT_TYPE, ct.clone());
    }
    if let Some(ce) = &hit.meta.content_encoding {
        builder = builder.header(hyper::header::CONTENT_ENCODING, ce.clone());
    }
    if let Some(etag) = &hit.meta.etag {
        builder = builder.header(hyper::header::ETAG, etag.clone());
    }
    if let Some(lm) = &hit.meta.last_modified {
        builder = builder.header(hyper::header::LAST_MODIFIED, lm.clone());
    }
    match static_files::parse_range(headers.get(hyper::header::RANGE), total) {
        RangeOutcome::Full => None,
        RangeOutcome::Unsatisfiable => Some(
            builder
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(hyper::header::CONTENT_RANGE, format!("bytes */{total}"))
                .body(
                    Full::new(Bytes::new())
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap(),
        ),
        RangeOutcome::Satisfiable(start, end) => Some(
            builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(
                    hyper::header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{total}"),
                )
                .body(
                    Full::new(hit.body.slice(start as usize..=end as usize))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap(),
        ),
    }
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

#[allow(clippy::too_many_arguments)]
async fn handle_static_cache(
    mut req: Request<ZionBody>,
    state: Arc<AppState>,
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    dyn_scheme: &hyper::http::uri::Scheme,
    dyn_authority: &hyper::http::uri::Authority,
    xff_mode: proxy::XffMode,
    breaker: Option<Arc<health::UpstreamHealth>>,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Read before anything is fetched: a tag purge after this point keeps the response out.
    let tag_epoch = state.static_cache.tag_epoch();
    // Only GET is cacheable. HEAD/POST/PUT/PATCH/DELETE/OPTIONS must bypass the
    // cache and never populate it: the cache key is the path (no method), so a
    // non-GET 200 stored under it — a HEAD's empty body, or a POST response —
    // would later be served to a GET (method-confusion cache poisoning).
    if *req.method() != hyper::Method::GET {
        // RFC 9111 §4.4: a successful unsafe request invalidates the cached responses
        // for its target URI, and for the URIs its answer names in `Location` /
        // `Content-Location` when they are on the same origin. Capture what that needs
        // before `req` is consumed.
        let invalidating = matches!(
            *req.method(),
            hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH | hyper::Method::DELETE
        );
        let target_path = req.uri().path().to_string();
        let request_host = crate::security::request_host(&req).map(|h| h.to_ascii_lowercase());
        // The circuit guards writes to the upstream too: there is no stale copy to offer.
        let probe = match breaker.as_deref().map(breaker_admit) {
            Some(Err(ms)) => return Ok(circuit_open_response(ms)),
            Some(Ok(p)) => p,
            None => None,
        };
        let resp = proxy::proxy_pass(
            &state.client_for(rule.client_spec()),
            req,
            dyn_scheme,
            dyn_authority,
            Some(remote_addr),
            "https",
            xff_mode,
        )
        .await?;
        if let Some(entry) = &breaker {
            breaker_record(entry, resp.status(), probe);
        }
        if invalidating && resp.status().as_u16() < 400 {
            let mut removed = state.static_cache.invalidate_path(&target_path);
            for path in named_same_origin_paths(resp.headers(), request_host.as_deref()) {
                if path != target_path {
                    removed += state.static_cache.invalidate_path(&path);
                }
            }
            if removed > 0 {
                metrics::METRICS
                    .cache_invalidations
                    .fetch_add(removed as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        return Ok(resp);
    }

    // Cache TTL / capacity from the profile (mode=StaticCache without an
    // explicit profile uses the conservative 1h default; see config::default_ttl).
    let (cache_ttl, cache_max, max_object) = match &rule.cache {
        Some(cp) => (
            cp.ttl_seconds,
            cp.max_entries,
            usize::try_from(cp.max_object_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX),
        ),
        // Conservative fallback (1h) for a static_cache route with no resolved
        // profile — never the old 1-year freeze. See config::default_ttl.
        None => (3600, 10_000, DEFAULT_MAX_OBJECT_BYTES),
    };
    let normalize_query = rule.cache.as_ref().is_some_and(|cp| cp.normalize_query);

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
    // With `normalize_query` the key carries the parameters in a canonical order; the
    // request itself (and so what the upstream is sent) is untouched. Such keys end in a
    // `\x1d` mode marker, which no request can produce, so they never share a namespace
    // with raw-query keys: the cache survives a config reload, and switching the option
    // must not let a raw request be served an entry filed under a sorted key (or the other
    // way round).
    let (key_target, mode_marker): (Cow<'_, str>, &str) = match (normalize_query, req.uri().query())
    {
        (true, Some(q)) => (
            match uri_norm::sorted_query(q) {
                Cow::Borrowed(_) => Cow::Borrowed(pq),
                Cow::Owned(sorted) => Cow::Owned(format!("{}?{sorted}", req.uri().path())),
            },
            "\u{1d}nq",
        ),
        _ => (Cow::Borrowed(pq), ""),
    };
    // The response cache is shared by every route and host, so the key carries the
    // request's host, normalised exactly as host routing sees it (case, port, trailing
    // dot; HTTP/2 `:authority` or HTTP/1 `Host`): two hosts with the same path are two
    // entries, whether they reach two origins or one multi-tenant origin. It goes last,
    // after a `\x1b` no request can produce, so path invalidation and prefix purges,
    // which match on the leading `path\x1f`, still reach every host's entry.
    let host_marker = match crate::security::request_host(&req) {
        Some(h) => format!("\u{1b}{h}"),
        None => String::new(),
    };
    let primary_key = format!(
        "{key_target}\u{1f}{}{mode_marker}{host_marker}",
        accept_encoding_key(req.headers())
    );
    // A response that is the same bytes for every client (no content coding, not chosen by
    // Accept-Encoding) is stored once, under a shared identity key, and found from any
    // `Accept-Encoding` (#484). The `\x1c` in its place cannot come from a request (header
    // values carry no control characters), so it never collides with the own key of a
    // client that sent no Accept-Encoding. It is per host like every other key.
    let identity_primary = format!("{key_target}\u{1f}\u{1c}{mode_marker}{host_marker}");
    let takes_identity = !refuses_identity(req.headers());
    // If this primary key's responses vary (RFC 9111 §4.1), the entry for THIS request
    // lives under a secondary key built from the varied request headers.
    let Some(cache_key) = lookup_key(&state, &primary_key, req.headers()) else {
        // A varied request header too long to key on: do not touch the cache. The circuit
        // still applies to the origin fetch (there is no stale entry to fall back on).
        let probe = match breaker.as_deref().map(breaker_admit) {
            Some(Err(ms)) => return Ok(circuit_open_response(ms)),
            Some(Ok(p)) => p,
            None => None,
        };
        let mut resp = proxy::proxy_pass(
            &state.client_for(rule.client_spec()),
            req,
            dyn_scheme,
            dyn_authority,
            Some(remote_addr),
            "https",
            xff_mode,
        )
        .await?;
        if let Some(entry) = &breaker {
            breaker_record(entry, resp.status(), probe);
        }
        resp.headers_mut().insert(
            "X-Zion-Cache",
            hyper::header::HeaderValue::from_static("BYPASS"),
        );
        return Ok(resp);
    };

    // Where the shared identity entry for this request would live.
    let identity_key: Option<String> = if takes_identity {
        lookup_key(&state, &identity_primary, req.headers())
    } else {
        None
    };
    // Look the request up under its own key, then under the identity key. Returns the
    // outcome and the key (and primary key) it was found under.
    let find = |state: &AppState| -> (cache::CacheLookup, String, String) {
        let own = state.static_cache.get(&cache_key);
        match (&own, &identity_key) {
            (cache::CacheLookup::Miss, Some(ik)) => (
                state.static_cache.get(ik),
                ik.clone(),
                identity_primary.clone(),
            ),
            _ => (own, cache_key.clone(), primary_key.clone()),
        }
    };

    // only-if-cached (§5.2.1.7): serve from cache or 504 — never fetch.
    if rcc_only_if_cached {
        return Ok(match find(&state).0 {
            // only-if-cached (§5.2.1.7) must not contact the origin, so a stale
            // stored response can't be revalidated → 504, same as a miss.
            cache::CacheLookup::Fresh(hit) => fresh_hit_response(hit, req.method(), req.headers()),
            _ => cache_only_if_cached_miss(),
        });
    }

    // RAM lookup. `Fresh` → zero-copy serve. `Stale` → keep the body and
    // revalidate with the origin below (RFC 9111 §4.3) instead of refetching.
    // `Miss` → fall through to a full fetch. Skipped when the client demanded a
    // fresh response (`no-cache` / `no-store`).
    let mut revalidate: Option<cache::CacheHit> = None;
    // Any stale entry found, validators or not: what an open circuit can fall back on.
    let mut stale_entry: Option<cache::CacheHit> = None;
    // The key the entry being revalidated lives under (its own key or the identity key).
    let mut found_key: String = cache_key.clone();
    if !rcc_no_cache && !rcc_no_store {
        let (outcome, at_key, at_primary) = find(&state);
        found_key = at_key.clone();
        match outcome {
            cache::CacheLookup::Fresh(hit) => {
                // 304 on a matching precondition (RFC 9110 §13), else a Range slice, else all
                return Ok(fresh_hit_response(hit, req.method(), req.headers()));
            }
            cache::CacheLookup::Stale(hit) => {
                stale_entry = Some(hit.clone());
                // stale-while-revalidate (RFC 5861): inside the window the origin
                // offered, answer NOW with the stale copy and refresh in the
                // background, so the client does not wait for the origin.
                // `age_secs` is whole seconds (floored), so the real staleness is in
                // [staleness, staleness + 1): `<` keeps us from ever serving past the
                // window the origin allowed.
                let staleness = hit.age_secs.saturating_sub(hit.max_age_secs);
                if hit.meta.stale_while_revalidate_secs > 0
                    && !hit.meta.must_revalidate
                    && staleness < hit.meta.stale_while_revalidate_secs
                {
                    if client_conditional_hit(req.headers(), &hit.meta) {
                        return Ok(not_modified_response(&hit));
                    }
                    let refresh = SwrRefresh {
                        state: state.clone(),
                        key: Arc::from(at_key.as_str()),
                        identity_entry: at_primary == identity_primary,
                        primary_key: Arc::from(at_primary.as_str()),
                        stale: hit.clone(),
                        request: swr_request(&req),
                        client_spec: rule.client_spec(),
                        scheme: dyn_scheme.clone(),
                        authority: dyn_authority.clone(),
                        remote_addr,
                        xff_mode,
                        cache_ttl,
                        cache_max,
                        tag_epoch: state.static_cache.tag_epoch(),
                        max_object,
                        breaker: breaker.clone(),
                    };
                    spawn_swr_refresh(refresh);
                    crate::metrics::METRICS
                        .cache_swr_served
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(cache_response(hit, "STALE-WHILE-REVALIDATE"));
                }
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

    // The in-flight (singleflight) key: the identity key whenever this client can take an
    // identity body, so cold requests with different Accept-Encoding coalesce on one fetch.
    // If that fetch turns out to be encoded for another encoding set, waiters that cannot
    // use it find nothing and fetch for themselves (the existing re-fetch path).
    let mut path_owned: Arc<str> =
        Arc::from(identity_key.clone().unwrap_or_else(|| cache_key.clone()));

    // Singleflight: coalesce concurrent cache misses for the same key.
    //
    // "Become the fetcher, or find the one already running" must be a single
    // atomic step — a separate `get()` then `insert()` lets two concurrent
    // misses both see "absent" and both register, the second clobbering the
    // first's sender (orphaning its waiters and double-fetching upstream). So
    // we use `get_or_insert_with`, which returns `inserted = true` to exactly
    // one caller. We use watch (not Notify) because `Receiver::wait_for`
    // inspects the current value at first poll: if the fetcher published `true`
    // between our registration and our `.await`, we still observe it and return
    // immediately instead of hanging.
    //
    // A waiter whose fetcher ended without storing anything (the response was not
    // storable, the fetch failed, or the fetcher's client went away) wakes when the
    // channel closes, re-checks the cache, and on a miss fetches for itself, alone.
    //
    // Two things make that wake happen, and both were missing from v0.8.0 to v0.9.10:
    //  - a waiter keeps a receiver and nothing else. It used to keep the sender it was
    //    handed, which kept the channel open for itself and for every other waiter:
    //    after a response that was not stored (a 404, a 500, `no-store`), every request
    //    that had been waiting hung for good;
    //  - the fetcher's registration is a guard ([`Fetching`]) that takes itself out of
    //    the map when dropped. The request future is dropped, at any `.await`, when its
    //    client goes away: without the guard the registration stayed, and every later
    //    request for that URL waited on a fetch that no longer existed.
    let tx = loop {
        let (tx, inserted) = state
            .inflight
            .get_or_insert_with(path_owned.clone(), || tokio::sync::watch::channel(false).0);
        if inserted {
            // We own the fetch for this key.
            break tx;
        }
        // Someone else is fetching — wait for them.
        let mut rx = tx.subscribe();
        drop(tx);
        let fetcher_stored = rx.wait_for(|v| *v).await.is_ok();
        // The fetcher may have just learned that this key varies, so the entry for
        // THIS request can now live under a secondary key: look it up afresh, under its own
        // primary key and, when it takes identity, under the identity one.
        let mut keys_now = vec![lookup_key(&state, &primary_key, req.headers())];
        if takes_identity {
            keys_now.push(lookup_key(&state, &identity_primary, req.headers()));
        }
        if let Some(hit) = keys_now
            .iter()
            .flatten()
            .find_map(|k| state.static_cache.get(k).fresh())
        {
            // get() already counted this hit — don't double-count it here.
            return Ok(fresh_hit_response(hit, req.method(), req.headers()));
        }
        // Nothing usable after the wait. Two cases:
        //
        // The fetcher stored a response and it is not one this request can use (it was
        // encoded for another encoding set, and this wait was under the shared identity
        // key): wait once more, under this request's own key, with the other clients of
        // its encoding set, so that there is one fetch per set and not one per client.
        //
        // Anything else (the fetcher stored nothing, or this was already the request's own
        // key): fetch alone, and not behind another fetcher. A response that is not
        // storable would otherwise be fetched by one waiter at a time, each wake electing
        // the next, and requests would queue for as long as they arrive faster than the
        // origin answers. The key is then this request's alone: the next turn of the loop
        // registers it and goes to the origin.
        if fetcher_stored && path_owned.as_ref() != cache_key.as_str() {
            path_owned = Arc::from(cache_key.as_str());
        } else {
            static ALONE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            path_owned = Arc::from(format!(
                "{cache_key}\u{0}{}",
                ALONE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
        }
    };
    // From here the registration is taken out when this fetch ends, however it ends.
    let fetching = Fetching {
        state: state.clone(),
        key: path_owned,
        tx,
    };

    // Opt-in circuit breaker: if the upstream's circuit is open, do not contact it. A stale
    // copy (when the origin allowed stale responses) stands in for it; otherwise the client
    // gets the 503. A fresh hit never reaches this point.
    // The breaker comes from the request's own config snapshot (passed in), not a fresh
    // load, so a reload while this request is in flight cannot change which breaker guards it.
    let breaker_cached = breaker.clone();
    let mut probe: Option<breaker::ProbeToken> = None;
    if let Some(entry) = &breaker_cached {
        match breaker_admit(entry) {
            Ok(p) => probe = p,
            Err(ms) => {
                drop(fetching);
                if let Some(hit) = stale_entry.as_ref().filter(|h| !h.meta.must_revalidate) {
                    metrics::METRICS
                        .cache_stale_if_error
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(cache_response(hit.clone(), "STALE"));
                }
                return Ok(circuit_open_response(ms));
            }
        }
    }

    // The varied request headers must outlive `req`, which the fetch consumes: the
    // response may reveal (via `Vary`) which of them the entry is keyed on.
    let req_headers = req.headers().clone();

    // RAM miss — fetch from upstream.
    // On error `fetching` is dropped. Waiters' wait_for() returns Err (channel
    // closed without receiving `true`), they re-check the cache, miss, and fetch
    // for themselves.
    let resp = match proxy::proxy_pass(
        &state.client_for(rule.client_spec()),
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
            if let Some(entry) = &breaker_cached {
                entry.breaker.record(false, breaker::now_ms(), probe.take());
            }
            drop(fetching);
            // stale-if-error (RFC 9111 §4.2.4): if we were revalidating a stale
            // entry and the origin is unreachable, serve the stale body rather
            // than fail — a flapping origin doesn't take cached content down.
            if let Some(hit) = revalidate.filter(|h| !h.meta.must_revalidate) {
                metrics::METRICS
                    .cache_stale_if_error
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(cache_response(hit, "STALE"));
            }
            return Err(e);
        }
    };

    if let Some(entry) = &breaker_cached {
        breaker_record(entry, resp.status(), probe.take());
    }

    // stale-if-error (RFC 9111 §4.2.4 / RFC 5861 §4): `proxy_pass` turns a transport
    // failure into a 502 response instead of an `Err`, so an origin that is down or
    // erroring reaches us as a 5xx. While revalidating a stale entry, that is the case
    // to answer from the stale copy — unless the origin forbade stale responses.
    if let Some(hit) = revalidate.as_ref() {
        if matches!(resp.status().as_u16(), 500 | 502 | 503 | 504) && !hit.meta.must_revalidate {
            drop(fetching);
            metrics::METRICS
                .cache_stale_if_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(cache_response(hit.clone(), "STALE"));
        }
    }

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
            let mut refreshed_meta = (*hit.meta).clone();
            if resp.headers().contains_key(hyper::header::CACHE_CONTROL) {
                refreshed_meta.stale_while_revalidate_secs = origin_swr(resp.headers());
                refreshed_meta.must_revalidate = forbids_stale(resp.headers());
            }
            // Skipped when a tag purge ran since this request began: it must not bring back an
            // entry the purge may have just removed.
            state.static_cache.refresh_checked(
                &found_key,
                hit.body.clone(),
                refreshed_meta,
                effective_ttl,
                initial_age,
                cache_max,
                tag_epoch,
            );
            fetching.stored(); // waiters observe the revived (fresh) entry
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
        // A declared length over the profile's limit: do not even start buffering it.
        let too_big = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<usize>().ok())
            .is_some_and(|n| n > max_object);
        if too_big {
            metrics::METRICS
                .cache_too_large
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let cacheable = !rcc_no_store
            && !too_big
            && is_shared_cacheable(
                req_authenticated,
                &parts.headers,
                effective_ttl,
                initial_age,
            );
        // Where the entry lives: the primary key, or — when the response varies — the
        // secondary key of THIS request's varied headers (bounded; see `vary`).
        // An identity body the origin did not select by Accept-Encoding goes under the
        // identity primary key, shared by every Accept-Encoding (#484). An encoded one, or one
        // with `Vary: Accept-Encoding` (the origin may compress for other clients), stays
        // under this request's own primary key, found only by the same encoding set.
        let store_primary: &str = if !takes_identity || !shareable_identity(&parts.headers) {
            &primary_key
        } else {
            &identity_primary
        };
        let store_key: Option<Arc<str>> = if !cacheable {
            None
        } else {
            match vary::policy(&parts.headers) {
                vary::VaryPolicy::Uncacheable => None,
                vary::VaryPolicy::None => {
                    // Not varying (any more): forget an old rule so lookups use the primary key.
                    state.static_cache.vary.remove(store_primary);
                    Some(Arc::from(store_primary))
                }
                vary::VaryPolicy::Keyed(names) => state
                    .static_cache
                    .vary
                    .install(
                        store_primary,
                        names,
                        // Outlive the variants' usefulness: a stale variant is kept for
                        // revalidation / stale-while-revalidate, so the rule must still be
                        // there to find it (the profile ceiling, plus any SWR window).
                        cache_ttl
                            .max(effective_ttl)
                            .saturating_add(origin_swr(&parts.headers)),
                        cache_max,
                    )
                    .and_then(|rule| {
                        let vk = vary::variant_key(store_primary, &rule.names, &req_headers)?;
                        rule.admit(&vk).then(|| Arc::from(vk.as_str()))
                    }),
            }
        };
        let Some(store_key) = store_key else {
            // Stream the body straight to the client without caching.
            // Drop the registration (no `true` sent): waiters fetch for themselves,
            // since the cache will not be populated for this key.
            drop(fetching);
            if cacheable {
                // Storable in principle but refused by the Vary policy or its cap.
                metrics::METRICS
                    .cache_vary_uncached
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            let mut resp = Response::from_parts(parts, body.map_err(hyper::Error::from).boxed());
            resp.headers_mut().insert(
                "X-Zion-Cache",
                hyper::header::HeaderValue::from_static("BYPASS"),
            );
            return Ok(resp);
        };

        // `Surrogate-Key` tags (purge by tag). Tags that cannot be tracked mean the entry could
        // never be purged by them, so the response is streamed through without being stored.
        let Ok(tags) = cache::surrogate_keys(&parts.headers) else {
            drop(fetching);
            metrics::METRICS
                .cache_tag_uncached
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut resp = Response::from_parts(parts, body.map_err(hyper::Error::from).boxed());
            resp.headers_mut().insert(
                "X-Zion-Cache",
                hyper::header::HeaderValue::from_static("BYPASS"),
            );
            return Ok(resp);
        };

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
            stale_while_revalidate_secs: origin_swr(&parts.headers),
            must_revalidate: forbids_stale(&parts.headers),
        };

        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(16);
        let stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
        let stream_body = http_body_util::StreamBody::new(stream);

        let state_clone = state.clone();
        let store_key_clone = store_key.clone();
        let meta_clone = meta.clone();

        // Cache Tee-Reader Pipeline. The registration moves into it: the fetch is not over
        // until the body is, and it ends with the task however the task ends.
        tokio::spawn(async move {
            let fetching = fetching;
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
                                    if total_bytes > max_object {
                                        cache_aborted = true; // Stop buffering, but continue streaming!
                                        metrics::METRICS
                                            .cache_too_large
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                            // Client disconnected mid-stream: the buffer is partial.
                            // `fetching` drops without signaling completion; waiters'
                            // wait_for returns Err and they fetch for themselves.
                            return;
                        }
                    }
                    Some(Err(e)) => {
                        // Upstream chunking failed: `fetching` drops (abort signal).
                        let _ = sender.send(Err(e)).await;
                        return;
                    }
                    None => {
                        break;
                    }
                }
            }

            // Not stored when a tag purge ran after the fetch began: the response may predate it.
            let outcome = if cache_aborted {
                None
            } else {
                Some(state_clone.static_cache.insert_tagged(
                    &store_key_clone,
                    cache_buffer.into(),
                    meta_clone,
                    effective_ttl,
                    initial_age,
                    cache_max,
                    &tags,
                    tag_epoch,
                ))
            };
            if outcome == Some(cache::TagStore::IndexFull) {
                // The response is already on its way to the client (as a MISS); only the
                // metric can say it was not kept.
                metrics::METRICS
                    .cache_tag_uncached
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            if outcome == Some(cache::TagStore::Stored) {
                // Cache populated: signal `true` so waiters' wait_for resolves
                // immediately at the next poll, even if they hadn't subscribed
                // before this point.
                fetching.stored();
            }
            // (else not stored, e.g. the body exceeded max_object: `fetching` drops
            //  without signaling; waiters fetch for themselves.)
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

    // Non-200 or non-cacheable: the registration ends without signaling completion.
    // Waiters re-check the cache (miss) and fetch for themselves.
    drop(fetching);

    Ok(resp)
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
        /// Drop every entry (the capacity and allocations are kept).
        pub(super) fn clear(&mut self) {
            self.map.clear();
            self.nodes.clear();
            self.free.clear();
            self.head = NIL;
            self.tail = NIL;
        }

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
    /// An oversize body is `413`; a body that broke on the way is `400`, not `413`.
    #[tokio::test]
    async fn a_broken_body_is_not_reported_as_too_large() {
        use http_body_util::{BodyExt, Full, Limited};
        let over = Limited::new(Full::new(bytes::Bytes::from(vec![0u8; 100])), 10);
        let e = over
            .collect()
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
            c.insert(k, k as u32 + 10);
        }
        assert_eq!(c.get(1), Some(11));
        c.clear();
        assert!((0..3u64).all(|k| c.get(k).is_none()), "cleared");
        // refills to capacity and evicts normally afterwards
        for k in 10..14u64 {
            c.insert(k, k as u32);
        }
        assert!(
            c.get(10).is_none(),
            "the LRU entry was evicted past capacity"
        );
        assert_eq!(c.get(13), Some(13));
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
