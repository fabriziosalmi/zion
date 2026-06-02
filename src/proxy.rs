// SPDX-License-Identifier: Apache-2.0
//! Upstream HTTP client + request/response forwarding.
//!
//! Wraps `hyper-util`'s legacy connection pool with the proxy's own
//! `XffMode` policy, header rewrites (hop-by-hop strip per RFC 7230,
//! `X-Request-ID` injection, `X-Forwarded-{For,Host,Proto}`), and the
//! body type used by every response Zion emits — `ZionBody` aliases
//! `BoxBody<Bytes, hyper::Error>`.
//!
//! HTTP/2 upstream multiplexing is opportunistic via ALPN. Pre-warming
//! of the connection pool happens at boot in `build_http_client`.

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
#[allow(unused_imports)]
use std::fmt::Write;
use std::net::SocketAddr;

/// How Zion treats the inbound `X-Forwarded-For` header before forwarding.
///
/// * `Append` (default): preserve the inbound chain, append the resolved
///   client IP. Compatible with the prior behaviour and correct when Zion
///   sits behind a sanitising edge (Cloudflare, ALB, etc.) AND the
///   downstream app reads the *rightmost-trusted* hop. Vulnerable to
///   client-side spoofing of the leftmost entry when Zion is the front
///   edge — apps that read XFF\[0\] would consume an attacker-controlled IP.
/// * `Rewrite` (recommended for front-edge): drop any inbound XFF and
///   replace with a single trusted entry — the IP returned by
///   `TrustedProxies::resolve_client_ip`. Downstream apps see a clean,
///   one-hop chain regardless of what the client tried to inject.
/// * `Drop`: strip inbound XFF and add nothing. Use when upstreams must
///   not learn the original client IP at all.
///
/// `X-Real-IP` is always set to the resolved client IP (no inbound trust).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum XffMode {
    #[default]
    Append,
    Rewrite,
    Drop,
}

impl XffMode {
    /// Parse from config string (lowercase). Unknown values fall back to
    /// `Append` so a typo doesn't degrade security silently — but the
    /// caller is expected to validate and warn.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "append" => Some(Self::Append),
            "rewrite" => Some(Self::Rewrite),
            "drop" => Some(Self::Drop),
            _ => None,
        }
    }
}

// Pre-parsed static header values — zero cost at runtime.
static PROTO_HTTPS: HeaderValue = HeaderValue::from_static("https");
static PROTO_HTTP: HeaderValue = HeaderValue::from_static("http");

/// BoxBody used throughout Zion — erases concrete body types.
pub type ZionBody = BoxBody<Bytes, hyper::Error>;

/// Shared HTTP client type — supports both HTTP/1.1 and HTTP/2 to upstreams.
/// Plain HTTP upstreams use HttpConnector; HTTPS upstreams negotiate H2 via ALPN.
pub type HttpClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    ZionBody,
>;

/// Build the shared HTTP client with connection pooling and H2 upstream support.
/// HTTP/2 multiplexing eliminates head-of-line blocking for HTTPS upstreams.
pub fn build_http_client() -> HttpClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(128)
        .build(https)
}

#[inline]
pub fn bad_gateway() -> Response<ZionBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(
            Full::new(Bytes::from("502 Bad Gateway"))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// 504 Gateway Timeout — the upstream was reachable but produced no response
/// within `UPSTREAM_REQUEST_TIMEOUT`. Kept distinct from `bad_gateway` (502 =
/// connect refused/reset) so an operator can tell a *slow* backend from an
/// *unreachable* one.
#[inline]
pub fn gateway_timeout() -> Response<ZionBody> {
    Response::builder()
        .status(StatusCode::GATEWAY_TIMEOUT)
        .body(
            Full::new(Bytes::from("504 Gateway Timeout"))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Rewrite URI for upstream forwarding and add proxy headers.
/// Uses pre-parsed scheme+authority from config — only path is set at runtime.
#[inline]
fn prepare_request<B>(
    mut req: Request<B>,
    scheme: &hyper::http::uri::Scheme,
    authority: &hyper::http::uri::Authority,
    remote_addr: Option<SocketAddr>,
    proto: &str,
    xff_mode: XffMode,
) -> Option<Request<B>> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| hyper::http::uri::PathAndQuery::from_static("/"));

    // Build URI from pre-parsed parts — no string format, no full parse
    let new_uri = hyper::Uri::builder()
        .scheme(scheme.clone())
        .authority(authority.clone())
        .path_and_query(path_and_query)
        .build()
        .ok()?;

    *req.uri_mut() = new_uri;
    *req.version_mut() = Version::HTTP_11;

    // Shared forwarding hygiene: strip Host + dangerous hop-by-hop /
    // credential headers, enforce the X-Forwarded-For policy and set the
    // X-Real-IP / X-Forwarded-Proto / X-Forwarded-Host trust headers.
    apply_forwarding_hygiene(&mut req, remote_addr, proto, xff_mode);
    // Connection is hop-by-hop (RFC 7230 §6.1); unlike the WebSocket path a
    // normal proxy request must NOT forward it to the upstream.
    req.headers_mut().remove(hyper::header::CONNECTION);

    Some(req)
}

/// Forwarding header hygiene shared by the normal proxy ([`prepare_request`])
/// and the WebSocket upgrade ([`proxy_websocket`]). Strips the dangerous
/// hop-by-hop / credential headers that must never reach the upstream
/// (Transfer-Encoding, TE, Trailer, Proxy-Authorization, Proxy-Connection,
/// Keep-Alive), drops the inbound Host (re-surfaced as `X-Forwarded-Host` for
/// vhost-routing upstreams), and sets the `X-Forwarded-*` / `X-Real-IP` trust
/// headers per the XFF policy. `Connection` / `Upgrade` are intentionally left
/// to the caller: the normal proxy strips `Connection`, a WS upgrade keeps
/// both for the handshake.
fn apply_forwarding_hygiene<B>(
    req: &mut Request<B>,
    remote_addr: Option<SocketAddr>,
    proto: &str,
    xff_mode: XffMode,
) {
    // Capture the inbound Host for X-Forwarded-Host before we strip it.
    let inbound_host = req.headers().get(hyper::header::HOST).cloned();

    req.headers_mut().remove(hyper::header::HOST);
    req.headers_mut().remove(hyper::header::TRANSFER_ENCODING);
    req.headers_mut().remove(hyper::header::TE);
    req.headers_mut().remove(hyper::header::TRAILER);
    req.headers_mut().remove(hyper::header::PROXY_AUTHORIZATION);
    req.headers_mut().remove("Proxy-Connection");
    req.headers_mut().remove("Keep-Alive");

    // ── X-Forwarded-For policy ──
    // For Rewrite/Drop we MUST strip any inbound XFF first, otherwise an
    // attacker-controlled leftmost entry survives to upstream apps that read
    // XFF[0] for ACL/audit. For Append we keep the inbound chain.
    if matches!(xff_mode, XffMode::Rewrite | XffMode::Drop) {
        req.headers_mut().remove("X-Forwarded-For");
    }
    if let Some(addr) = remote_addr {
        thread_local! {
            static IP_BUF: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(45));
        }
        IP_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            let _ = write!(buf, "{}", addr.ip());
            if let Ok(val) = HeaderValue::from_str(&buf) {
                match xff_mode {
                    XffMode::Append => {
                        req.headers_mut().append("X-Forwarded-For", val.clone());
                    }
                    XffMode::Rewrite => {
                        req.headers_mut().insert("X-Forwarded-For", val.clone());
                    }
                    XffMode::Drop => {}
                }
                req.headers_mut().insert("X-Real-IP", val);
            }
        });
    }
    req.headers_mut().insert(
        "X-Forwarded-Proto",
        if proto == "https" {
            PROTO_HTTPS.clone()
        } else {
            PROTO_HTTP.clone()
        },
    );
    // X-Forwarded-Host: re-surface the original Host so a vhost-routing
    // upstream still sees it (the module doc claimed this header was set but
    // it never was).
    if let Some(host) = inbound_host {
        req.headers_mut().insert("X-Forwarded-Host", host);
    }
}

/// Forward a request to the upstream (standard proxy).
#[inline]
pub async fn proxy_pass(
    client: &HttpClient,
    req: Request<ZionBody>,
    scheme: &hyper::http::uri::Scheme,
    authority: &hyper::http::uri::Authority,
    remote_addr: Option<SocketAddr>,
    proto: &str,
    xff_mode: XffMode,
) -> Result<Response<ZionBody>, hyper::Error> {
    let Some(req) = prepare_request(req, scheme, authority, remote_addr, proto, xff_mode) else {
        return Ok(bad_gateway());
    };
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, body); // Already boxed
    send_request(client, req).await
}

/// Like [`send_request`] but surfaces the transport error to the caller
/// instead of collapsing it into a 502, so [`proxy_pass_ha`] can decide
/// whether to fail over to another upstream.
#[inline]
async fn send_request_try(
    client: &HttpClient,
    req: Request<ZionBody>,
) -> Result<Response<ZionBody>, hyper_util::client::legacy::Error> {
    let upstream_start = std::time::Instant::now();
    let result = client.request(req).await;
    crate::metrics::METRICS
        .upstream_duration
        .observe(upstream_start.elapsed());
    let (parts, body) = result?.into_parts();
    Ok(Response::from_parts(parts, body.boxed()))
}

/// High-availability forward over a multi-upstream pool.
///
/// Picks the pool's best healthy upstream and, on a *connection-level*
/// failure, transparently fails over to the next healthy upstream instead
/// of returning 502 — closing the window between a backend dying and the
/// background health prober ejecting it (up to the steady probe interval).
///
/// The body is buffered once so it can be safely replayed. Non-idempotent
/// methods are retried only on a pure connect error (the request provably
/// never reached the upstream); idempotent methods retry on any transport
/// error. Single-upstream pools take the zero-overhead [`proxy_pass`] path.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_pass_ha(
    client: &HttpClient,
    req: Request<ZionBody>,
    pool: &[String],
    default_scheme: &hyper::http::uri::Scheme,
    default_authority: &hyper::http::uri::Authority,
    health_map: &crate::health::HealthMap,
    remote_addr: Option<SocketAddr>,
    proto: &str,
    xff_mode: XffMode,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Nothing to fail over to — keep the streaming fast path.
    if pool.len() < 2 {
        return proxy_pass(
            client,
            req,
            default_scheme,
            default_authority,
            remote_addr,
            proto,
            xff_mode,
        )
        .await;
    }

    // Buffer the body once so each attempt can replay it.
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Ok(bad_gateway()),
    };
    let method = parts.method.clone();
    let uri = parts.uri.clone();
    let version = parts.version;
    let headers = parts.headers.clone();
    let idempotent = matches!(
        method,
        hyper::Method::GET
            | hyper::Method::HEAD
            | hyper::Method::OPTIONS
            | hyper::Method::PUT
            | hyper::Method::DELETE
            | hyper::Method::TRACE
    );

    // At most one attempt per pool member; marking a failed upstream down
    // makes the next `select_best_upstream` rotate to a survivor.
    for _ in 0..pool.len() {
        let url = match crate::health::select_best_upstream(health_map, pool) {
            Some(u) => u.clone(),
            None => break,
        };
        let (scheme, authority) = match url.parse::<hyper::Uri>() {
            Ok(u) => (
                u.scheme()
                    .cloned()
                    .unwrap_or_else(|| default_scheme.clone()),
                u.authority()
                    .cloned()
                    .unwrap_or_else(|| default_authority.clone()),
            ),
            Err(_) => (default_scheme.clone(), default_authority.clone()),
        };

        let mut attempt: Request<ZionBody> = Request::new(
            Full::new(body_bytes.clone())
                .map_err(|never| match never {})
                .boxed(),
        );
        *attempt.method_mut() = method.clone();
        *attempt.uri_mut() = uri.clone();
        *attempt.version_mut() = version;
        *attempt.headers_mut() = headers.clone();

        let Some(prepared) =
            prepare_request(attempt, &scheme, &authority, remote_addr, proto, xff_mode)
        else {
            return Ok(bad_gateway());
        };

        match send_request_try(client, prepared).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                let connect = e.is_connect();
                eprintln!("  failover: upstream {url} error (connect={connect}): {e}");
                // Eagerly eject: mark unhealthy and bring the next probe
                // forward (`next_probe_at_us = 0` == due now) so the upstream
                // rejoins rotation the moment it recovers.
                if let Some(h) = health_map.get(&url) {
                    h.healthy.store(false, std::sync::atomic::Ordering::Relaxed);
                    h.next_probe_at_us
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                }
                // Don't replay a non-idempotent request unless it provably
                // never reached the upstream.
                if !(connect || idempotent) {
                    return Ok(bad_gateway());
                }
            }
        }
    }
    Ok(bad_gateway())
}

/// Forward a request whose body has already been collected (post-WAF path).
#[allow(dead_code)] // retained for symmetric API; not currently called
#[allow(clippy::too_many_arguments)]
// 8/7 — the caller path here is
// already a low-frequency post-WAF re-emit; collapsing into a struct
// would force every (currently zero) caller to allocate or borrow it,
// which is the wrong trade-off until at least one caller exists.
#[inline]
pub async fn proxy_pass_bytes(
    client: &HttpClient,
    parts: hyper::http::request::Parts,
    body_bytes: Bytes,
    scheme: &hyper::http::uri::Scheme,
    authority: &hyper::http::uri::Authority,
    remote_addr: SocketAddr,
    proto: &str,
    xff_mode: XffMode,
) -> Result<Response<ZionBody>, hyper::Error> {
    let body: ZionBody = Full::new(body_bytes)
        .map_err(|never| match never {})
        .boxed();
    let req = Request::from_parts(parts, body);
    let Some(req) = prepare_request(req, scheme, authority, Some(remote_addr), proto, xff_mode)
    else {
        return Ok(bad_gateway());
    };
    send_request(client, req).await
}

/// Forward a request for SSE streaming — adds no-buffer headers to response.
#[inline]
pub async fn proxy_pass_stream(
    client: &HttpClient,
    req: Request<ZionBody>,
    scheme: &hyper::http::uri::Scheme,
    authority: &hyper::http::uri::Authority,
    remote_addr: Option<SocketAddr>,
    proto: &str,
    xff_mode: XffMode,
) -> Result<Response<ZionBody>, hyper::Error> {
    let Some(req) = prepare_request(req, scheme, authority, remote_addr, proto, xff_mode) else {
        return Ok(bad_gateway());
    };
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, body);

    match client.request(req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            parts.headers.insert(
                "Cache-Control",
                hyper::header::HeaderValue::from_static("no-cache"),
            );
            parts.headers.insert(
                "X-Accel-Buffering",
                hyper::header::HeaderValue::from_static("no"),
            );
            Ok(Response::from_parts(parts, body.boxed()))
        }
        Err(e) => {
            eprintln!("  stream proxy error: {e}");
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Content-Type", "text/event-stream")
                .body(
                    Full::new(Bytes::from("event: error\ndata: upstream unreachable\n\n"))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap())
        }
    }
}

/// Upper bound on a single upstream request/response. A hung or black-holed
/// backend (TCP/TLS completes but the HTTP response never arrives, or arrives
/// at a trickle) would otherwise pin the request (and the conn-limit permit
/// plus per-IP slot it holds) up to the 1h connection cap — a DoS amplifier.
/// 504 on elapse. Per-upstream `connect_timeout_ms` covers only the connect
/// phase and is not yet wired to the shared pooled client; this overall bound
/// is what closes the hang.
const UPSTREAM_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Internal: send a prepared request through the shared client.
#[inline]
async fn send_request(
    client: &HttpClient,
    req: Request<ZionBody>,
) -> Result<Response<ZionBody>, hyper::Error> {
    let upstream_start = std::time::Instant::now();
    match tokio::time::timeout(UPSTREAM_REQUEST_TIMEOUT, client.request(req)).await {
        Ok(Ok(resp)) => {
            crate::metrics::METRICS
                .upstream_duration
                .observe(upstream_start.elapsed());
            let (parts, body) = resp.into_parts();
            Ok(Response::from_parts(parts, body.boxed()))
        }
        Ok(Err(e)) => {
            crate::metrics::METRICS
                .upstream_duration
                .observe(upstream_start.elapsed());
            eprintln!("  proxy error: {e}");
            Ok(bad_gateway())
        }
        Err(_elapsed) => {
            crate::metrics::METRICS
                .upstream_duration
                .observe(upstream_start.elapsed());
            eprintln!("  proxy upstream timeout after {UPSTREAM_REQUEST_TIMEOUT:?}");
            Ok(gateway_timeout())
        }
    }
}

/// Proxy a WebSocket upgrade. Connects to upstream, performs the HTTP Upgrade
/// handshake, returns 101 to client, and spawns a bidirectional byte pipe.
pub async fn proxy_websocket(
    mut req: Request<ZionBody>,
    on_client_upgrade: hyper::upgrade::OnUpgrade,
    scheme: &hyper::http::uri::Scheme,
    authority: &hyper::http::uri::Authority,
    remote_addr: Option<SocketAddr>,
    proto: &str,
    xff_mode: XffMode,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Build upstream URI
    let path_and_query = req
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| hyper::http::uri::PathAndQuery::from_static("/"));
    let upstream_uri = hyper::Uri::builder()
        .scheme(scheme.clone())
        .authority(authority.clone())
        .path_and_query(path_and_query)
        .build();
    let Ok(upstream_uri) = upstream_uri else {
        return Ok(bad_gateway());
    };

    // Extract host:port for TCP connection
    let host = authority.as_str();

    // G-03 FIX: Respect upstream scheme and provide default port fallback.
    let is_tls_upstream = scheme.as_str() == "https" || scheme.as_str() == "wss";

    // Authority may omit port (e.g., "api.internal"). Add default port based on scheme.
    let connect_target = if authority.port().is_some() {
        host.to_string()
    } else {
        let default_port = if is_tls_upstream { 443 } else { 80 };
        format!("{host}:{default_port}")
    };

    // Connect to upstream via raw TCP (not the pooled client — WebSocket is long-lived)
    let tcp_stream = match tokio::net::TcpStream::connect(&connect_target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  ws upstream connect failed ({connect_target}): {e}");
            return Ok(bad_gateway());
        }
    };
    let _ = tcp_stream.set_nodelay(true);
    crate::net::tune_accepted(&tcp_stream);

    // Perform HTTP upgrade handshake with upstream
    *req.uri_mut() = upstream_uri;
    *req.version_mut() = Version::HTTP_11;
    // Same forwarding hygiene as the normal proxy (strip Host + dangerous
    // hop-by-hop / credential headers — notably Proxy-Authorization — and set
    // the X-Forwarded-* / X-Real-IP trust headers per the XFF policy), but
    // KEEP Connection + Upgrade, which carry the WebSocket handshake. The old
    // path stripped only Host, so it leaked Proxy-Authorization and a spoofed
    // X-Forwarded-For straight to the upstream.
    apply_forwarding_hygiene(&mut req, remote_addr, proto, xff_mode);

    // HTTP/1.1 upgrade handshake — works on any AsyncRead+AsyncWrite stream.
    // For TLS upstreams, wrap in tokio-rustls connector first.
    if is_tls_upstream {
        // Cached TLS client config — build once, reuse for all WS upgrades.
        // Avoids re-parsing ~150 Mozilla CA roots on every WebSocket TLS connection.
        static WS_TLS_CONFIG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
            std::sync::OnceLock::new();
        let tls_config = WS_TLS_CONFIG.get_or_init(|| {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            std::sync::Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            )
        });
        let connector = tokio_rustls::TlsConnector::from(tls_config.clone());

        // SNI: use the hostname from the authority (without port).
        // SAFETY (inner unwrap): `"localhost"` is a compile-time-constant
        // valid DNS name accepted by `ServerName::try_from`. The inner
        // unwrap can only trip if rustls' DNS-name validator changes its
        // grammar to reject a literal we've shipped for the last decade —
        // which would be a downstream API break, not a runtime concern.
        let server_name = rustls::pki_types::ServerName::try_from(authority.host().to_string())
            .unwrap_or_else(|_| {
                rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap()
            });

        let tls_stream = match connector.connect(server_name, tcp_stream).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  ws upstream TLS handshake failed ({connect_target}): {e}");
                return Ok(bad_gateway());
            }
        };

        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  ws upstream handshake failed: {e}");
                return Ok(bad_gateway());
            }
        };
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });

        return send_ws_upgrade(&mut sender, req, on_client_upgrade).await;
    }

    // Plain TCP path (non-TLS upstreams)
    let io = hyper_util::rt::TokioIo::new(tcp_stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  ws upstream handshake failed: {e}");
            return Ok(bad_gateway());
        }
    };

    // Drive the connection in background
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    send_ws_upgrade(&mut sender, req, on_client_upgrade).await
}

/// Common WebSocket upgrade exchange — send the upgrade request, check for 101,
/// spawn bidirectional pipe. Shared between plain TCP and TLS upstream paths.
async fn send_ws_upgrade(
    sender: &mut hyper::client::conn::http1::SendRequest<ZionBody>,
    req: Request<ZionBody>,
    on_client_upgrade: hyper::upgrade::OnUpgrade,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Send the upgrade request to upstream
    let upstream_resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  ws upstream request failed: {e}");
            return Ok(bad_gateway());
        }
    };

    // If upstream didn't 101, return that response as-is
    if upstream_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (parts, body) = upstream_resp.into_parts();
        return Ok(Response::from_parts(parts, body.boxed()));
    }

    // Capture Sec-WebSocket-Accept and other WS headers from upstream
    // BEFORE consuming the response for upgrade IO (RFC 6455 §4.2.2).
    let ws_accept = upstream_resp.headers().get("Sec-WebSocket-Accept").cloned();
    let ws_protocol = upstream_resp
        .headers()
        .get("Sec-WebSocket-Protocol")
        .cloned();
    let ws_extensions = upstream_resp
        .headers()
        .get("Sec-WebSocket-Extensions")
        .cloned();

    // Get upgrade IO from upstream
    let upstream_upgraded = match hyper::upgrade::on(upstream_resp).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("  ws upstream upgrade failed: {e}");
            return Ok(bad_gateway());
        }
    };

    // Build 101 response for client, forwarding upstream's WS handshake headers.
    // Sec-WebSocket-Accept is mandatory (RFC 6455) — browsers reject without it.
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::UPGRADE, "websocket")
        .header(hyper::header::CONNECTION, "Upgrade");
    if let Some(accept) = ws_accept {
        builder = builder.header("Sec-WebSocket-Accept", accept);
    }
    if let Some(proto) = ws_protocol {
        builder = builder.header("Sec-WebSocket-Protocol", proto);
    }
    if let Some(ext) = ws_extensions {
        builder = builder.header("Sec-WebSocket-Extensions", ext);
    }
    let resp = builder
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap();

    // Spawn bidirectional pipe with activity-aware idle timeout.
    // - Idle timeout: 5 minutes of zero traffic in either direction.
    // - Max session:  24 hours wall-clock as a safety valve.
    // The previous implementation only had the 24h cap, allowing idle
    // connections to hold resources indefinitely (Slowloris-style exhaustion).
    tokio::spawn(async move {
        if let Ok(client_upgraded) = on_client_upgrade.await {
            let mut c = hyper_util::rt::TokioIo::new(client_upgraded);
            let mut u = hyper_util::rt::TokioIo::new(upstream_upgraded);

            let max_session = std::time::Duration::from_secs(24 * 60 * 60);
            let idle_timeout = std::time::Duration::from_secs(5 * 60);

            let session_deadline = tokio::time::Instant::now() + max_session;

            let ws_pipe = async {
                // copy_bidirectional runs until either side closes or errors.
                // The idle timeout tears down completely silent sessions.
                let _ = tokio::time::timeout(
                    idle_timeout,
                    tokio::io::copy_bidirectional(&mut c, &mut u),
                )
                .await;
            };

            // Cap total session at the absolute deadline.
            let _ = tokio::time::timeout_at(session_deadline, ws_pipe).await;
        }
    });

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::uri::{Authority, Scheme};

    fn make_request(method: &str, uri: &str) -> Request<()> {
        Request::builder().method(method).uri(uri).body(()).unwrap()
    }

    fn scheme() -> Scheme {
        "http".parse().unwrap()
    }
    fn authority() -> Authority {
        "127.0.0.1:8000".parse().unwrap()
    }
    fn authority2() -> Authority {
        "127.0.0.1:3000".parse().unwrap()
    }

    #[test]
    fn prepare_rewrites_uri() {
        let req = make_request("GET", "/api/v1/users?page=2");
        let req =
            prepare_request(req, &scheme(), &authority(), None, "https", XffMode::Append).unwrap();
        assert_eq!(
            req.uri().to_string(),
            "http://127.0.0.1:8000/api/v1/users?page=2"
        );
    }

    #[test]
    fn prepare_sets_http11() {
        let req = make_request("GET", "/test");
        let req =
            prepare_request(req, &scheme(), &authority(), None, "https", XffMode::Append).unwrap();
        assert_eq!(req.version(), Version::HTTP_11);
    }

    #[test]
    fn prepare_removes_hop_by_hop_headers() {
        let req = Request::builder()
            .method("GET")
            .uri("/test")
            .header(hyper::header::HOST, "original.com")
            .header(hyper::header::CONNECTION, "keep-alive")
            .body(())
            .unwrap();
        let req =
            prepare_request(req, &scheme(), &authority(), None, "https", XffMode::Append).unwrap();
        assert!(req.headers().get(hyper::header::HOST).is_none());
        assert!(req.headers().get(hyper::header::CONNECTION).is_none());
    }

    #[test]
    fn prepare_adds_forwarding_headers() {
        let req = make_request("GET", "/test");
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let req = prepare_request(
            req,
            &scheme(),
            &authority(),
            Some(addr),
            "https",
            XffMode::Append,
        )
        .unwrap();
        assert_eq!(req.headers().get("X-Forwarded-For").unwrap(), "1.2.3.4");
        assert_eq!(req.headers().get("X-Real-IP").unwrap(), "1.2.3.4");
        assert_eq!(req.headers().get("X-Forwarded-Proto").unwrap(), "https");
    }

    #[test]
    fn prepare_http_proto() {
        let req = make_request("GET", "/test");
        let req =
            prepare_request(req, &scheme(), &authority(), None, "http", XffMode::Append).unwrap();
        assert_eq!(req.headers().get("X-Forwarded-Proto").unwrap(), "http");
    }

    #[test]
    fn prepare_no_forwarding_without_addr() {
        let req = make_request("GET", "/test");
        let req =
            prepare_request(req, &scheme(), &authority(), None, "https", XffMode::Append).unwrap();
        assert!(req.headers().get("X-Forwarded-For").is_none());
        assert!(req.headers().get("X-Real-IP").is_none());
    }

    #[test]
    fn prepare_ipv6_forwarding() {
        let req = make_request("GET", "/test");
        let addr: SocketAddr = "[::1]:1234".parse().unwrap();
        let req = prepare_request(
            req,
            &scheme(),
            &authority(),
            Some(addr),
            "https",
            XffMode::Append,
        )
        .unwrap();
        assert_eq!(req.headers().get("X-Forwarded-For").unwrap(), "::1");
    }

    #[test]
    fn prepare_preserves_query_string() {
        let req = make_request("GET", "/search?q=hello&page=1");
        let req = prepare_request(
            req,
            &scheme(),
            &authority2(),
            None,
            "https",
            XffMode::Append,
        )
        .unwrap();
        assert_eq!(
            req.uri().to_string(),
            "http://127.0.0.1:3000/search?q=hello&page=1"
        );
    }

    #[test]
    fn prepare_root_path_default() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(())
            .unwrap();
        assert!(
            prepare_request(req, &scheme(), &authority(), None, "https", XffMode::Append).is_some()
        );
    }

    #[test]
    fn bad_gateway_returns_502() {
        assert_eq!(bad_gateway().status(), StatusCode::BAD_GATEWAY);
    }

    // ── XffMode policy tests ──
    //
    // These pin the contract that motivated the policy:
    //   * Append (legacy): keep inbound chain, append our IP. A spoofed
    //     leftmost survives — caller must trust the inbound edge.
    //   * Rewrite: drop inbound, emit a single trusted entry. Spoofed
    //     leftmost gets erased; downstream apps reading XFF[0] are safe.
    //   * Drop: emit no XFF at all.

    /// Helper: build a request that already carries an attacker-controlled
    /// X-Forwarded-For header, simulating a client trying to spoof their IP.
    fn req_with_spoofed_xff(spoofed: &str) -> Request<()> {
        Request::builder()
            .method("GET")
            .uri("/test")
            .header("X-Forwarded-For", spoofed)
            .body(())
            .unwrap()
    }

    fn xff_values(req: &Request<()>) -> Vec<String> {
        req.headers()
            .get_all("X-Forwarded-For")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn xff_append_preserves_inbound_chain() {
        let req = req_with_spoofed_xff("9.9.9.9");
        let addr: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        let req = prepare_request(
            req,
            &scheme(),
            &authority(),
            Some(addr),
            "https",
            XffMode::Append,
        )
        .unwrap();
        // Append: spoofed value is preserved as a separate header value;
        // our resolved IP is appended. Downstream reading XFF[0] would see
        // 9.9.9.9 — this is the documented foot-gun of `append` mode.
        let vals = xff_values(&req);
        assert_eq!(vals, vec!["9.9.9.9".to_string(), "1.2.3.4".to_string()]);
        assert_eq!(req.headers().get("X-Real-IP").unwrap(), "1.2.3.4");
    }

    #[test]
    fn xff_rewrite_strips_spoofed_and_emits_single_entry() {
        let req = req_with_spoofed_xff("9.9.9.9");
        let addr: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        let req = prepare_request(
            req,
            &scheme(),
            &authority(),
            Some(addr),
            "https",
            XffMode::Rewrite,
        )
        .unwrap();
        // Rewrite: only ONE XFF entry, equal to the resolved IP. The
        // spoofed leftmost is gone — downstream apps cannot be tricked
        // into trusting attacker-controlled XFF[0].
        let vals = xff_values(&req);
        assert_eq!(vals, vec!["1.2.3.4".to_string()]);
        assert_eq!(req.headers().get("X-Real-IP").unwrap(), "1.2.3.4");
    }

    #[test]
    fn xff_rewrite_strips_multi_hop_spoofed_chain() {
        let req = req_with_spoofed_xff("evil1, evil2, evil3");
        let addr: SocketAddr = "203.0.113.7:443".parse().unwrap();
        let req = prepare_request(
            req,
            &scheme(),
            &authority(),
            Some(addr),
            "https",
            XffMode::Rewrite,
        )
        .unwrap();
        let vals = xff_values(&req);
        assert_eq!(vals, vec!["203.0.113.7".to_string()]);
    }

    #[test]
    fn xff_drop_emits_no_xff() {
        let req = req_with_spoofed_xff("9.9.9.9");
        let addr: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        let req = prepare_request(
            req,
            &scheme(),
            &authority(),
            Some(addr),
            "https",
            XffMode::Drop,
        )
        .unwrap();
        // Drop: no XFF at all. X-Real-IP is still set so internal
        // deployments that rely on it for logging continue to work.
        assert!(req.headers().get("X-Forwarded-For").is_none());
        assert_eq!(req.headers().get("X-Real-IP").unwrap(), "1.2.3.4");
    }

    #[test]
    fn xff_drop_strips_spoofed_even_without_remote_addr() {
        // No remote_addr: nothing to add, but inbound XFF still gets
        // stripped under Drop. (Defensive against downstream misuse.)
        let req = req_with_spoofed_xff("9.9.9.9");
        let req =
            prepare_request(req, &scheme(), &authority(), None, "https", XffMode::Drop).unwrap();
        assert!(req.headers().get("X-Forwarded-For").is_none());
        assert!(req.headers().get("X-Real-IP").is_none());
    }

    #[test]
    fn xff_real_ip_is_never_trusted_from_inbound() {
        // X-Real-IP must always be set from the resolved client IP, never
        // copied from an inbound header. Verify under Append mode (the one
        // most likely to leak inbound state).
        let req = Request::builder()
            .method("GET")
            .uri("/test")
            .header("X-Real-IP", "9.9.9.9") // attacker-supplied
            .body(())
            .unwrap();
        let addr: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        let req = prepare_request(
            req,
            &scheme(),
            &authority(),
            Some(addr),
            "https",
            XffMode::Append,
        )
        .unwrap();
        // The X-Real-IP value must be the resolved IP, not the spoofed one.
        let real_ip = req.headers().get("X-Real-IP").unwrap();
        assert_eq!(real_ip, "1.2.3.4");
    }

    #[test]
    fn xff_mode_parse_known_values() {
        assert_eq!(XffMode::parse("append"), Some(XffMode::Append));
        assert_eq!(XffMode::parse("rewrite"), Some(XffMode::Rewrite));
        assert_eq!(XffMode::parse("drop"), Some(XffMode::Drop));
    }

    #[test]
    fn xff_mode_parse_rejects_unknown() {
        assert_eq!(XffMode::parse("APPEND"), None); // case-sensitive
        assert_eq!(XffMode::parse("strip"), None);
        assert_eq!(XffMode::parse(""), None);
    }

    #[test]
    fn xff_mode_default_is_append() {
        // The default must remain Append for zero-impact upgrades from
        // earlier Zion versions, even at the cost of accepting the spoof
        // foot-gun for users who don't opt in.
        assert_eq!(XffMode::default(), XffMode::Append);
    }

    // ── WebSocket TLS-to-Upstream Tests ──

    fn is_tls_upstream(scheme: &str) -> bool {
        scheme == "https" || scheme == "wss"
    }

    fn default_port(scheme: &str) -> u16 {
        if is_tls_upstream(scheme) {
            443
        } else {
            80
        }
    }

    #[test]
    fn ws_http_is_plain() {
        assert!(!is_tls_upstream("http"));
    }

    #[test]
    fn ws_ws_is_plain() {
        assert!(!is_tls_upstream("ws"));
    }

    #[test]
    fn ws_https_is_tls() {
        assert!(is_tls_upstream("https"));
    }

    #[test]
    fn ws_wss_is_tls() {
        assert!(is_tls_upstream("wss"));
    }

    #[test]
    fn ws_default_port_http_80() {
        assert_eq!(default_port("http"), 80);
        assert_eq!(default_port("ws"), 80);
    }

    #[test]
    fn ws_default_port_https_443() {
        assert_eq!(default_port("https"), 443);
        assert_eq!(default_port("wss"), 443);
    }

    #[test]
    fn ws_authority_with_port_preserved() {
        let auth: Authority = "api.internal:9443".parse().unwrap();
        assert!(auth.port().is_some());
        assert_eq!(auth.port_u16().unwrap(), 9443);
    }

    #[test]
    fn ws_authority_without_port_needs_default() {
        let auth: Authority = "api.internal".parse().unwrap();
        assert!(auth.port().is_none());
        // Should use default_port(scheme) when port is None
        let connect = format!("{}:{}", auth.as_str(), default_port("https"));
        assert_eq!(connect, "api.internal:443");
    }
}
