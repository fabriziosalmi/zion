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
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
#[allow(unused_imports)]
use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::Arc;

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
    hyper_rustls::HttpsConnector<
        hyper_util::client::legacy::connect::HttpConnector<crate::dns::StaleOnErrorResolver>,
    >,
    ZionBody,
>;

/// Default per-upstream TCP connect deadline (`connect_timeout_ms`).
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 3000;

/// Build an HTTP client with connection pooling and H2 upstream support, whose
/// connector abandons a TCP connect after `connect_timeout_ms` (`0` = no connect
/// deadline). HTTP/2 multiplexing eliminates head-of-line blocking for HTTPS
/// upstreams.
///
/// Without a connector deadline a black-holed upstream (packets dropped, no RST)
/// is bounded only by the overall 30s request timeout, so every HA failover
/// attempt against it costs ~30s before the next member is tried. The deadline
/// covers the TCP connect only; the TLS handshake and the response stay bounded
/// by that overall timeout.
///
/// `http1_only` offers TLS upstreams only `http/1.1` in ALPN: an upstream with
/// `preserve_host` must not be spoken to over HTTP/2, which cannot carry a `Host` that
/// differs from `:authority` (the backend resets the stream; ADR-0024).
pub fn build_http_client(connect_timeout_ms: u64, http1_only: bool) -> HttpClient {
    build_client(&ClientSpec {
        connect_timeout_ms,
        http1_only,
        keepalive: DEFAULT_KEEPALIVE,
        tls: None,
    })
}

/// Default per-upstream deadline for the response headers (`request_timeout_ms`). Shorter
/// under test so a hanging upstream can be exercised in seconds.
#[cfg(not(test))]
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
#[cfg(test)]
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 2_000;
/// Bounds of `request_timeout_ms`: no "0 = none" (a request with no deadline would hold its
/// connection slot until the connection cap), and no longer than that 1 h cap.
pub const MIN_REQUEST_TIMEOUT_MS: u64 = 1;
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 3_600_000;

/// A request extension: how long one upstream attempt may wait for the response headers
/// (`[upstream.x] request_timeout_ms`). Set where the route is known, like [`PreserveHost`];
/// a request without it gets [`UPSTREAM_REQUEST_TIMEOUT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTimeout(pub std::time::Duration);

/// The deadline for `req`'s upstream attempt.
fn request_timeout<B>(req: &Request<B>) -> std::time::Duration {
    req.extensions()
        .get::<RequestTimeout>()
        .map_or(UPSTREAM_REQUEST_TIMEOUT, |t| t.0)
}

/// Idle pooled connections kept per upstream host (`[upstream.x] keepalive`).
pub const DEFAULT_KEEPALIVE: usize = 128;

/// What an upstream needs from its HTTP client: the connect deadline, whether it must be
/// spoken to over HTTP/1.1 only (`preserve_host`), and how many idle connections to
/// keep (`keepalive`). Clients are cached per distinct spec ([`crate::state::AppState::client_for`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientSpec {
    pub connect_timeout_ms: u64,
    pub http1_only: bool,
    pub keepalive: usize,
    /// The upstream's own TLS settings (a private CA, a client certificate); `None`: the
    /// public roots and no client certificate.
    pub tls: Option<Arc<UpstreamTls>>,
}

impl ClientSpec {
    /// The spec of the shared default client.
    pub const DEFAULT: ClientSpec = ClientSpec {
        connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
        http1_only: false,
        keepalive: DEFAULT_KEEPALIVE,
        tls: None,
    };
}

/// How zion's TLS towards one upstream differs from the default (`[upstream.x] ca_path`,
/// `client_cert_path` / `client_key_path`): which CA signs the upstream's certificate, and
/// which certificate zion presents (mTLS). Loaded and checked when the config is built, so
/// a bad file is a config error and never a request that goes out without the certificate.
pub struct UpstreamTls {
    /// SHA-256 of the files' contents: two upstreams with the same material share a client,
    /// and a renewed certificate is a new one (the client cache is keyed by this).
    id: [u8; 32],
    config: Arc<rustls::ClientConfig>,
    presents_certificate: bool,
}

impl UpstreamTls {
    /// Load the settings. `ca_path` REPLACES the public roots (an upstream behind a private
    /// CA is not also trusted through every public one); the client certificate and key
    /// must be given together and must match.
    pub fn load(
        ca_path: Option<&str>,
        cert_path: Option<&str>,
        key_path: Option<&str>,
    ) -> Result<Arc<Self>, String> {
        let mut digest = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        let mut read = |role: &str, path: &str| -> Result<Vec<u8>, String> {
            let bytes = std::fs::read(path).map_err(|e| format!("{role} {path}: {e}"))?;
            digest.update(role.as_bytes());
            digest.update(&(bytes.len() as u64).to_le_bytes());
            digest.update(&bytes);
            Ok(bytes)
        };
        let mut roots = rustls::RootCertStore::empty();
        match ca_path {
            Some(path) => {
                let pem = read("ca_path", path)?;
                for cert in crate::pem::certs(&pem).map_err(|e| format!("ca_path {path}: {e}"))? {
                    roots
                        .add(cert)
                        .map_err(|e| format!("ca_path {path}: {e}"))?;
                }
                if roots.is_empty() {
                    return Err(format!("ca_path {path}: no certificate in the file"));
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let (config, presents_certificate) = match (cert_path, key_path) {
            (Some(cert), Some(key)) => {
                // Same check as the server side: a key that is not the certificate's is
                // refused here, not at the first handshake.
                crate::tls::load_certified_key(cert, key)
                    .map_err(|e| format!("client certificate: {e}"))?;
                let cert_pem = read("client_cert_path", cert)?;
                let key_pem = read("client_key_path", key)?;
                let chain = crate::pem::certs(&cert_pem)
                    .map_err(|e| format!("client_cert_path {cert}: {e}"))?;
                let key_der = crate::pem::private_key(&key_pem)
                    .map_err(|e| format!("client_key_path {key}: {e}"))?
                    .ok_or_else(|| format!("client_key_path {key}: no private key in the file"))?;
                (
                    builder
                        .with_client_auth_cert(chain, key_der)
                        .map_err(|e| format!("client certificate: {e}"))?,
                    true,
                )
            }
            (None, None) => (builder.with_no_client_auth(), false),
            _ => {
                return Err("client_cert_path and client_key_path must be set together".to_string())
            }
        };
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.finish().as_ref());
        Ok(Arc::new(Self {
            id,
            config: Arc::new(config),
            presents_certificate,
        }))
    }

    /// The rustls configuration (no ALPN set: each user adds its own).
    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        self.config.clone()
    }

    /// Does zion present a client certificate to this upstream?
    pub fn presents_certificate(&self) -> bool {
        self.presents_certificate
    }
}

impl PartialEq for UpstreamTls {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for UpstreamTls {}
impl std::hash::Hash for UpstreamTls {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
impl std::fmt::Debug for UpstreamTls {
    // Never the key material: only whether a certificate is presented.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTls")
            .field("presents_certificate", &self.presents_certificate)
            .finish()
    }
}

/// A request extension: the TLS settings of the upstream this request goes to, for the
/// paths that build their own connection (the WebSocket upgrade). Set where the route is
/// known, like [`PreserveHost`].
#[derive(Clone)]
pub struct UpstreamTlsMark(pub Arc<UpstreamTls>);

/// Build the HTTP client for `spec`.
pub fn build_client(spec: &ClientSpec) -> HttpClient {
    let (connect_timeout_ms, http1_only) = (spec.connect_timeout_ms, spec.http1_only);
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(
        crate::dns::StaleOnErrorResolver,
    );
    // The TLS wrapper needs to see `https://` URIs; it does its own scheme check.
    http.enforce_http(false);
    // Kernel keepalive on pooled upstream sockets too: a pooled connection to a host
    // that died silently would otherwise be handed to the next request and fail then.
    http.set_keepalive(Some(std::time::Duration::from_secs(
        crate::net::DEFAULT_TCP_KEEPALIVE_SECS,
    )));
    http.set_connect_timeout(
        (connect_timeout_ms > 0).then(|| std::time::Duration::from_millis(connect_timeout_ms)),
    );
    let builder = match &spec.tls {
        // The upstream's own CA and/or client certificate.
        Some(tls) => hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(rustls::ClientConfig::clone(&tls.client_config())),
        None => hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots(),
    }
    .https_or_http()
    .enable_http1();
    let https = if http1_only {
        builder.wrap_connector(http)
    } else {
        builder.enable_http2().wrap_connector(http)
    };

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(spec.keepalive)
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
/// within the request timeout (`[upstream.x] request_timeout_ms`). Kept distinct from `bad_gateway` (502 =
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

#[inline]
fn simple_status(status: StatusCode, msg: &'static str) -> Response<ZionBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from_static(msg.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Request extension: forward the client's `Host` to the upstream instead of the
/// upstream's own authority (`[upstream.x] preserve_host`, ADR-0024). Set once by the
/// dispatcher on the inbound request, read by the forwarding hygiene shared by every
/// proxy path; a path that rebuilds the request carries it over.
#[derive(Clone, Copy, Debug)]
pub struct PreserveHost;

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

    // Shared forwarding hygiene: strip Host + dangerous hop-by-hop /
    // credential headers, enforce the X-Forwarded-For policy, set the
    // X-Real-IP / X-Forwarded-Proto / X-Forwarded-Host trust headers and add this
    // proxy to `Via`. It reads the INBOUND version (for `Via`), so the upstream
    // version is set only afterwards.
    apply_forwarding_hygiene(&mut req, remote_addr, proto, xff_mode);
    // (after the hygiene pass, which reads the INBOUND authority and version)
    *req.uri_mut() = new_uri;
    *req.version_mut() = Version::HTTP_11;
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
    // Capture the inbound host for X-Forwarded-Host before we strip it: the Host header, or the
    // URI authority when there is none (HTTP/2 carries it there and sends no Host header).
    // Whatever X-Forwarded-Host the client sent is discarded either way.
    let inbound_host = req.headers().get(hyper::header::HOST).cloned().or_else(|| {
        req.uri()
            .authority()
            .and_then(|a| hyper::header::HeaderValue::from_str(a.as_str()).ok())
    });
    req.headers_mut().remove("X-Forwarded-Host");
    let preserve_host = req.extensions().get::<PreserveHost>().is_some();
    // RFC 9110 §7.6.3: name this proxy in `Via` (also what loop detection reads).
    let inbound_version = req.version();
    crate::via::append(req.headers_mut(), inbound_version);

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
        // `preserve_host`: the client's host is also the upstream's `Host`, as received
        // (for an HTTP/2 client, its `:authority`). The pooled client only adds `Host` when
        // it is absent, so this survives the URI rewrite.
        if preserve_host {
            req.headers_mut().insert(hyper::header::HOST, host.clone());
        }
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

/// Why reading an upstream response body failed, for the counter and the log.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BodyErrorKind {
    /// The upstream closed the TCP connection without a TLS `close_notify`. For a response
    /// delimited by the close that is indistinguishable from a truncation, so the client's
    /// stream is ended with an error (a reset over HTTP/2) and nothing else says why.
    TlsTruncated,
    Other,
}

fn classify_body_error(e: &(dyn std::error::Error + 'static)) -> BodyErrorKind {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::UnexpectedEof
                && io.to_string().contains("close_notify")
            {
                return BodyErrorKind::TlsTruncated;
            }
        }
        cur = err.source();
    }
    BodyErrorKind::Other
}

/// Count a failed read of an upstream response body and log it (a few lines a minute at
/// most, naming the upstream and nothing of the client or the URL).
fn note_upstream_body_error(upstream: Option<&hyper::http::uri::Authority>, e: &hyper::Error) {
    static TRUNCATED_LOG: crate::logging::Throttle = crate::logging::Throttle::new(1, 10);
    static OTHER_LOG: crate::logging::Throttle = crate::logging::Throttle::new(1, 10);
    let upstream = upstream.map_or("?", |a| a.as_str());
    let m = &crate::metrics::METRICS;
    match classify_body_error(e) {
        BodyErrorKind::TlsTruncated => {
            m.upstream_body_errors_tls_truncated
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if TRUNCATED_LOG.allow() {
                crate::logging::warn(
                    "proxy",
                    &format!(
                        "upstream {upstream} closed the connection without a TLS close_notify; the response is cut off for the client (the upstream should send close_notify, or give the response a Content-Length)"
                    ),
                );
            }
        }
        BodyErrorKind::Other => {
            m.upstream_body_errors_other
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if OTHER_LOG.allow() {
                crate::logging::warn(
                    "proxy",
                    &format!("reading the response body from upstream {upstream} failed: {e}"),
                );
            }
        }
    }
}

/// An upstream response body that reports its failures (see `note_upstream_body_error`).
fn watch_upstream_body(
    body: hyper::body::Incoming,
    upstream: Option<hyper::http::uri::Authority>,
) -> ZionBody {
    body.map_err(move |e| {
        note_upstream_body_error(upstream.as_ref(), &e);
        e
    })
    .boxed()
}

/// Strip hop-by-hop headers from an upstream RESPONSE before relaying it to the
/// client (RFC 9110 §7.6.1). These are meaningful only on the upstream→zion hop;
/// hyper frames the client connection itself, so forwarding the upstream's
/// connection-control headers is at best redundant and at worst a desync /
/// response-smuggling vector on a kept-alive client connection. Removes the
/// standard set plus any header named in the response's own `Connection` token
/// list (RFC 9110 §7.6.1: "intermediaries MUST ... remove ... fields ... listed
/// in the Connection header field").
fn scrub_response_hop_by_hop(headers: &mut hyper::HeaderMap) {
    // Headers nominated by the Connection token list, e.g.
    // `Connection: close, X-Foo` also strips `X-Foo`.
    if let Some(conn) = headers.get(hyper::header::CONNECTION).cloned() {
        if let Ok(conn) = conn.to_str() {
            for token in conn.split(',') {
                let name = token.trim();
                // "close"/"keep-alive" are connection options, not field names.
                if !name.is_empty()
                    && !name.eq_ignore_ascii_case("close")
                    && !name.eq_ignore_ascii_case("keep-alive")
                {
                    headers.remove(name);
                }
            }
        }
    }
    // The standard hop-by-hop set (RFC 9110 §7.6.1 + well-known extras).
    headers.remove(hyper::header::CONNECTION);
    headers.remove(hyper::header::TRANSFER_ENCODING);
    headers.remove(hyper::header::TE);
    headers.remove(hyper::header::TRAILER);
    headers.remove(hyper::header::UPGRADE);
    headers.remove(hyper::header::PROXY_AUTHENTICATE);
    headers.remove("Proxy-Connection");
    headers.remove("Keep-Alive");
}

/// Like [`send_request`] but surfaces the transport error to the caller
/// instead of collapsing it into a 502, so [`proxy_pass_ha`] can decide
/// whether to fail over to another upstream.
#[inline]
async fn send_request_try(
    client: &HttpClient,
    req: Request<ZionBody>,
) -> Result<Response<ZionBody>, hyper_util::client::legacy::Error> {
    let upstream = req.uri().authority().cloned();
    let upstream_start = std::time::Instant::now();
    let result = client.request(req).await;
    crate::metrics::METRICS
        .upstream_duration
        .observe(upstream_start.elapsed());
    let (mut parts, body) = result?.into_parts();
    scrub_response_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(
        parts,
        watch_upstream_body(body, upstream),
    ))
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
    algorithm: crate::pool::Algorithm,
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

    // Buffer the body once so each attempt can replay it. This buffer is held
    // entirely in memory, so it MUST be bounded: a bare `collect()` here lets a
    // client stream an unbounded (or slow-drip) body into an HA route and
    // exhaust RAM — one full copy per concurrent request — regardless of
    // whether the route has a WAF profile. Cap the size (413 on overflow) and
    // the read time (408 on a slowloris drip that never reaches the cap). Both
    // bounds apply before failover, so a rejected body never becomes N upstream
    // attempts either.
    let (parts, body) = req.into_parts();
    let limited = Limited::new(body, MAX_HA_REPLAY_BODY);
    let body_bytes = match tokio::time::timeout(HA_BODY_COLLECT_TIMEOUT, limited.collect()).await {
        Ok(Ok(c)) => c.to_bytes(),
        // `Limited` surfaces overflow as a boxed `LengthLimitError`; any other
        // collect error is a broken client stream → 400. Distinguish so an
        // operator sees "too large" separately from "client hung up".
        Ok(Err(e))
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            return Ok(simple_status(
                StatusCode::PAYLOAD_TOO_LARGE,
                "413 Payload Too Large",
            ));
        }
        Ok(Err(_)) => return Ok(simple_status(StatusCode::BAD_REQUEST, "400 Bad Request")),
        Err(_elapsed) => {
            return Ok(simple_status(
                StatusCode::REQUEST_TIMEOUT,
                "408 Request Timeout",
            ));
        }
    };
    let method = parts.method.clone();
    let uri = parts.uri.clone();
    let version = parts.version;
    let headers = parts.headers.clone();
    let preserve_host = parts.extensions.get::<PreserveHost>().is_some();
    let attempt_timeout = parts
        .extensions
        .get::<RequestTimeout>()
        .map_or(UPSTREAM_REQUEST_TIMEOUT, |t| t.0);
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
    // Members this request already waited out: a timeout does not mark a member down
    // (slow is not dead), so it is left out of this request's later picks instead.
    let mut candidates: Vec<String> = pool.to_vec();
    let mut timed_out = false;
    for _ in 0..pool.len() {
        let url = match crate::pool::pick(
            health_map,
            &candidates,
            algorithm,
            crate::breaker::now_ms(),
            &mut |n| fastrand::usize(..n),
        ) {
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
        if preserve_host {
            attempt.extensions_mut().insert(PreserveHost);
        }

        let Some(prepared) =
            prepare_request(attempt, &scheme, &authority, remote_addr, proto, xff_mode)
        else {
            return Ok(bad_gateway());
        };

        // Live load and latency of this member, for the next pick; the guard keeps the
        // in-flight count honest on every exit path.
        let member = health_map.get(&url);
        let _in_flight = member.map(|h| h.pool.begin());
        let started = std::time::Instant::now();
        // Bounded like the single-upstream path: a member that accepts the connection
        // and never answers must not hold the request until the connection cap.
        let Ok(outcome) =
            tokio::time::timeout(attempt_timeout, send_request_try(client, prepared)).await
        else {
            // Slow is not dead: no eager ejection; the pool stats count the failure.
            crate::pool::report(
                health_map,
                pool,
                &url,
                false,
                None,
                crate::breaker::now_ms(),
            );
            crate::metrics::METRICS
                .upstream_failovers_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::logging::warn(
                "proxy",
                &format!(
                    "upstream {} timeout after {attempt_timeout:?}",
                    crate::http_util::redact_userinfo(&url)
                ),
            );
            timed_out = true;
            candidates.retain(|c| c != &url);
            // The request may have been processed: replay only an idempotent one.
            if !idempotent {
                return Ok(gateway_timeout());
            }
            continue;
        };
        let took_us = started.elapsed().as_micros() as u64;
        let ok = matches!(&outcome, Ok(r) if !crate::breaker::is_failure(r.status().as_u16()));
        crate::pool::report(
            health_map,
            pool,
            &url,
            ok,
            outcome.is_ok().then_some(took_us),
            crate::breaker::now_ms(),
        );
        match outcome {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                timed_out = false;
                let connect = e.is_connect();
                crate::metrics::METRICS
                    .upstream_failovers_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                crate::logging::warn(
                    "proxy",
                    &format!(
                        "failover: upstream {} error (connect={connect}): {e}",
                        crate::http_util::redact_userinfo(&url)
                    ),
                );
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
    // Every member failed: 504 when the last one timed out, 502 otherwise.
    Ok(if timed_out {
        gateway_timeout()
    } else {
        bad_gateway()
    })
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
    let upstream = req.uri().authority().cloned();

    match client.request(req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            scrub_response_hop_by_hop(&mut parts.headers);
            parts.headers.insert(
                "Cache-Control",
                hyper::header::HeaderValue::from_static("no-cache"),
            );
            parts.headers.insert(
                "X-Accel-Buffering",
                hyper::header::HeaderValue::from_static("no"),
            );
            Ok(Response::from_parts(
                parts,
                watch_upstream_body(body, upstream),
            ))
        }
        Err(e) => {
            crate::logging::warn("proxy", &format!("stream proxy error: {e}"));
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

/// Default upper bound on a single upstream request/response
/// ([`DEFAULT_REQUEST_TIMEOUT_MS`]; `[upstream.x] request_timeout_ms` overrides it per
/// upstream through [`RequestTimeout`]). A hung or black-holed
/// backend (TCP/TLS completes but the HTTP response never arrives, or arrives
/// at a trickle) would otherwise pin the request (and the conn-limit permit
/// plus per-IP slot it holds) up to the 1h connection cap — a DoS amplifier.
/// 504 on elapse. The per-upstream `connect_timeout_ms` bounds only the TCP
/// connect (it is applied to the connector, see `build_http_client`); this
/// overall bound is what closes a hang *after* connect. It applies to every attempt of a
/// pool too (see [`proxy_pass_ha`]).
const UPSTREAM_REQUEST_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS);

/// Hard ceiling on a request body buffered for HA replay. Failover has to hold
/// the whole body in memory to resend it, so this bounds per-request RAM on
/// Standard (multi-upstream) routes independently of any WAF `max_body_mb`.
/// 16 MiB comfortably covers ordinary API/form payloads; genuinely large
/// uploads belong on a single-upstream (streaming) route, not an HA-replay one.
const MAX_HA_REPLAY_BODY: usize = 16 * 1024 * 1024;

/// Wall-clock cap on reading the replay body. Stops a slowloris drip from
/// pinning a worker (and its per-IP conn slot) indefinitely while never
/// reaching `MAX_HA_REPLAY_BODY`.
const HA_BODY_COLLECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Internal: send a prepared request through the shared client.
#[inline]
/// `upstream=<scheme://authority> trace_id=<32 hex>` for a log line about this upstream
/// request: which backend failed, and the join key to the access log, the audit record
/// and the trace (`-` when the request carries no traceparent).
fn upstream_context<B>(req: &Request<B>) -> String {
    let uri = req.uri();
    let target = match (uri.scheme_str(), uri.authority()) {
        // An authority can carry `user:pass@`: never into a log line.
        (Some(s), Some(a)) => crate::http_util::redact_userinfo(&format!("{s}://{a}")),
        _ => "-".to_string(),
    };
    let trace = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(|tp| tp.split('-').nth(1))
        .filter(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or("-");
    format!("upstream={target} trace_id={trace}")
}

async fn send_request(
    client: &HttpClient,
    req: Request<ZionBody>,
) -> Result<Response<ZionBody>, hyper::Error> {
    let context = upstream_context(&req);
    let upstream = req.uri().authority().cloned();
    let deadline = request_timeout(&req);
    let upstream_start = std::time::Instant::now();
    match tokio::time::timeout(deadline, client.request(req)).await {
        Ok(Ok(resp)) => {
            crate::metrics::METRICS
                .upstream_duration
                .observe(upstream_start.elapsed());
            let (mut parts, body) = resp.into_parts();
            scrub_response_hop_by_hop(&mut parts.headers);
            Ok(Response::from_parts(
                parts,
                watch_upstream_body(body, upstream),
            ))
        }
        Ok(Err(e)) => {
            crate::metrics::METRICS
                .upstream_duration
                .observe(upstream_start.elapsed());
            crate::logging::warn("proxy", &format!("upstream error: {e} {context}"));
            Ok(bad_gateway())
        }
        Err(_elapsed) => {
            crate::metrics::METRICS
                .upstream_duration
                .observe(upstream_start.elapsed());
            crate::logging::warn(
                "proxy",
                &format!("upstream timeout after {deadline:?} {context}"),
            );
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
    // The handshake goes over a bare HTTP/1.1 connection (below), which sends the request
    // as given: it adds no `Host` and writes an absolute URI as is. So the request target
    // must be origin-form (`/path?query`) and `Host` set here, or strict servers (RFC 9112
    // §3.2: Go net/http, among others) answer the upgrade 400.
    let path_and_query = req
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| hyper::http::uri::PathAndQuery::from_static("/"));
    let Ok(origin_form) = hyper::Uri::builder().path_and_query(path_and_query).build() else {
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
    let tcp_stream = match crate::dns::connect_tcp(&connect_target).await {
        Ok(s) => s,
        Err(e) => {
            crate::logging::warn(
                "ws",
                &format!("upstream connect failed ({connect_target}): {e}"),
            );
            return Ok(bad_gateway());
        }
    };
    let _ = tcp_stream.set_nodelay(true);
    crate::net::tune_accepted(&tcp_stream);
    crate::net::set_keepalive(&tcp_stream, crate::net::DEFAULT_TCP_KEEPALIVE_SECS);

    // Perform HTTP upgrade handshake with upstream
    // Same forwarding hygiene as the normal proxy (strip Host + dangerous
    // hop-by-hop / credential headers — notably Proxy-Authorization — and set
    // the X-Forwarded-* / X-Real-IP trust headers per the XFF policy), but
    // KEEP Connection + Upgrade, which carry the WebSocket handshake. The old
    // path stripped only Host, so it leaked Proxy-Authorization and a spoofed
    // X-Forwarded-For straight to the upstream.
    apply_forwarding_hygiene(&mut req, remote_addr, proto, xff_mode);
    // (after the hygiene pass, which reads the INBOUND authority for X-Forwarded-Host)
    *req.uri_mut() = origin_form;
    *req.version_mut() = Version::HTTP_11;
    // The upstream's own authority, without a default port, as the pooled client sends it.
    let default_port = if is_tls_upstream { 443 } else { 80 };
    let host_value = match authority.port_u16() {
        Some(p) if p != default_port => authority.as_str().to_string(),
        _ => authority.host().to_string(),
    };
    let Ok(host_value) = HeaderValue::from_str(&host_value) else {
        return Ok(bad_gateway());
    };
    // Unless `preserve_host` kept the client's.
    req.headers_mut()
        .entry(hyper::header::HOST)
        .or_insert(host_value);

    // HTTP/1.1 upgrade handshake — works on any AsyncRead+AsyncWrite stream.
    // For TLS upstreams, wrap in tokio-rustls connector first.
    if is_tls_upstream {
        // The upstream's own TLS settings when it has any (private CA, client
        // certificate); otherwise one cached config with the public roots, built once
        // (re-parsing ~150 CA roots on every WebSocket connection would be wasteful).
        static WS_TLS_CONFIG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
            std::sync::OnceLock::new();
        let tls_config = match req.extensions().get::<UpstreamTlsMark>() {
            Some(mark) => mark.0.client_config(),
            None => WS_TLS_CONFIG
                .get_or_init(|| {
                    let mut root_store = rustls::RootCertStore::empty();
                    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    std::sync::Arc::new(
                        rustls::ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_no_client_auth(),
                    )
                })
                .clone(),
        };
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
                crate::logging::warn(
                    "ws",
                    &format!("upstream TLS handshake failed ({connect_target}): {e}"),
                );
                return Ok(bad_gateway());
            }
        };

        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(r) => r,
            Err(e) => {
                crate::logging::warn("ws", &format!("upstream handshake failed: {e}"));
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
            crate::logging::warn("ws", &format!("upstream handshake failed: {e}"));
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
            crate::logging::warn("ws", &format!("upstream request failed: {e}"));
            return Ok(bad_gateway());
        }
    };

    // If upstream didn't 101, return that response as-is — but still strip
    // hop-by-hop headers (RFC 9110 §7.6.1), same as the normal proxy return
    // paths. A declined WS upgrade is a normal HTTP response and must not leak
    // the upstream's Connection/Keep-Alive/Transfer-Encoding to the client.
    if upstream_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (mut parts, body) = upstream_resp.into_parts();
        scrub_response_hop_by_hop(&mut parts.headers);
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
            crate::logging::warn("ws", &format!("upstream upgrade failed: {e}"));
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
        // Bound the upgrade handoff itself. `on_client_upgrade` normally
        // resolves near-instantly (right after the 101 is written), but a
        // client that vanishes in that window can otherwise leave this future
        // pending forever — pinning `upstream_upgraded`'s socket FD for the
        // whole process lifetime, since the idle/session timeouts below only
        // start once the upgrade has resolved. A short cap guarantees the
        // upstream socket is released when the handoff never completes.
        const UPGRADE_HANDOFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
        let client_upgraded =
            match tokio::time::timeout(UPGRADE_HANDOFF_TIMEOUT, on_client_upgrade).await {
                Ok(Ok(c)) => c,
                // Timed out or the upgrade errored → return, dropping
                // `upstream_upgraded` and freeing its FD.
                _ => return,
            };
        let mut c = hyper_util::rt::TokioIo::new(client_upgraded);
        let mut u = hyper_util::rt::TokioIo::new(upstream_upgraded);

        let max_session = std::time::Duration::from_secs(24 * 60 * 60);
        let idle_timeout = std::time::Duration::from_secs(5 * 60);

        let session_deadline = tokio::time::Instant::now() + max_session;

        let ws_pipe = async {
            // copy_bidirectional runs until either side closes or errors.
            // The idle timeout tears down completely silent sessions.
            let _ =
                tokio::time::timeout(idle_timeout, tokio::io::copy_bidirectional(&mut c, &mut u))
                    .await;
        };

        // Cap total session at the absolute deadline.
        let _ = tokio::time::timeout_at(session_deadline, ws_pipe).await;
    });

    Ok(resp)
}

#[cfg(test)]
mod tests {
    /// The error as hyper hands it over: the I/O error is a link in a chain, not the top.
    #[derive(Debug)]
    struct Wrapped(Box<dyn std::error::Error + Send + Sync>);
    impl std::fmt::Display for Wrapped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("error reading a body from connection")
        }
    }
    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&*self.0)
        }
    }

    #[test]
    fn a_tls_close_without_close_notify_is_told_from_other_body_errors() {
        use std::io::{Error, ErrorKind};
        let eof = Error::new(
            ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof",
        );
        assert_eq!(
            super::classify_body_error(&Wrapped(Box::new(eof))),
            super::BodyErrorKind::TlsTruncated
        );
        // Another unexpected EOF (a plain connection that dropped) is not that.
        let plain = Error::new(
            ErrorKind::UnexpectedEof,
            "connection closed before message completed",
        );
        assert_eq!(
            super::classify_body_error(&Wrapped(Box::new(plain))),
            super::BodyErrorKind::Other
        );
        // Nor is another kind of error that happens to mention it.
        let reset = Error::new(ErrorKind::ConnectionReset, "no close_notify here");
        assert_eq!(
            super::classify_body_error(&Wrapped(Box::new(reset))),
            super::BodyErrorKind::Other
        );
    }

    /// Time a GET to a black-holed address (TEST-NET-1: packets dropped, no RST) on
    /// a client built with `connect_timeout_ms`, capped at `cap` so a client with no
    /// deadline cannot hold the test for the full 30s.
    async fn time_blackhole(
        connect_timeout_ms: u64,
        cap: std::time::Duration,
    ) -> std::time::Duration {
        use http_body_util::BodyExt;
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = build_http_client(connect_timeout_ms, false);
        let req = Request::builder()
            .uri("http://192.0.2.1:81/")
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();
        let started = std::time::Instant::now();
        let _ = tokio::time::timeout(cap, client.request(req)).await;
        started.elapsed()
    }

    #[tokio::test]
    async fn connect_timeout_is_applied_to_the_connector() {
        // ZION-REL-01: with a 300ms connect deadline the attempt is abandoned
        // quickly instead of waiting for the 30s request timeout. (On a network
        // that answers ENETUNREACH at once this passes trivially; on one that drops
        // the packets it is the real check.)
        let bounded = time_blackhole(300, std::time::Duration::from_secs(10)).await;
        assert!(
            bounded < std::time::Duration::from_secs(4),
            "a 300ms connect deadline must abandon a black-holed connect fast, took {bounded:?}"
        );
    }

    #[test]
    fn default_connect_timeout_is_in_sync_with_the_config_default() {
        assert_eq!(
            crate::config::default_connect_timeout(),
            DEFAULT_CONNECT_TIMEOUT_MS
        );
    }

    use super::*;

    #[test]
    fn upstream_log_lines_name_the_upstream_and_the_trace() {
        let req = Request::builder()
            .uri("http://10.0.0.5:8000/api/x?q=1")
            .header(
                "traceparent",
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            )
            .body(())
            .unwrap();
        assert_eq!(
            upstream_context(&req),
            "upstream=http://10.0.0.5:8000 trace_id=0af7651916cd43dd8448eb211c80319c"
        );
        let bare = Request::builder().uri("/relative").body(()).unwrap();
        assert_eq!(upstream_context(&bare), "upstream=- trace_id=-");
        let bad = Request::builder()
            .uri("https://api.internal/")
            .header("traceparent", "garbage")
            .body(())
            .unwrap();
        assert_eq!(
            upstream_context(&bad),
            "upstream=https://api.internal trace_id=-"
        );
    }
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
    fn scrub_strips_response_hop_by_hop_headers() {
        // RFC 9110 §7.6.1: the upstream response's hop-by-hop headers + any
        // header it names in `Connection` must not reach the client; end-to-end
        // headers must survive.
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::CONNECTION,
            "keep-alive, X-Custom-Hop".parse().unwrap(),
        );
        headers.insert(hyper::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert("Keep-Alive", "timeout=5".parse().unwrap());
        headers.insert("X-Custom-Hop", "secret".parse().unwrap());
        headers.insert(hyper::header::CONTENT_TYPE, "text/html".parse().unwrap());
        headers.insert("X-Keep-Me", "ok".parse().unwrap());

        scrub_response_hop_by_hop(&mut headers);

        // standard hop-by-hop stripped
        assert!(headers.get(hyper::header::CONNECTION).is_none());
        assert!(headers.get(hyper::header::TRANSFER_ENCODING).is_none());
        assert!(headers.get("Keep-Alive").is_none());
        // header nominated by the Connection token list stripped
        assert!(headers.get("X-Custom-Hop").is_none());
        // end-to-end headers preserved
        assert_eq!(
            headers.get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/html"
        );
        assert_eq!(headers.get("X-Keep-Me").unwrap(), "ok");
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

    #[tokio::test]
    async fn ha_replay_rejects_oversized_body_before_dialing() {
        // A body past MAX_HA_REPLAY_BODY must be refused with 413 at the buffer
        // step — before any upstream is selected or dialed, so an oversized
        // payload never becomes N connection attempts and never sits unbounded
        // in RAM. An empty health map guarantees that if we *did* reach the
        // failover loop, select_best_upstream would return None and we'd see a
        // 502 instead — so a 413 here proves the bound fired first.
        // The HTTPS client build needs a process-level rustls provider; the
        // daemon installs this at boot (main.rs). Idempotent, so safe here.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let oversized = vec![0u8; MAX_HA_REPLAY_BODY + 1];
        let body: ZionBody = Full::new(Bytes::from(oversized))
            .map_err(|never| match never {})
            .boxed();
        let req = Request::builder()
            .method("POST")
            .uri("/upload")
            .body(body)
            .unwrap();

        let pool = vec![
            "http://127.0.0.1:9/a".to_string(),
            "http://127.0.0.1:9/b".to_string(),
        ];
        let health_map: crate::health::HealthMap = std::sync::Arc::new(Default::default());

        let resp = proxy_pass_ha(
            &build_http_client(DEFAULT_CONNECT_TIMEOUT_MS, false),
            req,
            &pool,
            &scheme(),
            &authority(),
            &health_map,
            crate::pool::Algorithm::default(),
            None,
            "https",
            XffMode::Append,
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
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
    /// What `UpstreamTls::load` refuses without opening a valid certificate: the real
    /// handshakes are in tests/upstream_mtls.rs.
    #[test]
    fn upstream_tls_load_refuses_incomplete_or_missing_material() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let e = UpstreamTls::load(None, Some("/c.pem"), None).unwrap_err();
        assert!(e.contains("must be set together"), "{e}");
        let e = UpstreamTls::load(Some("/no/such/ca.pem"), None, None).unwrap_err();
        assert!(e.contains("ca_path /no/such/ca.pem"), "{e}");
        let dir = std::env::temp_dir().join(format!("zion-upstream-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        let e = UpstreamTls::load(Some(&empty.to_string_lossy()), None, None).unwrap_err();
        assert!(e.contains("no certificate in the file"), "{e}");
        let e = UpstreamTls::load(None, Some("/no/c.pem"), Some("/no/k.pem")).unwrap_err();
        assert!(e.contains("client certificate"), "{e}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
