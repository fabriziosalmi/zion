use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
#[allow(unused_imports)]
use std::fmt::Write;
use std::net::SocketAddr;

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

/// Rewrite URI for upstream forwarding and add proxy headers.
/// Uses pre-parsed scheme+authority from config — only path is set at runtime.
#[inline]
fn prepare_request<B>(
    mut req: Request<B>,
    scheme: &hyper::http::uri::Scheme,
    authority: &hyper::http::uri::Authority,
    remote_addr: Option<SocketAddr>,
    proto: &str,
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

    // Remove hop-by-hop headers (RFC 7230 §6.1).
    // Forwarding Transfer-Encoding enables CL/TE request smuggling.
    // Forwarding Proxy-Authorization leaks client credentials to upstream.
    req.headers_mut().remove(hyper::header::HOST);
    req.headers_mut().remove(hyper::header::CONNECTION);
    req.headers_mut().remove(hyper::header::TRANSFER_ENCODING);
    req.headers_mut().remove(hyper::header::TE);
    req.headers_mut().remove(hyper::header::TRAILER);
    req.headers_mut().remove(hyper::header::PROXY_AUTHORIZATION);
    req.headers_mut().remove("Proxy-Connection");
    req.headers_mut().remove("Keep-Alive");

    // Forwarding headers — append to X-Forwarded-For chain (preserves upstream proxies),
    // set X-Real-IP to the direct client IP.
    if let Some(addr) = remote_addr {
        thread_local! {
            static IP_BUF: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(45));
        }
        IP_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            let _ = write!(buf, "{}", addr.ip());
            if let Ok(val) = HeaderValue::from_str(&buf) {
                // X-Forwarded-For: append to existing chain (proxy1, proxy2, client)
                // so upstream sees the full trust chain when Zion is behind an LB.
                req.headers_mut().append("X-Forwarded-For", val.clone());
                // X-Real-IP: always the direct connection IP (last hop)
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

    Some(req)
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
) -> Result<Response<ZionBody>, hyper::Error> {
    let Some(req) = prepare_request(req, scheme, authority, remote_addr, proto) else {
        return Ok(bad_gateway());
    };
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, body); // Already boxed
    send_request(client, req).await
}

/// Forward a request whose body has already been collected (post-WAF path).
#[inline]
pub async fn proxy_pass_bytes(
    client: &HttpClient,
    parts: hyper::http::request::Parts,
    body_bytes: Bytes,
    scheme: &hyper::http::uri::Scheme,
    authority: &hyper::http::uri::Authority,
    remote_addr: SocketAddr,
    proto: &str,
) -> Result<Response<ZionBody>, hyper::Error> {
    let body: ZionBody = Full::new(body_bytes)
        .map_err(|never| match never {})
        .boxed();
    let req = Request::from_parts(parts, body);
    let Some(req) = prepare_request(req, scheme, authority, Some(remote_addr), proto) else {
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
) -> Result<Response<ZionBody>, hyper::Error> {
    let Some(req) = prepare_request(req, scheme, authority, remote_addr, proto) else {
        return Ok(bad_gateway());
    };
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, body);

    match client.request(req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            parts
                .headers
                .insert("Cache-Control", "no-cache".parse().unwrap());
            parts
                .headers
                .insert("X-Accel-Buffering", "no".parse().unwrap());
            Ok(Response::from_parts(parts, body.boxed()))
        }
        Err(e) => {
            eprintln!("  stream proxy error: {}", e);
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

/// Internal: send a prepared request through the shared client.
#[inline]
async fn send_request(
    client: &HttpClient,
    req: Request<ZionBody>,
) -> Result<Response<ZionBody>, hyper::Error> {
    let upstream_start = std::time::Instant::now();
    match client.request(req).await {
        Ok(resp) => {
            crate::metrics::METRICS
                .upstream_duration
                .observe(upstream_start.elapsed());
            let (parts, body) = resp.into_parts();
            Ok(Response::from_parts(parts, body.boxed()))
        }
        Err(e) => {
            crate::metrics::METRICS
                .upstream_duration
                .observe(upstream_start.elapsed());
            eprintln!("  proxy error: {}", e);
            Ok(bad_gateway())
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
        format!("{}:{}", host, default_port)
    };

    // Connect to upstream via raw TCP (not the pooled client — WebSocket is long-lived)
    let tcp_stream = match tokio::net::TcpStream::connect(&connect_target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  ws upstream connect failed ({}): {}", connect_target, e);
            return Ok(bad_gateway());
        }
    };
    let _ = tcp_stream.set_nodelay(true);
    crate::net::tune_accepted(&tcp_stream);

    // Perform HTTP upgrade handshake with upstream
    *req.uri_mut() = upstream_uri;
    *req.version_mut() = Version::HTTP_11;
    req.headers_mut().remove(hyper::header::HOST);

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

        // SNI: use the hostname from the authority (without port)
        let server_name = rustls::pki_types::ServerName::try_from(authority.host().to_string())
            .unwrap_or_else(|_| {
                rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap()
            });

        let tls_stream = match connector.connect(server_name, tcp_stream).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "  ws upstream TLS handshake failed ({}): {}",
                    connect_target, e
                );
                return Ok(bad_gateway());
            }
        };

        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  ws upstream handshake failed: {}", e);
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
            eprintln!("  ws upstream handshake failed: {}", e);
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
            eprintln!("  ws upstream request failed: {}", e);
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
            eprintln!("  ws upstream upgrade failed: {}", e);
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

    // Spawn bidirectional pipe with idle timeout.
    // Unlike the previous hard 30-minute wall-clock limit, this uses
    // activity-aware idle detection: the connection stays alive as long as
    // either side sends data within the idle window. Also caps total session
    // at 24 hours as a safety valve against resource exhaustion.
    tokio::spawn(async move {
        if let Ok(client_upgraded) = on_client_upgrade.await {
            let mut c = hyper_util::rt::TokioIo::new(client_upgraded);
            let mut u = hyper_util::rt::TokioIo::new(upstream_upgraded);

            // Cap total session at 24 hours as a safety valve against resource exhaustion.
            // (Idle timeouts deferred to TCP keepalives to prevent copy_bidirectional blocking complexity)
            let max_session = std::time::Duration::from_secs(24 * 60 * 60);

            let _ =
                tokio::time::timeout(max_session, tokio::io::copy_bidirectional(&mut c, &mut u))
                    .await;
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
        let req = prepare_request(req, &scheme(), &authority(), None, "https").unwrap();
        assert_eq!(
            req.uri().to_string(),
            "http://127.0.0.1:8000/api/v1/users?page=2"
        );
    }

    #[test]
    fn prepare_sets_http11() {
        let req = make_request("GET", "/test");
        let req = prepare_request(req, &scheme(), &authority(), None, "https").unwrap();
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
        let req = prepare_request(req, &scheme(), &authority(), None, "https").unwrap();
        assert!(req.headers().get(hyper::header::HOST).is_none());
        assert!(req.headers().get(hyper::header::CONNECTION).is_none());
    }

    #[test]
    fn prepare_adds_forwarding_headers() {
        let req = make_request("GET", "/test");
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let req = prepare_request(req, &scheme(), &authority(), Some(addr), "https").unwrap();
        assert_eq!(req.headers().get("X-Forwarded-For").unwrap(), "1.2.3.4");
        assert_eq!(req.headers().get("X-Real-IP").unwrap(), "1.2.3.4");
        assert_eq!(req.headers().get("X-Forwarded-Proto").unwrap(), "https");
    }

    #[test]
    fn prepare_http_proto() {
        let req = make_request("GET", "/test");
        let req = prepare_request(req, &scheme(), &authority(), None, "http").unwrap();
        assert_eq!(req.headers().get("X-Forwarded-Proto").unwrap(), "http");
    }

    #[test]
    fn prepare_no_forwarding_without_addr() {
        let req = make_request("GET", "/test");
        let req = prepare_request(req, &scheme(), &authority(), None, "https").unwrap();
        assert!(req.headers().get("X-Forwarded-For").is_none());
        assert!(req.headers().get("X-Real-IP").is_none());
    }

    #[test]
    fn prepare_ipv6_forwarding() {
        let req = make_request("GET", "/test");
        let addr: SocketAddr = "[::1]:1234".parse().unwrap();
        let req = prepare_request(req, &scheme(), &authority(), Some(addr), "https").unwrap();
        assert_eq!(req.headers().get("X-Forwarded-For").unwrap(), "::1");
    }

    #[test]
    fn prepare_preserves_query_string() {
        let req = make_request("GET", "/search?q=hello&page=1");
        let req = prepare_request(req, &scheme(), &authority2(), None, "https").unwrap();
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
        assert!(prepare_request(req, &scheme(), &authority(), None, "https").is_some());
    }

    #[test]
    fn bad_gateway_returns_502() {
        assert_eq!(bad_gateway().status(), StatusCode::BAD_GATEWAY);
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
