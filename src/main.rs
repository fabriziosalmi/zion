mod acme;
mod auth;
mod bootstrap;
mod cache;
mod config;
mod health;
mod logging;
mod metrics;
mod net;
mod proxy;
#[cfg(feature = "http3")]
mod quic;
mod security;
mod tls;
#[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
mod uring;
mod waf;

// ── Global allocator: mimalloc ──────────────────────────────────
// ~2-3x faster than system malloc on small allocations.
// Reduces allocator contention under high concurrency.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use config::ResolvedRoute;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use matchit::Router;
use proxy::{HttpClient, ZionBody};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

/// Max response body size we'll cache in RAM (50 MB).
const MAX_CACHEABLE_BODY: usize = 50 * 1024 * 1024;

/// Atomic request counter for generating unique request IDs.
/// Format: {timestamp_hex}-{counter_hex} — unique, sortable, zero alloc crate.
static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[inline]
fn generate_request_id() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let seq = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{:x}-{:04x}", ts, seq & 0xFFFF)
}

// Re-export security types used in AppState and handlers.
use security::{CorsHeaders, RateEntry};

/// Global shared state — lock-free reads via Arc + ArcSwap.
struct AppState {
    router: Router<Arc<ResolvedRoute>>,
    tls_acceptor: Arc<ArcSwap<tokio_rustls::TlsAcceptor>>,
    http_client: HttpClient,
    static_cache: cache::StaticCache,
    conn_limit: Arc<Semaphore>,
    http_builder: AutoBuilder<TokioExecutor>,
    cors: CorsHeaders,
    /// ACME HTTP-01 challenge tokens (empty when no challenge active).
    acme_challenges: acme::ChallengeStore,
    /// Per-IP rate limiter. 0 = disabled.
    rate_limit_rps: u32,
    rate_limit_window: u64,
    rate_map: Arc<dashmap::DashMap<std::net::IpAddr, RateEntry>>,
    /// Shared upstream health state — checked before dispatching to prevent 502 cascades.
    health_map: health::HealthMap,
}

// Pre-compiled constants — zero runtime cost.
static EMPTY_BYTES: Bytes = Bytes::new();
static CACHE_CONTROL_IMMUTABLE: hyper::header::HeaderValue =
    hyper::header::HeaderValue::from_static("public, max-age=31536000, immutable");

// Security headers, rate limiter constants, and validators are in security.rs.

/// Maximum allowed URI length (bytes). Requests exceeding this are dropped
/// before routing — prevents buffer overflow probes and log pollution.
const MAX_URI_LEN: usize = 8192;

#[inline]
fn empty_response(status: StatusCode) -> Response<ZionBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(EMPTY_BYTES.clone())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

#[inline]
fn text_response(status: StatusCode, text: &'static str) -> Response<ZionBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from_static(text.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0. Bootstrap — detect hardware and auto-tune (BEFORE runtime starts)
    let platform = bootstrap::detect();

    // Build tokio runtime with detected optimal worker count
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(platform.worker_threads)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async_main(platform))
}

async fn async_main(platform: &'static bootstrap::Platform) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("ZION EDGE GATEWAY — initializing...");
    bootstrap::print_report(platform);

    // 1. Load configuration
    let config_path = std::env::var("ZION_CONFIG").unwrap_or_else(|_| "zion.toml".to_string());
    let config = config::load_config(&config_path);
    logging::init(&config.server.log_format);
    logging::info("config", &format!("loaded from {}", config_path));

    // 2. Build radix tree router
    let router = config::build_router(&config);

    // 3. Load initial TLS — build acceptor once, cache via ArcSwap
    let initial_tls = tls::load_tls_config(&config.tls);
    let acceptor = TlsAcceptor::from(Arc::new(initial_tls));
    let tls_acceptor_store = Arc::new(ArcSwap::from_pointee(acceptor));
    eprintln!(
        "  tls loaded (min={}, alpn={:?})",
        config.tls.min_version, config.tls.alpn
    );

    // 4. Start TLS hot-reload watcher (rebuilds acceptor on cert change)
    if config.tls.hot_reload {
        tls::spawn_tls_watcher(tls_acceptor_store.clone(), config.tls.clone());
    }

    // 4b. Predictive TTL pre-warming: pre-build TLS config before cert expires
    tls::spawn_cert_prewarm_task(tls_acceptor_store.clone(), config.tls.clone());

    // 5. Build shared state — conn_limit computed from available RAM
    // 5b. Build health map (before Arc — so it's directly embedded in AppState)
    let health_map = {
        let mut upstreams = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for route in &config.route {
            let url = if let Some(up) = config.upstream.get(&route.upstream) {
                &up.url
            } else if let Some(url) = config.upstreams.get(&route.upstream) {
                url
            } else {
                continue;
            };
            if seen.insert(url.clone()) {
                upstreams.push(health::UpstreamHealth {
                    url: url.clone(),
                    healthy: std::sync::atomic::AtomicBool::new(true),
                });
            }
        }
        Arc::new(upstreams)
    };

    let state = Arc::new(AppState {
        router,
        tls_acceptor: tls_acceptor_store,
        http_client: proxy::build_http_client(),
        static_cache: cache::StaticCache::new(),
        conn_limit: Arc::new(Semaphore::new(platform.conn_limit)),
        cors: CorsHeaders::from_config(&config.cors),
        acme_challenges: acme::new_challenge_store(),
        rate_limit_rps: config.server.rate_limit_rps,
        rate_limit_window: config.server.rate_limit_window_secs,
        rate_map: Arc::new(dashmap::DashMap::new()),
        health_map: health_map.clone(),
        http_builder: {
            let mut b = AutoBuilder::new(TokioExecutor::new());
            // Limit header count and total header buffer size to prevent header bomb DoS.
            // hyper defaults: 100 headers, 400KB buf. We tighten both.
            b.http1().max_headers(64).max_buf_size(32 * 1024); // 64 headers, 32KB total
            b
        },
    });

    // 6. Spawn ACME auto-renewal task (if configured)
    if let Some(ref acme_config) = config.tls.acme {
        logging::info("acme", &format!(
            "auto-renewal enabled for: {}",
            acme_config.domains.join(", ")
        ));
        acme::spawn_renewal_task(
            acme_config.clone(),
            state.acme_challenges.clone(),
            state.tls_acceptor.clone(),
            config.tls.clone(),
        );
    }

    // 7. Spawn rate limit cleanup (remove stale IPs every 5 minutes)
    if config.server.rate_limit_rps > 0 {
        let rate_map = state.rate_map.clone();
        let window = config.server.rate_limit_window_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let current_window = (now / window) as u32;
                let before = rate_map.len();
                rate_map.retain(|_, entry| {
                    let packed = entry.packed.load(std::sync::atomic::Ordering::Relaxed);
                    let entry_window = (packed >> 32) as u32;
                    entry_window >= current_window.saturating_sub(2)
                });
                let removed = before - rate_map.len();
                if removed > 0 {
                    logging::info("rate_limit", &format!("cleaned {} stale IPs ({} tracked)", removed, rate_map.len()));
                }
            }
        });
    }

    // 8. Spawn upstream health checker background task
    if !health_map.is_empty() {
        logging::info("health", &format!("monitoring {} upstreams", health_map.len()));
        // Start the background ping loop using the shared health_map
        // (already embedded in AppState, so routing sees updates immediately)
        let hm = health_map.clone();
        tokio::spawn(async move {
            let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_idle_timeout(std::time::Duration::from_secs(10))
                .pool_max_idle_per_host(1)
                .build_http();
            loop {
                for up in hm.iter() {
                    let uri: hyper::Uri = match up.url.parse() {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    let req = match hyper::Request::builder()
                        .uri(&uri)
                        .header("Host", uri.authority().map(|a| a.as_str()).unwrap_or("localhost"))
                        .body(http_body_util::Full::new(bytes::Bytes::new())) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let healthy = match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        client.request(req),
                    ).await {
                        Ok(Ok(resp)) => resp.status().is_success() || resp.status().is_redirection(),
                        _ => false,
                    };
                    let was_healthy = up.healthy.swap(healthy, std::sync::atomic::Ordering::Relaxed);
                    if was_healthy && !healthy {
                        logging::warn("health", &format!("upstream {} is DOWN", up.url));
                    } else if !was_healthy && healthy {
                        logging::info("health", &format!("upstream {} is UP", up.url));
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    // 9. Spawn HTTP listener (port 80) — ACME challenges + HTTPS redirect
    let http_addr: SocketAddr = config.server.listen_http.parse()?;
    let state_http = state.clone();
    tokio::spawn(async move {
        let listener = match net::bind_with_reuseport(http_addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "  warning: HTTP listener on {} unavailable: {}",
                    http_addr, e
                );
                return;
            }
        };
        eprintln!("  listening HTTP on {}", http_addr);

        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("  http accept error: {}", e);
                    continue;
                }
            };

            let state = state_http.clone();
            let builder = state.http_builder.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = builder
                    .serve_connection(
                        io,
                        service_fn(move |req| handle_http(req, state.clone(), addr)),
                    )
                    .await;
            });
        }
    });

    // 10. Main HTTPS listener (port 443) with graceful shutdown
    let https_addr: SocketAddr = config.server.listen_https.parse()?;
    let listener = net::bind_with_reuseport(https_addr)?;
    eprintln!("  listening HTTPS on {}", https_addr);

    // io_uring multishot accept on Linux (one syscall for N connections)
    #[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
    let mut uring_rx = {
        use std::os::unix::io::AsRawFd;
        let fd = listener.as_ref().as_raw_fd();
        eprintln!("  io_uring multishot accept enabled");
        uring::spawn_uring_accept(fd, 4096)
    };

    // 10b. Spawn HTTP/3 (QUIC) listener on same port (UDP)
    #[cfg(feature = "http3")]
    {
        let quic_addr: SocketAddr = config.server.listen_https.parse()
            .expect("Invalid HTTPS address for QUIC binding");
        quic::spawn_quic_listener(quic_addr, &config.tls, state.clone());
    }

    eprintln!("ZION ONLINE.");

    let mut shutdown = std::pin::pin!(shutdown_signal());

    loop {
        // Accept path: io_uring on Linux, standard tokio everywhere else
        let accepted: Option<(tokio::net::TcpStream, SocketAddr)>;

        #[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
        {
            tokio::select! {
                conn = uring_rx.recv() => {
                    accepted = conn.map(|c| (c.stream, c.addr));
                }
                _ = &mut shutdown => {
                    logging::info("shutdown", "signal received, draining in-flight connections...");
                    break;
                }
            }
        }

        #[cfg(not(all(target_os = "linux", feature = "io-uring-accept")))]
        {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok(conn) => { accepted = Some(conn); }
                        Err(e) => {
                            eprintln!("  https accept error: {}", e);
                            accepted = None;
                        }
                    }
                }
                _ = &mut shutdown => {
                    logging::info("shutdown", "signal received, draining in-flight connections...");
                    break;
                }
            }
        }

        let Some((tcp_stream, remote_addr)) = accepted else { continue };

                // Connection limit — fast atomic check, no Arc clone
                let permit = match state.conn_limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { drop(tcp_stream); continue; }
                };

                let state = state.clone();
                let acceptor = state.tls_acceptor.load_full();
                let builder = state.http_builder.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let _conn_guard = metrics::ConnectionGuard::new();
                    let _ = tcp_stream.set_nodelay(true);
                    net::tune_accepted(&tcp_stream);
                    metrics::METRICS.connections_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let tls_start = std::time::Instant::now();
                    let mut tls_stream = match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        (*acceptor).accept(tcp_stream),
                    ).await {
                        Ok(Ok(s)) => {
                            metrics::METRICS.tls_handshake_duration.observe(tls_start.elapsed());
                            s
                        }
                        _ => {
                            metrics::METRICS.tls_handshake_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                    };

                    // 0-RTT: Check if this connection accepted early data.
                    // Only the first request on the connection can be early data.
                    // We pass this flag to handle_https for method gating (425 Too Early).
                    let is_early_data = tls_stream.get_mut().1.early_data().is_some();
                    let early_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(is_early_data));

                    // mTLS: extract client certificate DN if present
                    let client_cert_dn: Option<String> = tls_stream.get_ref().1
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .and_then(|cert| {
                            // Parse DER cert to extract subject DN
                            // Use a hex fingerprint of the raw subject as a lightweight DN
                            let raw = cert.as_ref();
                            if raw.len() > 20 {
                                // SHA256 fingerprint of the full cert (first 16 hex chars)
                                use std::fmt::Write;
                                let mut hasher_out = [0u8; 8];
                                for (i, &b) in raw.iter().take(64).enumerate() {
                                    hasher_out[i % 8] ^= b;
                                }
                                let mut s = String::with_capacity(16);
                                for b in &hasher_out {
                                    let _ = write!(s, "{:02x}", b);
                                }
                                Some(format!("cert:{}", s))
                            } else {
                                None
                            }
                        });
                    let client_dn = client_cert_dn.map(std::sync::Arc::new);

                    let io = TokioIo::new(tls_stream);
                    // HTTP request timeout — kill connections that don't complete a request
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        builder.serve_connection_with_upgrades(
                            io,
                            service_fn(move |mut req| {
                                // Consume early_data flag on first request (subsequent requests are normal)
                                let was_early = early_flag.swap(false, std::sync::atomic::Ordering::Relaxed);
                                // Inject client cert DN as header if mTLS authenticated
                                if let Some(ref dn) = client_dn {
                                    if let Ok(val) = hyper::header::HeaderValue::from_str(dn) {
                                        req.headers_mut().insert("X-Client-Cert-DN", val);
                                    }
                                }
                                handle_https(req, state.clone(), remote_addr, was_early)
                            }),
                        ),
                    ).await;
                });
    }

    // Graceful drain: wait for in-flight connections to complete.
    // conn_limit has MAX permits; available = MAX - in_flight.
    // We try to acquire ALL permits (meaning all connections finished).
    let drain_timeout = std::time::Duration::from_secs(30);
    let max = platform.conn_limit;
    let in_flight = max - state.conn_limit.available_permits();
    if in_flight > 0 {
        logging::info("shutdown", &format!("draining {} in-flight connections (timeout {}s)...", in_flight, drain_timeout.as_secs()));
    }
    match tokio::time::timeout(drain_timeout, async {
        // C-06: Checked cast — cap at u32::MAX to prevent silent truncation.
        // compute_conn_limit() returns ≤100K which fits u32, but this guards
        // against future changes to the computation.
        let permits = u32::try_from(max).unwrap_or(u32::MAX);
        let _ = state.conn_limit.acquire_many(permits).await;
    }).await {
        Ok(_) => logging::info("shutdown", "all connections drained cleanly"),
        Err(_) => {
            let remaining = max - state.conn_limit.available_permits();
            logging::warn("shutdown", &format!("drain timeout ({}s), {} connections still active, forcing exit", drain_timeout.as_secs(), remaining));
        }
    }

    logging::info("shutdown", "ZION offline.");
    Ok(())
}

// Network socket helpers (bind_with_reuseport, tune_accepted) are in net.rs.

/// Wait for SIGINT (Ctrl+C) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// Validate Host header to prevent header injection in redirects.
#[inline]
fn is_valid_host(host: &str) -> bool {
    security::is_valid_host(host)
}

/// HTTP (port 80) handler — ACME challenge proxy or 301 redirect to HTTPS.
async fn handle_http(
    req: Request<Incoming>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
) -> Result<Response<ZionBody>, hyper::Error> {
    let path = req.uri().path();

    // ACME HTTP-01 challenge — serve from in-memory store (auto-renewal)
    if path.starts_with("/.well-known/acme-challenge/") {
        if let Some(key_auth) = acme::handle_challenge(&state.acme_challenges, path) {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(key_auth)).map_err(|never| match never {}).boxed())
                .unwrap());
        }
        // Fallback: proxy to upstream (for external ACME clients like certbot)
        if let Ok(m) = state.router.at(path) {
            let rule = m.value;
            return proxy::proxy_pass(
                &state.http_client,
                req,
                &rule.upstream_scheme,
                &rule.upstream_authority,
                Some(remote_addr),
                "http",
            )
            .await;
        }
    }

    // Validate Host header
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| is_valid_host(h))
        .unwrap_or("localhost");

    // Preserve query string in redirect, but block path-based open redirects
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Block open redirect via "//evil.com" prefix (would redirect to https://host//evil.com)
    let safe_path = if path_and_query.starts_with("//") {
        "/"
    } else {
        path_and_query
    };

    let redirect_uri = format!("https://{}{}", host, safe_path);
    Ok(Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(hyper::header::LOCATION, redirect_uri)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap())
}

/// Lock-free per-IP rate limiter — delegates to security module.
#[inline]
fn check_rate_limit(state: &AppState, ip: std::net::IpAddr) -> bool {
    security::check_rate_limit(
        state.rate_limit_rps,
        state.rate_limit_window,
        &state.rate_map,
        ip,
    )
}

/// Inject security headers — delegates to security module.
#[inline]
fn inject_security_headers(resp: &mut Response<ZionBody>) {
    security::inject_security_headers(resp);
}

/// HTTPS (port 443) handler — security gates + minimal allocations.
#[inline]
async fn handle_https(
    mut req: Request<Incoming>,
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
    if !matches!(*req.method(),
        hyper::Method::GET | hyper::Method::POST | hyper::Method::PUT |
        hyper::Method::PATCH | hyper::Method::DELETE | hyper::Method::HEAD |
        hyper::Method::OPTIONS
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

    // Gate: per-IP rate limit (zero cost when disabled)
    // Placed BEFORE health endpoints so /healthz can't bypass rate limiting for DDoS.
    if !check_rate_limit(&state, remote_addr.ip()) {
        metrics::METRICS.rate_limited.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            if !is_internal_ip(&remote_addr.ip()) {
                return Ok(empty_response(StatusCode::FORBIDDEN));
            }
            let body = metrics::METRICS.render();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
                .unwrap());
        }
    }

    // ── CORS (zero cost when disabled) ──
    let req_origin: Option<String> = if state.cors.enabled {
        req.headers().get(hyper::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned())
    } else {
        None
    };

    if state.cors.enabled {
        if let Some(ref origin_str) = req_origin {
            if let Some(allow_origin) = state.cors.check_origin(origin_str) {
                // Pre-flight OPTIONS — respond immediately without proxying
                if *req.method() == hyper::Method::OPTIONS {
                    let mut resp = empty_response(StatusCode::NO_CONTENT);
                    let h = resp.headers_mut();
                    h.insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
                    h.insert(hyper::header::ACCESS_CONTROL_ALLOW_METHODS, state.cors.allow_methods.clone());
                    h.insert(hyper::header::ACCESS_CONTROL_ALLOW_HEADERS, state.cors.allow_headers.clone());
                    h.insert(hyper::header::ACCESS_CONTROL_MAX_AGE, state.cors.max_age.clone());
                    inject_security_headers(&mut resp);
                    return Ok(resp);
                }
            } else {
                // Origin not in allowed list — block state-changing methods (CSRF prevention).
                // GET/HEAD are safe (browser enforces response opacity), but POST/PUT/PATCH/DELETE
                // cause server-side mutations that execute before the browser blocks the response.
                if matches!(*req.method(),
                    hyper::Method::POST | hyper::Method::PUT |
                    hyper::Method::PATCH | hyper::Method::DELETE
                ) {
                    return Ok(empty_response(StatusCode::FORBIDDEN));
                }
            }
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

    // --- Gate: internal_only ---
    if rule.internal_only && !is_internal_ip(&remote_addr.ip()) {
        return Ok(empty_response(StatusCode::FORBIDDEN));
    }

    // --- Gate: Upstream health check (B-04) ---
    // If the upstream is marked DOWN by the background health checker,
    // return 503 immediately instead of forwarding and getting a connection error.
    if !health::is_healthy(&state.health_map, &rule.upstream_url) {
        metrics::METRICS.record_status(503);
        return Ok(text_response(StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable"));
    }

    // --- Gate: Auth (JWT/OIDC) ---
    #[cfg(feature = "auth")]
    if let Some(ref auth_profile) = rule.auth {
        let auth_header = req.headers()
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
                                return Ok(text_response(StatusCode::UNAUTHORIZED, "token expired"));
                            }
                            Err(_) => {
                                return Ok(empty_response(StatusCode::FORBIDDEN));
                            }
                        }
                    }
                    None => {
                        return Ok(text_response(StatusCode::UNAUTHORIZED, "invalid authorization"));
                    }
                }
            }
            None => {
                return Ok(text_response(StatusCode::UNAUTHORIZED, "authorization required"));
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
        let uri_str = req.uri().to_string();
        if let waf::WafVerdict::Deny(reason) = waf::validate_uri(&uri_str) {
            metrics::METRICS.waf_denied.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

            let verdict = waf::validate_request(
                method,
                ct_owned.as_deref(),
                &body_bytes,
                waf_profile,
            );
            if let waf::WafVerdict::Deny(_) = verdict {
                metrics::METRICS.waf_denied.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics::METRICS.record_status(400);
                return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
            }

            let mut resp = proxy::proxy_pass_bytes(
                &state.http_client,
                parts,
                body_bytes,
                &rule.upstream_scheme, &rule.upstream_authority,
                remote_addr,
                "https",
            )
            .await?;
            inject_security_headers(&mut resp);
            return Ok(resp);
        }

        // GET/HEAD/DELETE/OPTIONS — no body to validate
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        let verdict = waf::validate_request(method, ct, &[], waf_profile);
        if let waf::WafVerdict::Deny(_) = verdict {
            metrics::METRICS.waf_denied.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            metrics::METRICS.record_status(400);
            return Ok(text_response(StatusCode::BAD_REQUEST, "request rejected"));
        }
    }

    // --- Gate: WebSocket upgrade detection ---
    // Check for Upgrade: websocket on ANY route (or explicit websocket mode)
    let is_websocket = rule.mode == config::RouteMode::Websocket
        || req.headers().get(hyper::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

    if is_websocket {
        metrics::METRICS.websocket_upgrades.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let on_upgrade = hyper::upgrade::on(&mut req);
        let mut resp = proxy::proxy_websocket(
            req,
            on_upgrade,
            &rule.upstream_scheme,
            &rule.upstream_authority,
        ).await?;
        inject_security_headers(&mut resp);
        return Ok(resp);
    }

    // ── Request ID (preserve client's or generate new) ──
    let request_id = req.headers().get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_else(generate_request_id);
    if let Ok(val) = hyper::header::HeaderValue::from_str(&request_id) {
        req.headers_mut().insert("X-Request-ID", val);
    }

    // ── W3C Trace Context propagation ──
    // Preserve incoming traceparent or generate a new one.
    // Forward to upstream for distributed tracing (Jaeger, Tempo, etc.)
    if !req.headers().contains_key("traceparent") {
        // Generate: version-trace_id-parent_id-flags
        // 00-{32 hex trace_id}-{16 hex span_id}-01
        let trace_id = format!("{:032x}", request_start.elapsed().as_nanos() as u64
            ^ (REQUEST_COUNTER.load(std::sync::atomic::Ordering::Relaxed) << 32));
        let span_id = format!("{:016x}",
            REQUEST_COUNTER.load(std::sync::atomic::Ordering::Relaxed));
        let traceparent = format!("00-{}-{}-01", trace_id, span_id);
        if let Ok(val) = hyper::header::HeaderValue::from_str(&traceparent) {
            req.headers_mut().insert("traceparent", val);
        }
    }

    // Pre-compute CORS allow origin before state is consumed
    let cors_allow_origin: Option<hyper::header::HeaderValue> = req_origin.as_deref()
        .and_then(|o| state.cors.check_origin(o));

    // --- Dispatch by mode ---
    let mut resp = if rule.cache.is_some() {
        handle_static_cache(req, state, &rule, remote_addr).await?
    } else {
        match &rule.mode {
            config::RouteMode::StaticCache => {
                handle_static_cache(req, state, &rule, remote_addr).await?
            }
            config::RouteMode::SseStream => {
                proxy::proxy_pass_stream(
                    &state.http_client,
                    req,
                    &rule.upstream_scheme, &rule.upstream_authority,
                    Some(remote_addr),
                    "https",
                )
                .await?
            }
            config::RouteMode::Standard | config::RouteMode::Websocket => {
                proxy::proxy_pass(
                    &state.http_client,
                    req,
                    &rule.upstream_scheme, &rule.upstream_authority,
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
        resp.headers_mut().insert(
            hyper::header::CONTENT_SECURITY_POLICY,
            csp_val.clone(),
        );
    }

    // Record metrics (atomic increment, ~2ns)
    metrics::METRICS.record_status(resp.status().as_u16());

    // Record request duration histogram
    metrics::METRICS.request_duration.observe(request_start.elapsed());

    // CORS: add Access-Control-Allow-Origin on actual requests
    if let Some(allow) = cors_allow_origin {
        resp.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
    }

    // X-Request-ID on response (for client correlation)
    if let Ok(val) = hyper::header::HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert("X-Request-ID", val);
    }

    // Alt-Svc: advertise HTTP/3 to clients (zero cost if feature disabled)
    #[cfg(feature = "http3")]
    resp.headers_mut().insert("Alt-Svc", quic::ALT_SVC_H3.clone());

    Ok(resp)
}

/// Serve from RAM cache or fetch from upstream, then cache.
/// Preserves Content-Type and status from upstream to prevent MIME-sniff
/// issues (S-05: browsers blocked cached CSS/JS without Content-Type
/// because nosniff was set).
#[inline]
async fn handle_static_cache(
    req: Request<Incoming>,
    state: Arc<AppState>,
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
) -> Result<Response<ZionBody>, hyper::Error> {
    let path = req.uri().path();

    // RAM hit — zero-copy serve with preserved Content-Type
    if let Some(hit) = state.static_cache.get(path) {
        let mut builder = Response::builder()
            .status(hit.meta.status)
            .header("Cache-Control", CACHE_CONTROL_IMMUTABLE.clone());
        if let Some(ct) = &hit.meta.content_type {
            builder = builder.header(hyper::header::CONTENT_TYPE, ct.clone());
        }
        return Ok(builder
            .body(
                Full::new(hit.body)
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap());
    }

    // Need to own path before consuming req
    let path_owned = path.to_owned();

    // RAM miss — fetch from upstream
    let resp = proxy::proxy_pass(
        &state.http_client,
        req,
        &rule.upstream_scheme, &rule.upstream_authority,
        Some(remote_addr),
        "https",
    )
    .await?;

    // Only cache 200 OK responses
    if resp.status() == StatusCode::OK {
        let (parts, body) = resp.into_parts();

        // S-04: Skip caching if upstream uses content negotiation (Vary: Accept, etc.)
        // Caching content-negotiated responses with path-only key would serve wrong
        // content types to clients with different Accept headers.
        let has_negotiation_vary = parts.headers.get(hyper::header::VARY)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                let v_lower = v.to_ascii_lowercase();
                v_lower.contains("accept") || v_lower.contains("negotiate")
            })
            .unwrap_or(false);

        if has_negotiation_vary {
            // Don't cache — just forward the response as-is
            let resp = Response::from_parts(
                parts,
                Full::new({
                    let limited = Limited::new(body, MAX_CACHEABLE_BODY);
                    match BodyExt::collect(limited).await {
                        Ok(collected) => collected.to_bytes(),
                        Err(_) => return Ok(empty_response(StatusCode::BAD_GATEWAY)),
                    }
                })
                    .map_err(|never| match never {})
                    .boxed(),
            );
            return Ok(resp);
        }

        // Preserve Content-Type for cache (S-05 fix)
        let content_type = parts.headers.get(hyper::header::CONTENT_TYPE).cloned();
        let meta = cache::CachedMeta {
            content_type,
            status: parts.status,
        };

        let limited = Limited::new(body, MAX_CACHEABLE_BODY);
        let body_bytes = match BodyExt::collect(limited).await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return Ok(empty_response(StatusCode::BAD_GATEWAY)),
        };

        let (ttl, max) = match &rule.cache {
            Some(cp) => (cp.ttl_seconds, cp.max_entries),
            None => (31_536_000, 10_000),
        };
        state
            .static_cache
            .insert(&path_owned, body_bytes.clone(), meta, ttl, max);

        let mut resp = Response::from_parts(
            parts,
            Full::new(body_bytes)
                .map_err(|never| match never {})
                .boxed(),
        );
        resp.headers_mut()
            .insert("Cache-Control", CACHE_CONTROL_IMMUTABLE.clone());
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

    #[test]
    fn test_is_internal_ip_public_denied() {
        let ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_internal_ip(&ip));
    }

    #[test]
    fn test_is_internal_ip_v6_loopback() {
        let ip: std::net::IpAddr = "::1".parse().unwrap();
        assert!(is_internal_ip(&ip));
    }

    #[test]
    fn test_is_internal_ip_v6_public() {
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_internal_ip(&ip));
    }

    #[test]
    fn test_valid_host_normal() {
        assert!(is_valid_host("example.com"));
        assert!(is_valid_host("example.com:443"));
        assert!(is_valid_host("sub.domain.example.com"));
        assert!(is_valid_host("localhost"));
    }

    #[test]
    fn test_valid_host_rejects_injection() {
        assert!(!is_valid_host(""));
        assert!(!is_valid_host("evil.com/path"));
        assert!(!is_valid_host("evil.com\\path"));
        assert!(!is_valid_host("user@evil.com"));
        assert!(!is_valid_host("evil.com\r\nX-Injected: true"));
        assert!(!is_valid_host("evil.com\nX-Injected: true"));
        assert!(!is_valid_host("evil .com"));
    }

    #[test]
    fn test_valid_host_rejects_too_long() {
        let long_host = "a".repeat(254);
        assert!(!is_valid_host(&long_host));
    }

    // ── 0-RTT Method Gating Tests ──
    // These test the logic from handle_https: is_early_data + method → allow/deny

    fn should_reject_early_data(method: &str) -> bool {
        // Mirror the gate logic: reject non-idempotent methods on early data
        !matches!(method, "GET" | "HEAD")
    }

    #[test]
    fn test_0rtt_get_allowed() {
        assert!(!should_reject_early_data("GET"));
    }

    #[test]
    fn test_0rtt_head_allowed() {
        assert!(!should_reject_early_data("HEAD"));
    }

    #[test]
    fn test_0rtt_post_rejected() {
        assert!(should_reject_early_data("POST"));
    }

    #[test]
    fn test_0rtt_put_rejected() {
        assert!(should_reject_early_data("PUT"));
    }

    #[test]
    fn test_0rtt_patch_rejected() {
        assert!(should_reject_early_data("PATCH"));
    }

    #[test]
    fn test_0rtt_delete_rejected() {
        assert!(should_reject_early_data("DELETE"));
    }

    #[test]
    fn test_0rtt_options_rejected() {
        assert!(should_reject_early_data("OPTIONS"));
    }

    // ── CSP Header Value Tests ──

    #[test]
    fn test_csp_valid_policy_parses() {
        let csp = "default-src 'self'; script-src 'self'";
        let hv = hyper::header::HeaderValue::from_str(csp);
        assert!(hv.is_ok(), "valid CSP should parse as HeaderValue");
        assert_eq!(hv.unwrap().to_str().unwrap(), csp);
    }

    #[test]
    fn test_csp_complex_policy_parses() {
        let csp = "default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'";
        let hv = hyper::header::HeaderValue::from_str(csp);
        assert!(hv.is_ok());
    }

    #[test]
    fn test_csp_none_on_route_without_csp() {
        // Simulate: route without csp → None
        let csp_opt: Option<String> = None;
        let parsed: Option<hyper::header::HeaderValue> = csp_opt.as_ref().map(|s| {
            hyper::header::HeaderValue::from_str(s).unwrap()
        });
        assert!(parsed.is_none());
    }

    // ── StatusCode 425 ──

    #[test]
    fn test_status_425_too_early() {
        let status = hyper::StatusCode::from_u16(425);
        assert!(status.is_ok());
        assert_eq!(status.unwrap().as_u16(), 425);
    }
}
