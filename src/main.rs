#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::let_and_return)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::needless_borrow)]

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

mod dispatch;
pub(crate) use dispatch::process_request;

/// Max response body size we'll cache in RAM (50 MB).
const MAX_CACHEABLE_BODY: usize = 50 * 1024 * 1024;

/// Atomic request counter for generating unique request IDs.
/// Format: {timestamp_hex}-{counter_hex} — unique, sortable.
static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Hex digit lookup table for zero-alloc hex encoding.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Generate a unique request ID using a stack buffer.
/// Format: 16-char hex timestamp + '-' + 4-char hex counter = 21 bytes.
/// Zero heap allocation — writes directly to a stack [u8; 21] and converts
/// to String via from_utf8_unchecked (all bytes are ASCII hex or '-').
pub(crate) fn generate_request_id() -> [u8; 21] {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let seq = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u16;

    let mut buf = [0u8; 21]; // 16 hex + '-' + 4 hex
                             // Encode timestamp as 16 hex chars (big-endian)
    for i in 0..8 {
        let byte = (ts >> (56 - i * 8)) as u8;
        buf[i * 2] = HEX_DIGITS[(byte >> 4) as usize];
        buf[i * 2 + 1] = HEX_DIGITS[(byte & 0xF) as usize];
    }
    buf[16] = b'-';
    // Encode counter as 4 hex chars
    for i in 0..2 {
        let byte = (seq >> (8 - i * 8)) as u8;
        buf[17 + i * 2] = HEX_DIGITS[(byte >> 4) as usize];
        buf[17 + i * 2 + 1] = HEX_DIGITS[(byte & 0xF) as usize];
    }
    buf
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
    /// ACME HTTP-01 challenge tokens (empty when no challenge active).
    acme_challenges: acme::ChallengeStore,
    /// Per-IP rate limiter. 0 = disabled.
    rate_limit_rps: u32,
    rate_limit_window: u64,
    rate_map: Arc<dashmap::DashMap<std::net::IpAddr, RateEntry>>,
    /// Shared upstream health state — checked before dispatching to prevent 502 cascades.
    health_map: health::HealthMap,
    /// Trusted proxy CIDRs for X-Forwarded-For IP resolution.
    trusted_proxies: security::TrustedProxies,
}

// Pre-compiled constants — zero runtime cost.
static EMPTY_BYTES: Bytes = Bytes::new();
static CACHE_CONTROL_IMMUTABLE: hyper::header::HeaderValue =
    hyper::header::HeaderValue::from_static("public, max-age=31536000, immutable");

// Security headers, rate limiter constants, and validators are in security.rs.

/// Maximum allowed URI length (bytes). Requests exceeding this are dropped
/// before routing — prevents buffer overflow probes and log pollution.
const MAX_URI_LEN: usize = 8192;

pub(crate) fn empty_response(status: StatusCode) -> Response<ZionBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(EMPTY_BYTES.clone())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

pub(crate) fn text_response(status: StatusCode, text: &'static str) -> Response<ZionBody> {
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

    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let core_idx = std::sync::atomic::AtomicUsize::new(0);

    // Build tokio runtime with detected optimal worker count
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(platform.worker_threads)
        .on_thread_start(move || {
            if !core_ids.is_empty() {
                // Sequentially pin each worker thread to a physical core
                let idx = core_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let core = core_ids[idx % core_ids.len()];
                core_affinity::set_for_current(core);
            }
        })
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async_main(platform))
}

async fn async_main(
    platform: &'static bootstrap::Platform,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("ZION EDGE GATEWAY — initializing...");
    bootstrap::print_report(platform);

    // 1. Load configuration
    let config_path = std::env::var("ZION_CONFIG").unwrap_or_else(|_| "zion.toml".to_string());
    let config = config::load_config(&config_path).map_err(|e| format!("FATAL: {}", e))?;
    logging::init(&config.server.log_format);
    logging::info("config", &format!("loaded from {}", config_path));

    // 2. Build radix tree router
    let router = config::build_router(&config);

    // 3. Load initial TLS — build acceptor once, cache via ArcSwap
    let initial_tls = tls::load_tls_config(&config.tls).map_err(|e| format!("FATAL: {}", e))?;
    let acceptor = TlsAcceptor::from(Arc::new(initial_tls));
    let tls_acceptor_store = Arc::new(ArcSwap::from_pointee(acceptor));
    eprintln!(
        "  tls loaded (min={}, alpn={:?})",
        config.tls.min_version, config.tls.alpn
    );

    // 4. Start TLS hot-reload watcher (rebuilds acceptor on cert change)
    let (quic_reload_tx, quic_reload_rx) = tokio::sync::watch::channel(None);
    if config.tls.hot_reload {
        tls::spawn_tls_watcher(
            tls_acceptor_store.clone(),
            config.tls.clone(),
            Some(quic_reload_tx),
        );
    }

    // 4b. Predictive TTL pre-warming: pre-build TLS config before cert expires
    tls::spawn_cert_prewarm_task(tls_acceptor_store.clone(), config.tls.clone());

    // 5. Build shared state — conn_limit computed from available RAM
    // 5b. Build health map (before Arc — so it's directly embedded in AppState)
    let health_map = {
        let mut map = fnv::FnvHashMap::default();
        for route in &config.route {
            let urls = if let Some(up) = config.upstream.get(&route.upstream) {
                up.get_urls()
            } else if let Some(url) = config.upstreams.get(&route.upstream) {
                vec![url.clone()]
            } else {
                continue;
            };
            for url in urls {
                map.entry(url.clone()).or_insert_with(|| {
                    Arc::new(health::UpstreamHealth {
                        healthy: std::sync::atomic::AtomicBool::new(true),
                        latency_us: std::sync::atomic::AtomicU64::new(0),
                    })
                });
            }
        }
        Arc::new(map)
    };

    let trusted_proxies = security::TrustedProxies::from_config(&config.server.trusted_proxies);
    if !trusted_proxies.is_empty() {
        logging::info(
            "proxy",
            &format!("trusted proxies: {:?}", config.server.trusted_proxies),
        );
    }

    let state = Arc::new(AppState {
        router,
        tls_acceptor: tls_acceptor_store,
        http_client: proxy::build_http_client(),
        static_cache: cache::StaticCache::new(),
        conn_limit: Arc::new(Semaphore::new(platform.conn_limit)),
        acme_challenges: acme::new_challenge_store(),
        rate_limit_rps: config.server.rate_limit_rps,
        rate_limit_window: config.server.rate_limit_window_secs,
        rate_map: Arc::new(dashmap::DashMap::new()),
        health_map: health_map.clone(),
        trusted_proxies,
        http_builder: {
            let mut b = AutoBuilder::new(TokioExecutor::new());
            // Limit header count and total header buffer size to prevent header bomb DoS.
            // 16KB buffer is optimal for L1 CPU cache on micro-payloads (API/CSS).
            b.http1().max_headers(64).max_buf_size(16 * 1024);
            b.http1().preserve_header_case(false);
            b.http1().title_case_headers(false);
            b
        },
    });

    // 6. Spawn ACME auto-renewal task (if configured)
    if let Some(ref acme_config) = config.tls.acme {
        logging::info(
            "acme",
            &format!(
                "auto-renewal enabled for: {}",
                acme_config.domains.join(", ")
            ),
        );
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
                // Sampled cleanup: scan at most 1024 entries to avoid locking all shards.
                // DashMap::retain() would lock every shard sequentially, causing latency
                // spikes under high load. Instead, we collect stale keys from a sample
                // and remove them individually (each removal locks only one shard).
                let mut stale_keys: Vec<std::net::IpAddr> = Vec::new();
                for (i, entry) in rate_map.iter().enumerate() {
                    if i >= 1024 {
                        break;
                    }
                    let packed = entry.packed.load(std::sync::atomic::Ordering::Relaxed);
                    let entry_window = (packed >> 32) as u32;
                    if entry_window < current_window.saturating_sub(2) {
                        stale_keys.push(*entry.key());
                    }
                }
                for key in &stale_keys {
                    rate_map.remove(key);
                }
                if !stale_keys.is_empty() {
                    logging::info(
                        "rate_limit",
                        &format!(
                            "cleaned {} stale IPs ({} tracked)",
                            stale_keys.len(),
                            rate_map.len()
                        ),
                    );
                }
            }
        });
    }

    // 8. Spawn upstream health checker background task
    if !health_map.is_empty() {
        logging::info(
            "health",
            &format!("monitoring {} upstreams", health_map.len()),
        );
        // Start the background ping loop using the shared health_map
        // (already embedded in AppState, so routing sees updates immediately)
        let hm = health_map.clone();
        tokio::spawn(async move {
            let client =
                hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                    .pool_idle_timeout(std::time::Duration::from_secs(10))
                    .pool_max_idle_per_host(1)
                    .build_http();
            loop {
                let mut upstreams_to_check: Vec<(String, Arc<health::UpstreamHealth>)> = Vec::new();
                for (url, up) in hm.iter() {
                    upstreams_to_check.push((url.to_string(), Arc::clone(up)));
                }

                let mut join_set = tokio::task::JoinSet::new();

                for (url, up) in upstreams_to_check {
                    let client_clone = client.clone();
                    join_set.spawn(async move {
                        let uri: hyper::Uri = match url.parse() {
                            Ok(u) => u,
                            Err(_) => return,
                        };
                        let req = match hyper::Request::builder()
                            .uri(&uri)
                            .header(
                                "Host",
                                uri.authority().map(|a| a.as_str()).unwrap_or("localhost"),
                            )
                            .body(http_body_util::Full::new(bytes::Bytes::new()))
                        {
                            Ok(r) => r,
                            Err(_) => return,
                        };
                        let start = tokio::time::Instant::now();
                        let healthy = match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            client_clone.request(req),
                        )
                        .await
                        {
                            Ok(Ok(resp)) => {
                                resp.status().is_success() || resp.status().is_redirection()
                            }
                            _ => false,
                        };
                        let lat = if healthy {
                            start.elapsed().as_micros() as u64
                        } else {
                            0
                        };
                        up.update_latency(lat);

                        let was_healthy = up
                            .healthy
                            .swap(healthy, std::sync::atomic::Ordering::Relaxed);
                        if was_healthy && !healthy {
                            logging::warn("health", &format!("upstream {} is DOWN", url));
                        } else if !was_healthy && healthy {
                            logging::info("health", &format!("upstream {} is UP ({}us)", url, lat));
                        }
                    });
                }
                while join_set.join_next().await.is_some() {}
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
                        service_fn(move |req| {
                            use http_body_util::BodyExt;
                            let req_boxed = req.map(|b: hyper::body::Incoming| b.boxed());
                            handle_http(req_boxed, state.clone(), addr)
                        }),
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
        let fd = listener.as_raw_fd();
        eprintln!("  io_uring multishot accept enabled");
        uring::spawn_uring_accept(fd, 4096)
    };

    // 10b. Spawn HTTP/3 (QUIC) listener on same port (UDP)
    #[cfg(feature = "http3")]
    {
        let quic_addr: SocketAddr = config
            .server
            .listen_https
            .parse()
            .expect("Invalid HTTPS address for QUIC binding");
        quic::spawn_quic_listener(quic_addr, &config.tls, state.clone(), Some(quic_reload_rx));
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

        let Some((tcp_stream, remote_addr)) = accepted else {
            continue;
        };

        // Connection limit — fast atomic check, no Arc clone
        let permit = match state.conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(tcp_stream);
                continue;
            }
        };

        let state = state.clone();
        let acceptor = state.tls_acceptor.load_full();
        let builder = state.http_builder.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let _conn_guard = metrics::ConnectionGuard::new();
            let _ = tcp_stream.set_nodelay(true);
            net::tune_accepted(&tcp_stream);
            metrics::METRICS
                .connections_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            let tls_start = std::time::Instant::now();
            let mut tls_stream = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                (*acceptor).accept(tcp_stream),
            )
            .await
            {
                Ok(Ok(s)) => {
                    metrics::METRICS
                        .tls_handshake_duration
                        .observe(tls_start.elapsed());
                    s
                }
                _ => {
                    metrics::METRICS
                        .tls_handshake_errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            };

            // 0-RTT: Check if this connection accepted early data.
            // Only the first request on the connection can be early data.
            // We pass this flag to handle_https for method gating (425 Too Early).
            // rustls ServerConnection::early_data() returns Some if 0-RTT was
            // accepted during the handshake (was_accepted() flag persists).
            let is_early_data = tls_stream.get_mut().1.early_data().is_some();
            let early_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(is_early_data));

            // mTLS: extract client certificate DN if present
            let client_cert_dn: Option<String> = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| {
                    // Parse DER cert to extract a lightweight identifier.
                    // XOR-fold of first 64 bytes — fast but NOT cryptographic.
                    // Sufficient for logging/tracing, NOT for access control.
                    let raw = cert.as_ref();
                    if raw.len() > 20 {
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
            // Connection-level idle timeout. Set high (1 hour) because this
            // wraps the entire HTTP/2 mux / WebSocket / SSE connection, not
            // individual requests. Per-request timeouts are in process_request.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3600),
                builder.serve_connection_with_upgrades(
                    io,
                    service_fn(move |mut req: Request<Incoming>| {
                        let state = state.clone();
                        let early_flag = early_flag.clone();
                        let client_dn = client_dn.clone();
                        async move {
                            // Fast-path: health probes bypass the full pipeline (~1us vs ~5us)
                            let path = req.uri().path();
                            if path == "/healthz" {
                                return Ok(text_response(StatusCode::OK, "ok"));
                            }
                            if path == "/readyz" {
                                return Ok(text_response(StatusCode::OK, "ready"));
                            }

                            // Consume early_data flag on first request
                            let was_early =
                                early_flag.swap(false, std::sync::atomic::Ordering::Relaxed);
                            // Inject client cert DN as header if mTLS authenticated
                            if let Some(ref dn) = client_dn {
                                if let Ok(val) = hyper::header::HeaderValue::from_str(dn) {
                                    req.headers_mut().insert("X-Client-Cert-DN", val);
                                }
                            }
                            use http_body_util::BodyExt;
                            let req_boxed = req.map(|b: hyper::body::Incoming| b.boxed());
                            process_request(req_boxed, state, remote_addr, was_early).await
                        }
                    }),
                ),
            )
            .await;
        });
    }

    // Graceful drain: wait for in-flight connections to complete.
    // conn_limit has MAX permits; available = MAX - in_flight.
    // We try to acquire ALL permits (meaning all connections finished).
    let drain_timeout = std::time::Duration::from_secs(30);
    let max = platform.conn_limit;
    let in_flight = max - state.conn_limit.available_permits();
    if in_flight > 0 {
        logging::info(
            "shutdown",
            &format!(
                "draining {} in-flight connections (timeout {}s)...",
                in_flight,
                drain_timeout.as_secs()
            ),
        );
    }
    match tokio::time::timeout(drain_timeout, async {
        // C-06: Checked cast — cap at u32::MAX to prevent silent truncation.
        // compute_conn_limit() returns ≤100K which fits u32, but this guards
        // against future changes to the computation.
        let permits = u32::try_from(max).unwrap_or(u32::MAX);
        let _ = state.conn_limit.acquire_many(permits).await;
    })
    .await
    {
        Ok(_) => logging::info("shutdown", "all connections drained cleanly"),
        Err(_) => {
            let remaining = max - state.conn_limit.available_permits();
            logging::warn(
                "shutdown",
                &format!(
                    "drain timeout ({}s), {} connections still active, forcing exit",
                    drain_timeout.as_secs(),
                    remaining
                ),
            );
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
fn is_valid_host(host: &str) -> bool {
    security::is_valid_host(host)
}

/// HTTP (port 80) handler — ACME challenge proxy or 301 redirect to HTTPS.
async fn handle_http(
    req: Request<ZionBody>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Rate limit HTTP/80 to prevent DoS via redirect/ACME flood
    if !check_rate_limit(&state, remote_addr.ip()) {
        metrics::METRICS
            .rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(empty_response(StatusCode::TOO_MANY_REQUESTS));
    }

    // URI length check (same as HTTPS handler)
    if req.uri().path().len() > MAX_URI_LEN {
        return Ok(empty_response(StatusCode::URI_TOO_LONG));
    }

    let path = req.uri().path();

    // ACME HTTP-01 challenge — serve from in-memory store (auto-renewal)
    if path.starts_with("/.well-known/acme-challenge/") {
        if let Some(key_auth) = acme::handle_challenge(&state.acme_challenges, path) {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(
                    Full::new(Bytes::from(key_auth))
                        .map_err(|never| match never {})
                        .boxed(),
                )
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

    // Block open redirect via "//evil.com" or "/\evil.com" prefix
    // (browsers normalize backslash to forward slash, so /\x → //x)
    let safe_path = if path_and_query.starts_with("//") || path_and_query.starts_with("/\\") {
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
fn check_rate_limit(state: &AppState, ip: std::net::IpAddr) -> bool {
    security::check_rate_limit(
        state.rate_limit_rps,
        state.rate_limit_window,
        &state.rate_map,
        ip,
    )
}

/// Inject security headers — delegates to security module.
pub(crate) fn inject_security_headers(resp: &mut Response<ZionBody>) {
    security::inject_security_headers(resp);
}
