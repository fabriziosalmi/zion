// Crate-level lint hygiene.
//
// We deliberately do NOT silence dead_code / unused_imports / unused_variables
// here — they're a leading indicator of code rot and belong to the warnings
// surface. When a warning is genuinely intentional (feature-gated reserved
// hooks, future-feature scaffolding) it gets a *targeted* `#[allow(...)]`
// with a comment explaining the why, so the next reader can re-evaluate it.
//
// The clippy stylistic lints below are kept silenced: they are taste, not
// correctness, and re-running them is cheap when the project decides to
// adopt a uniform style.
//
// ─────────────────────────────────────────────────────────────────────────
// INVARIANT: `Response::builder().status(...).body(...).unwrap()` pattern.
// ─────────────────────────────────────────────────────────────────────────
// Multiple sites in this crate construct hyper responses with the literal
// shape `Response::builder().status(StatusCode).header("Foo", "bar").body(b)`.
// `Builder::body()` only returns `Err` when the builder accumulated a header
// parse error during prior `.header(...)` calls. We never feed user-controlled
// strings into header *values* in these constructions — only static literals
// or values we've already parsed (StatusCode, HeaderValue). Therefore the
// `.unwrap()` is sound by typing, and we treat it as an invariant rather than
// a TODO. Sites that DO build a header from dynamic data (URI parsing, header
// echoing back to a client) get an individual `// SAFETY:` comment explaining
// why the input is constrained.
#![allow(clippy::let_and_return)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::needless_borrow)]

mod acme;
mod audit;
mod auth;
mod bootstrap;
mod cache;
mod cli;
mod config;
mod doctor;
mod error;
mod health;
mod init;
mod listener;
mod logging;
mod metrics;
mod net;
mod observability;
mod proxy;
#[cfg(feature = "http3")]
mod quic;
mod reload;
mod security;
#[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
mod sovereign;
mod tls;
#[cfg(feature = "tui")]
mod tui;
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
use http_body_util::{BodyExt, Full};
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

// (Cache size limit lives in dispatch::MAX_CACHEABLE_BODY where it is
//  actually consumed by the static-cache pipeline.)

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
use security::RateEntry;

/// Snapshot of config-derived state. Everything in here is rebuilt from
/// `config::ZionConfig` and is intentionally independent of long-lived
/// runtime state (HTTP client pool, RAM caches, rate-limit IP map,
/// inflight singleflight, etc.) so that the whole snapshot can be
/// atomically swapped on hot-reload without disturbing in-flight
/// connections or warm caches.
///
/// In Phase 1 (this commit) the snapshot is held as a plain `Arc<...>`
/// in `AppState` — there is no swap yet, the contents are still built
/// once at boot from `zion.toml`. The follow-up commit will wrap the
/// `Arc` in `ArcSwap` and wire the watcher.
pub(crate) struct ResolvedAppConfig {
    /// Radix tree (matchit) of pre-resolved routes.
    pub(crate) router: Router<Arc<ResolvedRoute>>,
    /// Upstream URL → shared health/latency state. The `Arc<UpstreamHealth>`
    /// values are intentionally re-used across reloads when the URL is
    /// unchanged so the prober's accumulated state is preserved.
    pub(crate) health_map: health::HealthMap,
    /// Trusted proxy CIDRs for X-Forwarded-For IP resolution.
    pub(crate) trusted_proxies: security::TrustedProxies,
    /// Outbound XFF policy (append / rewrite / drop). See proxy::XffMode.
    pub(crate) xff_mode: proxy::XffMode,
    /// Per-IP rate limiter target (RPS). 0 = disabled.
    pub(crate) rate_limit_rps: u32,
    /// Rate limiter window in seconds.
    pub(crate) rate_limit_window: u64,
    /// Pre-parsed listen address for plain HTTP. `None` if the config
    /// string is malformed; the listener supervisor logs the parse error
    /// at reload time and keeps the previously-bound listener.
    pub(crate) listen_http: Option<SocketAddr>,
    /// Pre-parsed listen address for HTTPS. `None` only if the string is
    /// malformed; the supervisor refuses to drop the existing listener
    /// in that case (the previous valid bind survives the reload).
    pub(crate) listen_https: Option<SocketAddr>,
    /// Sovereign Edge Intelligence: whether IP classification is active.
    /// Pre-resolved at build time; the hot path checks only this bool.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    pub(crate) sovereign_enabled: bool,
    /// Whether to include ip_class in structured request logs.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    pub(crate) sovereign_log_classification: bool,
}

impl ResolvedAppConfig {
    /// Test-only constructor that lets unit tests in `reload.rs`
    /// fabricate a snapshot with a specific health map without going
    /// through `build()` (which requires a full `ZionConfig`). Other
    /// fields take harmless defaults — they're not exercised by the
    /// rebuild() merge logic.
    #[cfg(test)]
    pub(crate) fn test_with_health(health_map: health::HealthMap) -> Self {
        Self {
            router: matchit::Router::new(),
            health_map,
            trusted_proxies: security::TrustedProxies::from_config(&[]),
            xff_mode: proxy::XffMode::Append,
            rate_limit_rps: 0,
            rate_limit_window: 1,
            listen_http: None,
            listen_https: None,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_enabled: false,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_log_classification: false,
        }
    }

    /// Build a snapshot from a parsed `ZionConfig`.
    ///
    /// This is the single entry point that turns the static TOML config
    /// into the runtime-shaped state the request pipeline reads. Phase 1
    /// uses it once at boot; subsequent phases call it again on every
    /// hot-reload and atomic-swap the result.
    ///
    /// Panics at boot if the router cannot be built (bad patterns, unknown
    /// profiles). During hot-reload, `rebuild()` calls `try_build()` which
    /// propagates the error cleanly.
    fn build(config: &config::ZionConfig) -> Self {
        let router = config::build_router(config)
            .unwrap_or_else(|e| panic!("fatal: cannot build router at boot: {e}"));

        // Health map: one entry per upstream URL referenced by any route.
        // The same URL can appear in many routes — dedup via FnvHashMap.
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
        let health_map = Arc::new(map);

        let trusted_proxies = security::TrustedProxies::from_config(&config.server.trusted_proxies);

        // Parse the configured XFF policy. Unknown values fall back to
        // Append (silent fallback would weaken upstream IP integrity).
        // The boot path in async_main already emits a structured warning
        // when it sees an unknown value, so a second log here would be
        // redundant — we just take the parsed value.
        let xff_mode = proxy::XffMode::parse(&config.server.xff_mode).unwrap_or_default();

        // Parse listen addresses once at build time. A malformed string
        // logs a structured warning and yields `None`; the listener
        // supervisor refuses to drop the existing listener in that case,
        // so a typo in zion.toml never strands the daemon offline.
        let listen_http = config
            .server
            .listen_http
            .parse::<SocketAddr>()
            .map_err(|e| {
                logging::warn(
                    "config",
                    &format!(
                        "server.listen_http '{}' is not a valid socket address: {}",
                        config.server.listen_http, e
                    ),
                );
            })
            .ok();
        let listen_https = config
            .server
            .listen_https
            .parse::<SocketAddr>()
            .map_err(|e| {
                logging::warn(
                    "config",
                    &format!(
                        "server.listen_https '{}' is not a valid socket address: {}",
                        config.server.listen_https, e
                    ),
                );
            })
            .ok();

        // Sovereign Edge Intelligence (feature-gated)
        #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
        let (sovereign_enabled, sovereign_log_classification) = {
            let sov = &config.sovereign;
            if sov.enabled {
                let region_label = if cfg!(feature = "geo-eu") {
                    "eu"
                } else {
                    "ita"
                };
                logging::info(
                    "sovereign",
                    &format!(
                        "Sovereign Edge active (region={}, log_classification={})",
                        region_label, sov.log_classification
                    ),
                );
            }
            (sov.enabled, sov.log_classification)
        };

        Self {
            router,
            health_map,
            trusted_proxies,
            xff_mode,
            rate_limit_rps: config.server.rate_limit_rps,
            rate_limit_window: config.server.rate_limit_window_secs,
            listen_http,
            listen_https,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_enabled,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_log_classification,
        }
    }
}

/// Global shared state — lock-free reads via Arc + ArcSwap.
struct AppState {
    /// Config-derived snapshot, atomically swappable. The hot path reads
    /// it via `AppState::cfg()` (`load_full`, ~5 ns: Acquire load + Arc
    /// refcount bump). The returned `Arc` is held for the duration of
    /// the request so a single request always sees a consistent
    /// snapshot — even if a hot-reload swaps in a new one mid-flight.
    /// Old snapshots are reclaimed by ArcSwap's epoch-based GC once the
    /// last in-flight reader exits.
    ///
    /// Wrapped in `Arc<...>` so the config watcher (in `reload.rs`) can
    /// hold its own clone for `store()` without a back-pointer to the
    /// whole `AppState`.
    pub(crate) config: Arc<ArcSwap<ResolvedAppConfig>>,
    tls_acceptor: Arc<ArcSwap<tokio_rustls::TlsAcceptor>>,
    http_client: HttpClient,
    static_cache: cache::StaticCache,
    conn_limit: Arc<Semaphore>,
    http_builder: Arc<AutoBuilder<TokioExecutor>>,
    /// ACME HTTP-01 challenge tokens (empty when no challenge active).
    acme_challenges: acme::ChallengeStore,
    /// Per-IP rate limiter map. Persists across config reloads — the IP
    /// counters are about the IP's behaviour, not about the config.
    rate_map: Arc<dashmap::DashMap<std::net::IpAddr, RateEntry>>,
    /// Singleflight: coalesce concurrent cache misses for the same key.
    /// First request fetches from upstream and inserts a `watch::Sender<bool>`;
    /// subsequent requests subscribe and await `true`. Watch (vs Notify) is
    /// race-free: `wait_for` inspects the current value at first poll, so
    /// even if the fetcher completes between our get() and our .await we
    /// still observe the wake instead of hanging until the client times out.
    /// Sender drop without sending `true` (fetch aborted) yields Err on the
    /// receiver side and waiters fall through to re-check the cache.
    inflight: dashmap::DashMap<Arc<str>, tokio::sync::watch::Sender<bool>>,
    /// HMAC-chained audit log handle. `noop()` when audit is disabled.
    /// Cloned per request handler; `emit()` is non-blocking.
    pub(crate) audit: audit::AuditHandle,
    /// Compiled PII redaction policy. Applied at audit-event construction
    /// time. Cheap to clone (`Vec<String>`); held by Arc for ABI stability
    /// across hot-reloads of `[redact]`.
    pub(crate) redact: Arc<audit::CompiledRedaction>,
}

impl AppState {
    /// Snapshot the current config-derived state. Cheap: one atomic
    /// Acquire load + Arc refcount bump, ~5 ns. The returned `Arc` keeps
    /// the snapshot alive across `await` points without pinning the
    /// ArcSwap epoch — so it is safe to hold for the lifetime of a
    /// request, unlike a raw `load()` Guard.
    #[inline]
    pub(crate) fn cfg(&self) -> Arc<ResolvedAppConfig> {
        self.config.load_full()
    }
}

// Pre-compiled constants — zero runtime cost.
// (CACHE_CONTROL_IMMUTABLE moved to dispatch::CACHE_CONTROL_IMMUTABLE where
//  the static-cache path consumes it. Keeping a duplicate here was dead.)
static EMPTY_BYTES: Bytes = Bytes::new();

// Security headers, rate limiter constants, and validators are in security.rs.

/// Maximum allowed URI length (bytes). Requests exceeding this are dropped
/// before routing — prevents buffer overflow probes and log pollution.
const MAX_URI_LEN: usize = 8192;

pub(crate) fn empty_response(status: StatusCode) -> Response<ZionBody> {
    // INVARIANT: hyper's `Response::builder().status(StatusCode).body(...)`
    // returns `Err` only when the builder accumulated a header parse error.
    // We pass a typed StatusCode (no parse step) and a typed body, so the
    // construction is infallible by typing.
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
    // INVARIANT: same as `empty_response` — typed StatusCode + typed body,
    // no headers added that could fail to parse.
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from_static(text.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn main() -> error::ZionResult<()> {
    // ── Subcommand dispatch ──
    // Default (no args) → run the daemon, preserving every existing
    // systemd / Docker invocation path. Subcommands like `top`, `--version`,
    // and `--help` are additive.
    match cli::parse() {
        cli::Command::Daemon => {} // fall through to daemon below
        cli::Command::Auto(opts) => {
            // Generate ephemeral cert + zion.toml in tmpdir, set
            // ZION_CONFIG, then fall through to the daemon code path
            // below. Same daemon, same boot ceremony — just no config
            // files on the operator's disk.
            match init::run_auto(opts) {
                Ok(path) => {
                    eprintln!("  zion auto-mode: ephemeral config at {}", path.display());
                }
                Err(e) => {
                    eprintln!("zion auto: {e}");
                    std::process::exit(2);
                }
            }
            // fall through to daemon
        }
        cli::Command::Version => {
            cli::print_version();
            return Ok(());
        }
        cli::Command::Help => {
            cli::print_help();
            return Ok(());
        }
        cli::Command::Unknown(s) => {
            eprintln!("zion: unknown subcommand '{s}'\n");
            cli::print_help();
            std::process::exit(1);
        }
        cli::Command::Top(opts) => {
            #[cfg(feature = "tui")]
            {
                // tui::run still returns Box<dyn Error> internally — it's a
                // cargo-feature-gated subcommand and not part of the boot
                // contract we restructured. Convert at the boundary.
                return tui::run(opts).map_err(|e| error::ZionError::Other(e.to_string()));
            }
            #[cfg(not(feature = "tui"))]
            {
                let _ = opts;
                eprintln!(
                    "zion top requires the `tui` feature.\n\
                     rebuild with: cargo build --release --features tui"
                );
                std::process::exit(2);
            }
        }
        cli::Command::Doctor => {
            std::process::exit(doctor::run());
        }
        cli::Command::Init(opts) => {
            std::process::exit(init::run(opts));
        }
        cli::Command::Bootstrap => {
            // CI / automation entry point: detect the platform (incl. live
            // AES calibration unless ZION_BOOT_FAST=1) and dump JSON to
            // stdout. No daemon, no TLS, no logs — pipe-friendly.
            let p = bootstrap::detect();
            println!("{}", bootstrap::dump_platform_json(p));
            return Ok(());
        }
    }

    // 0a-pre. Install the panic hook BEFORE any worker thread is spawned so
    //         every panic — boot, async worker, anywhere — emits a structured
    //         JSON record to stderr and to a last-gasp file (so a sidecar /
    //         next-boot probe can self-report the previous death). The
    //         release profile is `panic = "abort"`; this runs once before
    //         abort. The path is overridable via ZION_LAST_GASP_PATH.
    let last_gasp = std::env::var_os("ZION_LAST_GASP_PATH")
        .map(std::path::PathBuf::from)
        .or_else(|| Some(std::path::PathBuf::from("/var/lib/zion/last_panic.jsonl")));
    observability::install_panic_hook(last_gasp);

    // 0a. Install the default crypto provider for rustls.
    //     The dep tree carries both aws-lc-rs (rustls default + our boot
    //     AES-GCM calibration) and ring (pulled in by hyper-rustls 0.27 for
    //     upstream HTTP/2). rustls 0.23 refuses to auto-pick when both are
    //     present and panics on first TLS use. We explicitly pin to
    //     aws-lc-rs so the runtime crypto provider matches the one we
    //     calibrated in `bootstrap::detect()`.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // 0b. Bootstrap — detect hardware and auto-tune (BEFORE runtime starts)
    metrics::record_start();
    let platform = bootstrap::detect();

    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let core_idx = std::sync::atomic::AtomicUsize::new(0);

    // Build tokio runtime with detected optimal worker count.
    // INVARIANT: `Builder::build()` only fails on (a) zero worker threads
    // (we always pass `platform.worker_threads >= 1`), or (b) the kernel
    // refusing to spawn the I/O reactor thread (catastrophic — at that
    // point the daemon cannot run). Map to a structured ZionError so the
    // operator gets a clean exit code instead of an `expect` panic.
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
        .map_err(|e| error::ZionError::Other(format!("tokio runtime build failed: {e}")))?;

    runtime.block_on(async_main(platform))
}

async fn async_main(platform: &'static bootstrap::Platform) -> error::ZionResult<()> {
    eprintln!("ZION EDGE GATEWAY — initializing...");
    bootstrap::print_report(platform);

    // 1. Load configuration
    let config_path = std::env::var("ZION_CONFIG").unwrap_or_else(|_| "zion.toml".to_string());
    let config = config::load_config(&config_path).map_err(error::ZionError::Config)?;
    logging::init(&config.server.log_format);
    // tracing-subscriber init mirrors the log_format choice — JSON for
    // production, pretty for dev. Boot-line output continues to use
    // `logging::*` (those run before the runtime exists, so they cannot
    // depend on tracing's executor-aware machinery); request-path events
    // will go through tracing once the worker pool is up.
    observability::init_subscriber(observability::LogFormat::parse_or_text(
        &config.server.log_format,
    ));
    logging::info("config", &format!("loaded from {config_path}"));

    // 2. (config-derived state is now built later via ResolvedAppConfig::build —
    //  the standalone `let router = …` step was removed in favour of a single
    //  build entry point.)

    // 3. Load initial TLS — build acceptor once, cache via ArcSwap
    let initial_tls = tls::load_tls_config(&config.tls).map_err(error::ZionError::Tls)?;
    let acceptor = TlsAcceptor::from(Arc::new(initial_tls));
    let tls_acceptor_store = Arc::new(ArcSwap::from_pointee(acceptor));
    eprintln!(
        "  tls loaded (min={}, alpn={:?})",
        config.tls.min_version, config.tls.alpn
    );

    // 4. Start TLS hot-reload watcher (rebuilds acceptor on cert change).
    // The QUIC listener consumes the receiver to reload its server config in
    // sync with the TCP listener. Without the http3 feature there is no QUIC
    // listener, so the receiver is intentionally unused; the underscore-prefix
    // tells rustc this is by design.
    let (quic_reload_tx, _quic_reload_rx) = tokio::sync::watch::channel(None);
    if config.tls.hot_reload {
        tls::spawn_tls_watcher(
            tls_acceptor_store.clone(),
            config.tls.clone(),
            Some(quic_reload_tx),
        );
    }

    // 4b. Predictive TTL pre-warming: pre-build TLS config before cert expires
    tls::spawn_cert_prewarm_task(tls_acceptor_store.clone(), config.tls.clone());

    // 5. Build the config-derived snapshot (router, health map, trusted
    // proxies, XFF policy, rate-limit settings — everything that follows
    // from `zion.toml`). This is the single entry point that future
    // hot-reload phases will re-invoke and atomic-swap.
    let resolved = ResolvedAppConfig::build(&config);

    // Boot-time visibility: structured logs for the bits operators
    // commonly check at startup. (Validation of `xff_mode` happens
    // inside `ResolvedAppConfig::build`, but it falls back silently on
    // an unknown value; we log explicitly here so a typo in the config
    // surfaces without grep-ing the source.)
    if !resolved.trusted_proxies.is_empty() {
        logging::info(
            "proxy",
            &format!("trusted proxies: {:?}", config.server.trusted_proxies),
        );
    }
    if proxy::XffMode::parse(&config.server.xff_mode).is_none() {
        logging::warn(
            "config",
            &format!(
                "unknown server.xff_mode '{}', falling back to 'append' (valid: append/rewrite/drop)",
                config.server.xff_mode
            ),
        );
    }
    logging::info("proxy", &format!("xff_mode: {:?}", resolved.xff_mode));

    // Hold a clone for the background tasks below (health prober,
    // connection pool pre-warm) that spawn before the AppState `Arc` is
    // constructed and need the upstream URL → health map.
    let health_map = resolved.health_map.clone();

    // Track B observability handles. The audit writer is a tokio task
    // spawned now; its handle clones into AppState. Both are cheap to
    // clone — `AuditHandle` wraps an `mpsc::Sender`, `CompiledRedaction`
    // is two small `Vec<String>`.
    let audit_handle = audit::spawn_writer(&config.audit);
    let compiled_redact = Arc::new(config.redact.compile());

    let state = Arc::new(AppState {
        config: Arc::new(ArcSwap::from_pointee(resolved)),
        tls_acceptor: tls_acceptor_store,
        http_client: proxy::build_http_client(),
        static_cache: cache::StaticCache::new(),
        conn_limit: Arc::new(Semaphore::new(platform.conn_limit)),
        acme_challenges: acme::new_challenge_store(),
        rate_map: Arc::new(dashmap::DashMap::new()),
        inflight: dashmap::DashMap::new(),
        audit: audit_handle,
        redact: compiled_redact,
        http_builder: Arc::new({
            let mut b = AutoBuilder::new(TokioExecutor::new());
            b.http1().max_headers(64).max_buf_size(16 * 1024);
            b.http1().preserve_header_case(false);
            b.http1().title_case_headers(false);
            b
        }),
    });

    // 5b. Phase 1.5 channels.
    //  * `config_change_*` is bumped by the config watcher after every
    //    successful swap; the listener supervisor (built later) uses it
    //    to know when to reconcile bind addresses.
    //  * `super_shutdown_*` is flipped to `true` on SIGINT/SIGTERM by
    //    the main task and tells the supervisor to retire all listeners.
    let (config_change_tx, config_change_rx) = tokio::sync::watch::channel(0u64);
    let (super_shutdown_tx, super_shutdown_rx) = tokio::sync::watch::channel(false);

    // 5c. Spawn the config-file hot-reload watcher. Watches `zion.toml`
    // for Modify/Create events; on change, parses + validates the new
    // config and atomic-swaps `state.config`. Invalid configs are
    // rejected with a WARN log, the previous snapshot stays in place.
    // TLS settings (cert paths, min_version, SNI) are not currently
    // re-applied through this watcher — the existing `tls_watcher`
    // covers cert/key file changes; pivoting `[tls]` paths is a
    // separate hot-reload step beyond Phase 1.
    reload::spawn_config_watcher(
        config_path.clone().into(),
        state.config.clone(),
        Some(config_change_tx),
        Some(config.tls.cert_path.clone()),
        Some(config.tls.key_path.clone()),
    );

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

    // 7. Spawn rate limit cleanup (scavenge stale IPs every 60s).
    // This prevents the rate map from reaching MAX_RATE_MAP_ENTRIES
    // with dead entries, which would trigger the fail-closed path
    // for legitimate new IPs.
    if config.server.rate_limit_rps > 0 {
        let rate_map = state.rate_map.clone();
        let window = config.server.rate_limit_window_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let removed = security::scavenge_rate_map(&rate_map, window);
                if removed > 0 {
                    logging::info(
                        "rate_limit",
                        &format!(
                            "scavenged {} stale IPs ({} tracked)",
                            removed,
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
        let health_http_client = state.http_client.clone();
        tokio::spawn(async move {
            // Reuse the shared HTTP client for health checks. This has two benefits:
            // 1. HTTPS upstreams get TLS pre-warming (connections stay in pool)
            // 2. HTTP/2 multiplexing for HTTPS health probes
            let client = health_http_client;
            loop {
                let mut upstreams_to_check: Vec<(String, Arc<health::UpstreamHealth>)> = Vec::new();
                for (url, up) in hm.iter() {
                    upstreams_to_check.push((url.to_string(), Arc::clone(up)));
                }

                let mut join_set = tokio::task::JoinSet::new();

                for (url, up) in upstreams_to_check {
                    let client_clone = client.clone();
                    join_set.spawn(async move {
                        use http_body_util::BodyExt;
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
                            .body(
                                http_body_util::Full::new(bytes::Bytes::new())
                                    .map_err(|never| match never {})
                                    .boxed(),
                            )
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
                            logging::warn(
                                "health",
                                &format!(
                                    "upstream {url} is DOWN — requests to this upstream will return 503 until it recovers"
                                ),
                            );
                        } else if !was_healthy && healthy {
                            logging::info(
                                "health",
                                &format!("upstream {url} is UP ({lat}us)"),
                            );
                        }
                    });
                }
                while join_set.join_next().await.is_some() {}
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    // 8b. Pre-warm upstream connection pool (first health check warms TLS + DNS)
    // This eliminates cold-start latency on the first real request.
    if !health_map.is_empty() {
        let client = state.http_client.clone();
        let hm = health_map.clone();
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            for (url, _) in hm.iter() {
                let uri: hyper::Uri = match url.parse() {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                let req = hyper::Request::builder()
                    .uri(&uri)
                    .header(
                        "Host",
                        uri.authority().map(|a| a.as_str()).unwrap_or("localhost"),
                    )
                    .body(
                        http_body_util::Full::new(bytes::Bytes::new())
                            .map_err(|never| match never {})
                            .boxed(),
                    );
                if let Ok(req) = req {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        client.request(req),
                    )
                    .await;
                }
            }
            logging::info(
                "pool",
                &format!("pre-warmed {} upstream connections", hm.len()),
            );
        });
    }

    // 9. Initial bind: HTTP (port 80, optional) + HTTPS (port 443, primary).
    // HTTP bind failures are non-fatal (no CAP_NET_BIND_SERVICE on a
    // dev machine, port already in use, etc.); the listener supervisor
    // will retry on the next config reload. HTTPS bind failure at boot
    // is a hard error — there is nothing useful to do without it.
    let http_addr: SocketAddr = config.server.listen_http.parse().map_err(|e| {
        error::ZionError::Config(format!(
            "invalid listen_http address {:?}: {e}",
            config.server.listen_http
        ))
    })?;
    let http_initial: Option<(SocketAddr, tokio::net::TcpListener)> =
        match net::bind_with_reuseport(http_addr) {
            Ok(l) => {
                eprintln!("  listening HTTP  on {http_addr}");
                Some((http_addr, l))
            }
            Err(e) => {
                eprintln!("  warning: HTTP listener on {http_addr} unavailable: {e}");
                None
            }
        };

    let https_addr: SocketAddr = config.server.listen_https.parse().map_err(|e| {
        error::ZionError::Config(format!(
            "invalid listen_https address {:?}: {e}",
            config.server.listen_https
        ))
    })?;
    let https_listener = net::bind_with_reuseport(https_addr)
        .map_err(|e| error::ZionError::Listener(format!("HTTPS bind {https_addr}: {e}")))?;
    eprintln!("  listening HTTPS on {https_addr}");

    // io_uring multishot accept on Linux (one syscall for N connections).
    // The uring task is bound to the listener's fd at spawn time and the
    // listener supervisor explicitly does NOT manage HTTPS rebind in this
    // build flavour — that limitation is documented in `listener.rs`.
    // Operators using io_uring keep the v0.1.7 behaviour for `listen_https`
    // (restart required for port changes).
    #[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
    let https_initial: Option<(SocketAddr, tokio::net::TcpListener)> = {
        use std::os::unix::io::AsRawFd;
        let fd = https_listener.as_raw_fd();
        eprintln!("  io_uring multishot accept enabled");
        let uring_rx = uring::spawn_uring_accept(fd, 4096);
        // Spawn the accept loop ourselves; pass `https_initial = None`
        // to the supervisor so it tracks no HTTPS slot.
        let (tx, rx) = tokio::sync::watch::channel(false);
        let _ = tx; // sender held by main task lifetime; supervisor doesn't touch this loop
        tokio::spawn(run_https_accept_loop(
            https_listener,
            state.clone(),
            rx,
            Some(uring_rx),
        ));
        None
    };
    #[cfg(not(all(target_os = "linux", feature = "io-uring-accept")))]
    let https_initial: Option<(SocketAddr, tokio::net::TcpListener)> =
        Some((https_addr, https_listener));

    // 10. HTTP/3 (QUIC) listener on UDP — independent of the supervisor.
    // QUIC listen-port hot-reload is out of scope for Phase 1.5.
    #[cfg(feature = "http3")]
    {
        // INVARIANT: `config.server.listen_https` was already parsed above
        // (line ~819) into `https_addr` for the TCP bind. If it parsed once
        // it parses again — but we still surface a structured error if the
        // address grammar differs by some accident.
        let quic_addr: SocketAddr = config.server.listen_https.parse().map_err(|e| {
            error::ZionError::Config(format!(
                "invalid listen_https for QUIC ({:?}): {e}",
                config.server.listen_https
            ))
        })?;
        quic::spawn_quic_listener(quic_addr, &config.tls, state.clone(), Some(_quic_reload_rx))
            .map_err(error::ZionError::Tls)?;
    }

    bootstrap::print_ready_banner(&config.server.listen_http, &config.server.listen_https);

    // 11. Build the listener supervisor. It owns the HTTP/HTTPS accept
    // loops and reconciles them when `state.config` is hot-swapped to a
    // new snapshot whose `listen_*` differs. On io_uring the supervisor
    // is `https_initial = None`: it will log a WARN and refuse to rebind
    // HTTPS (the uring task above already drives the accept loop on the
    // initial listener for the lifetime of the process).
    let supervisor = listener::ListenerSupervisor::new(state.clone(), http_initial, https_initial);
    let supervisor_handle =
        supervisor.spawn_reconciler(state.config.clone(), config_change_rx, super_shutdown_rx);

    shutdown_signal().await;
    logging::info(
        "shutdown",
        "signal received, draining in-flight connections...",
    );
    // Tell the supervisor to retire all listeners. Its accept loops stop
    // on the next iteration; spawned per-connection tasks continue and
    // are drained by the semaphore wait below.
    let _ = super_shutdown_tx.send(true);
    // Best-effort wait on the supervisor to exit cleanly. Bounded by 2s
    // so a stuck reconcile does not block process shutdown.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), supervisor_handle).await;

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

// ──────────────────────────────────────────────────────────────────────
// Accept-loop functions
//
// Extracted as free functions in Phase 1.5 so that the listener
// supervisor can spawn / drain / respawn them when `[server.listen_*]`
// changes in `zion.toml`. Behaviour is identical to the previous
// inline `tokio::spawn(async move { ... })` blocks; the only addition
// is a `watch::Receiver<bool>` shutdown channel that lets the main
// task tell the loops to stop accepting (existing connection tasks
// continue independently).
// ──────────────────────────────────────────────────────────────────────

/// Run the plain-HTTP accept loop on the given listener until
/// `shutdown_rx` flips to `true` or the channel closes. New incoming
/// TCP connections are spawned as detached tasks; the loop never owns
/// them, so terminating the loop does not interrupt active requests.
async fn run_http_accept_loop(
    http_listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // Rate-limit accept error logging to avoid serializing the accept loop
    // under SYN floods (stderr lock + format! per error).
    let mut last_err_log = std::time::Instant::now() - std::time::Duration::from_secs(2);
    loop {
        tokio::select! {
            biased;
            res = shutdown_rx.changed() => {
                // Either the sender flipped to `true` or the channel closed.
                // In both cases we stop accepting; live connections continue.
                if res.is_err() || *shutdown_rx.borrow() {
                    return;
                }
            }
            accept = http_listener.accept() => {
                let (stream, addr) = match accept {
                    Ok(c) => c,
                    Err(e) => {
                        let now = std::time::Instant::now();
                        if now.duration_since(last_err_log).as_secs() >= 1 {
                            eprintln!("  http accept error: {e}");
                            last_err_log = now;
                        }
                        continue;
                    }
                };
                let conn_state = state.clone();
                let builder = state.http_builder.clone();
                tokio::spawn(handle_http_connection(stream, addr, conn_state, builder));
            }
        }
    }
}

/// Single HTTP/1.1 connection on port 80 — runs until the client closes.
/// Extracted from the previous inline spawn; behaviour unchanged.
async fn handle_http_connection(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    state: Arc<AppState>,
    builder: Arc<AutoBuilder<TokioExecutor>>,
) {
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
}

/// Run the HTTPS / TLS accept loop. On non-Linux or without the
/// `io-uring-accept` feature this is a plain `listener.accept()` loop;
/// with `io-uring-accept` the accepted-connection stream is consumed
/// from the kernel-batched receiver instead. The two paths are
/// cfg-gated to avoid pulling io_uring symbols on platforms that
/// don't have them.
#[cfg(not(all(target_os = "linux", feature = "io-uring-accept")))]
async fn run_https_accept_loop(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // Rate-limit accept error logging (same rationale as run_http_accept_loop).
    let mut last_err_log = std::time::Instant::now() - std::time::Duration::from_secs(2);
    loop {
        tokio::select! {
            biased;
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    return;
                }
            }
            accept = listener.accept() => {
                let (tcp_stream, remote_addr) = match accept {
                    Ok(c) => c,
                    Err(e) => {
                        let now = std::time::Instant::now();
                        if now.duration_since(last_err_log).as_secs() >= 1 {
                            eprintln!("  https accept error: {e}");
                            last_err_log = now;
                        }
                        continue;
                    }
                };
                spawn_https_handler(tcp_stream, remote_addr, state.clone());
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
async fn run_https_accept_loop(
    _listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut uring_rx: Option<tokio::sync::mpsc::Receiver<uring::AcceptedConn>>,
) {
    let Some(mut uring_rx) = uring_rx.take() else {
        return;
    };
    loop {
        tokio::select! {
            biased;
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    return;
                }
            }
            conn = uring_rx.recv() => {
                let Some(conn) = conn else { return; };
                spawn_https_handler(conn.stream, conn.addr, state.clone());
            }
        }
    }
}

/// Common path for spawning a single HTTPS connection task: enforces
/// the connection-limit semaphore, performs the TLS handshake, extracts
/// 0-RTT and mTLS-fingerprint context, then drives `serve_connection_with_upgrades`.
fn spawn_https_handler(
    tcp_stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: Arc<AppState>,
) {
    // Connection limit — fast atomic check, no Arc clone.
    let permit = match state.conn_limit.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            drop(tcp_stream);
            return;
        }
    };

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

        // 0-RTT: Check if this connection accepted early data. Only the
        // first request on the connection can be early data. We pass
        // this flag to handle_https for method gating (425 Too Early).
        let is_early_data = tls_stream.get_mut().1.early_data().is_some();
        let early_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(is_early_data));

        // mTLS: stable SHA-256 fingerprint of the leaf cert DER. See the
        // module-level rationale in v0.1.7 — replaced the previous XOR
        // pseudo-DN. Forwarded as `X-Client-Cert-Fingerprint`.
        let client_cert_fingerprint: Option<String> = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| {
                let der = cert.as_ref();
                let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
                let bytes = digest.as_ref();
                let mut s = String::with_capacity(7 + bytes.len() * 2);
                s.push_str("sha256:");
                for &b in bytes {
                    s.push(HEX_DIGITS[(b >> 4) as usize] as char);
                    s.push(HEX_DIGITS[(b & 0xF) as usize] as char);
                }
                s
            });
        let client_fp = client_cert_fingerprint.map(std::sync::Arc::new);

        let io = TokioIo::new(tls_stream);
        // Connection-level idle timeout. 1h to cover long-lived HTTP/2
        // mux / WebSocket / SSE; per-request timeouts are in process_request.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(3600),
            builder.serve_connection_with_upgrades(
                io,
                service_fn(move |mut req: Request<Incoming>| {
                    let state = state.clone();
                    let early_flag = early_flag.clone();
                    let client_fp = client_fp.clone();
                    async move {
                        // Fast-path: health probes bypass the full pipeline (~1us vs ~5us).
                        let path = req.uri().path();
                        if path == "/healthz" {
                            return Ok(text_response(StatusCode::OK, "ok"));
                        }
                        if path == "/readyz" {
                            return Ok(text_response(StatusCode::OK, "ready"));
                        }

                        // Consume early_data flag on first request.
                        let was_early =
                            early_flag.swap(false, std::sync::atomic::Ordering::Relaxed);
                        // Inject mTLS fingerprint header if the peer presented a cert.
                        if let Some(ref fp) = client_fp {
                            if let Ok(val) = hyper::header::HeaderValue::from_str(fp) {
                                req.headers_mut().insert("X-Client-Cert-Fingerprint", val);
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

/// Wait for SIGINT (Ctrl+C) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let terminate = async {
        // INVARIANT: signal handler installation only fails on (a) the
        // kernel rejecting `sigaction` (which never happens for SIGTERM
        // on a Unix system that successfully started a tokio runtime), or
        // (b) running outside a tokio context (we are inside `block_on`).
        // Both are unreachable in practice; if the kernel refuses SIGTERM
        // we have no graceful-shutdown signal anyway, so falling through
        // to ctrl_c is the correct degraded behaviour — but the daemon is
        // already in a wedged state at that point.
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

    // Live JSON snapshot — exposed on the plain-HTTP listener too so that
    // `zion top` can connect from the same host without dragging in a TLS
    // client. Same internal-IP gate as the HTTPS handler.
    if path == "/_zion/snapshot.json" {
        if !security::is_internal_ip(&remote_addr.ip()) {
            return Ok(empty_response(StatusCode::FORBIDDEN));
        }
        let platform = bootstrap::detect();
        let cfg = state.cfg();
        let mut rows: Vec<metrics::UpstreamRow<'_>> = cfg
            .health_map
            .iter()
            .map(|(url, h)| metrics::UpstreamRow {
                url: url.as_str(),
                healthy: h.healthy.load(std::sync::atomic::Ordering::Relaxed),
                latency_us: h.latency_us.load(std::sync::atomic::Ordering::Relaxed),
            })
            .collect();
        rows.sort_by(|a, b| a.url.cmp(b.url));
        let body = metrics::snapshot_json(platform, &rows);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Cache-Control", "no-store")
            .body(Full::new(body).map_err(|never| match never {}).boxed())
            .unwrap());
    }

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
        let cfg = state.cfg();
        if let Ok(m) = cfg.router.at(path) {
            let rule = m.value;
            return proxy::proxy_pass(
                &state.http_client,
                req,
                &rule.upstream_scheme,
                &rule.upstream_authority,
                Some(remote_addr),
                "http",
                cfg.xff_mode,
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

    let redirect_uri = format!("https://{host}{safe_path}");
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
    let cfg = state.cfg();
    security::check_rate_limit(
        cfg.rate_limit_rps,
        cfg.rate_limit_window,
        &state.rate_map,
        ip,
    )
}

/// Inject security headers — delegates to security module.
pub(crate) fn inject_security_headers(resp: &mut Response<ZionBody>) {
    security::inject_security_headers(resp);
}
