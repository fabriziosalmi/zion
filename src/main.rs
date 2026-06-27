// SPDX-License-Identifier: Apache-2.0
//! Zion Edge Gateway — binary entry point.
//!
//! Boots the daemon: parses CLI flags (`zion`, `zion init`, `zion top`,
//! `zion doctor`, `zion bootstrap`, `zion auto`), loads `zion.toml`,
//! builds the resolved runtime config (`ResolvedAppConfig::try_build`),
//! starts the TLS acceptor + listeners (HTTP/HTTPS, optional QUIC),
//! spawns the cert-watcher, the config-reload watcher, the cache prober
//! and the audit writer, and finally hands every accepted connection to
//! `dispatch::handle_request`.
//!
//! `main()` returns `error::ZionResult<()>` so any boot-time failure
//! propagates with a structured exit code instead of panicking.

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
mod admin;
mod audit;
mod auth;
mod bootstrap;
mod cache;
mod cli;
mod config;
mod connlimit;
mod doctor;
mod error;
mod health;
mod init;
mod listener;
mod logging;
mod metrics;
mod net;
mod numa;
mod observability;
mod proxy;
#[cfg(feature = "http3")]
mod quic;
mod reload;
mod security;
#[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
mod sovereign;
mod suggest;
mod tarpit;
mod tls;
#[cfg(feature = "tui")]
mod tui;
// `uring.rs` compiles on every target — the io_uring-accept inner
// module is feature-gated *inside* the file. This way the
// `io-uring-rw` capability probe (issue #51) and its tests stay
// reachable even when `io-uring-accept` is off, and on non-Linux the
// probe degrades to "always returns false".
mod uring;
mod waf;

// ── Beyond-FAANG tracks (experimental, feature-gated) ─────────────────
// Track A — XDP pre-filter: drops blacklisted CIDRs at NIC driver layer.
#[cfg(all(target_os = "linux", feature = "xdp"))]
mod xdp;
// v0.2 perf-ceiling — SO_REUSEPORT + BPF demux scaffolding (issue #53).
// Probe + capability check today; listener wire-up deferred.
#[cfg(all(target_os = "linux", feature = "bpf-demux"))]
mod bpf_demux;
// Track A — kTLS post-handshake offload (Linux >= 5.10 + CONFIG_TLS).
#[cfg(all(target_os = "linux", feature = "ktls"))]
mod ktls;
// Track A — memfd-backed cache entries (issue #52 building block).
// Compiles on Linux only; consumed by the future sendfile dispatch
// path. Gated on `--features ktls` so today's bin builds without it
// don't carry an unused module.
#[cfg(all(target_os = "linux", feature = "ktls"))]
mod memfd;
// Track C — ML-augmented WAF scoring (ONNX via tract).
#[cfg(feature = "ml-waf")]
mod waf_ml;
// Track B — AIMP-as-control-plane: serverless gossip of WAF rules and
// IP reputation via Merkle-CRDT. Top-level `aimp_cp` instead of nesting
// under `sovereign::` so it does not pull in geo-* features by accident.
#[cfg(feature = "sovereign-aimp")]
mod aimp_cp;
// AIMP→XDP reconciler. Lives in its own file so the example crates
// (`examples/aimp_*.rs`) that embed `aimp_cp.rs` via `#[path]` don't
// drag in `crate::xdp::*` references they cannot resolve.
#[cfg(all(target_os = "linux", feature = "xdp", feature = "sovereign-aimp"))]
mod aimp_xdp_sync;

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
    /// Max concurrent connections per source IP. 0 = disabled. Read at
    /// accept, so a hot-reload retunes the cap without dropping live conns.
    pub(crate) max_connections_per_ip: u32,
    /// Resolved tag-driven enforcement policy (`[sovereign.enforce]`, #150).
    /// Lives under the geo-gated `[sovereign]` block (class deny needs the
    /// dataset). Disabled by default. Mesh-score deny additionally needs
    /// `--features sovereign-aimp`.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    pub(crate) enforce: sovereign::EnforcePolicy,
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
    /// Access-log emission policy (issue #60). Snapshot of
    /// `ZionConfig.access_log` with header names already lowercased
    /// at config-load time.
    pub(crate) access_log: config::AccessLogConfig,
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
            max_connections_per_ip: 0,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            enforce: sovereign::EnforcePolicy::default(),
            listen_http: None,
            listen_https: None,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_enabled: false,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_log_classification: false,
            access_log: config::AccessLogConfig::default(),
        }
    }

    /// Build a snapshot from a parsed `ZionConfig`.
    ///
    /// This is the single entry point that turns the static TOML config
    /// into the runtime-shaped state the request pipeline reads. Phase 1
    /// uses it once at boot; subsequent phases call it again on every
    /// hot-reload and atomic-swap the result.
    ///
    /// Returns `Err(ZionError::Config)` if the router cannot be built
    /// (bad patterns, unknown profiles). At boot the error propagates to
    /// `main()` and the process exits with the structured ZionResult code;
    /// during hot-reload the existing snapshot stays in place and the
    /// new config is rejected with a logged WARN.
    pub(crate) fn try_build(
        config: &config::ZionConfig,
        conn_limit_max: usize,
    ) -> error::ZionResult<Self> {
        let router = config::build_router(config).map_err(error::ZionError::Config)?;

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
                map.entry(url.clone())
                    .or_insert_with(|| Arc::new(health::UpstreamHealth::new_healthy()));
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

        // Resolve the tag-driven enforcement policy (#150) and warn on any
        // deny label that matches no known IpClass — a typo would silently
        // never fire, which is exactly the failure an operator can't see.
        #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
        let enforce = {
            let mut policy = sovereign::EnforcePolicy::from_config(&config.sovereign.enforce);
            if config.sovereign.enforce.enabled {
                let unknown = policy.unknown_deny_labels();
                if !unknown.is_empty() {
                    logging::warn(
                        "sovereign",
                        &format!(
                            "[sovereign.enforce] deny lists unknown class label(s) {:?} — they will never match (known: {:?})",
                            unknown,
                            sovereign::known_class_labels(),
                        ),
                    );
                }
                let tp = &config.sovereign.enforce.tarpit;
                // #151: a tarpit with a zero ceiling holds nothing — every
                // flagged request sheds straight to the 403. Surface it so the
                // operator doesn't think the tarpit is doing anything.
                if tp.enabled && tp.max_concurrent == 0 {
                    logging::warn(
                        "sovereign",
                        "[sovereign.enforce.tarpit] enabled with max_concurrent = 0 — every flagged request is shed to an immediate 403 (tarpit is a no-op)",
                    );
                }
                // #151 self-DoS guard: a held tarpit connection keeps its
                // global connection-pool permit and per-IP slot for the whole
                // hold, so the ceiling must stay a small fraction of the pool —
                // otherwise a flood of flagged sources pins admission. Clamp to
                // 1/4 of the global connection ceiling and say so.
                if tp.enabled && policy.tarpit_max_concurrent > 0 {
                    let safety_cap = ((conn_limit_max / 4) as u32).max(1);
                    if policy.tarpit_max_concurrent > safety_cap {
                        logging::warn(
                            "sovereign",
                            &format!(
                                "[sovereign.enforce.tarpit] max_concurrent {} exceeds 1/4 of the global connection ceiling ({}) — clamping to {} so held connections can't pin the admission pool",
                                policy.tarpit_max_concurrent, conn_limit_max, safety_cap,
                            ),
                        );
                        policy.tarpit_max_concurrent = safety_cap;
                    }
                    // A few seconds already imposes the cost; very long holds
                    // tie up connections (capped by the connection idle timeout)
                    // and slow the shutdown drain.
                    if tp.hold_secs > 60 {
                        logging::warn(
                            "sovereign",
                            &format!(
                                "[sovereign.enforce.tarpit] hold_secs = {} is very large — a few seconds already imposes the cost; long holds tie up connections and slow shutdown drain",
                                tp.hold_secs,
                            ),
                        );
                    }
                }
            }
            policy
        };

        // Per-IP connection cap (CVE-2026-49975 multi-connection hardening),
        // resolved from the tri-state config field. `None` (omitted) defaults
        // ON at ~1/8 of the global connection ceiling so no single source can
        // monopolize admission or run the multi-connection HTTP/2 Bomb; the
        // cap scales with the box (via `conn_limit_max`) so it won't pinch
        // CGNAT/large-NAT on big nodes. `Some(0)` is an explicit opt-out.
        let max_connections_per_ip = match config.server.max_connections_per_ip {
            None => ((conn_limit_max / 8) as u32).max(1),
            Some(explicit) => explicit,
        };

        Ok(Self {
            router,
            health_map,
            trusted_proxies,
            xff_mode,
            rate_limit_rps: config.server.rate_limit_rps,
            rate_limit_window: config.server.rate_limit_window_secs,
            max_connections_per_ip,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            enforce,
            listen_http,
            listen_https,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_enabled,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_log_classification,
            access_log: config.access_log.clone(),
        })
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
    ///
    /// NUMA wrapper (issue #50): on a single-socket box / non-Linux /
    /// `--no-default-features` build this is a transparent newtype
    /// around `DashMap`. With `--features numa-aware` on a multi-socket
    /// Linux host, `NumaAwareMap` shards by NUMA node and routes by the
    /// calling thread's current node — same-socket workers stay
    /// cache-local, cross-socket fallback scans on get-miss.
    rate_map: Arc<numa::NumaAwareMap<std::net::IpAddr, RateEntry>>,
    /// Per-IP concurrent-connection limiter. Like `rate_map`, persists
    /// across config reloads (it tracks live sockets, not config); the cap
    /// is read from the config snapshot at accept time. The global ceiling
    /// stays the `conn_limit` semaphore above.
    conn_per_ip: Arc<connlimit::PerIpConnLimiter>,
    /// Singleflight: coalesce concurrent cache misses for the same key.
    /// First request fetches from upstream and inserts a `watch::Sender<bool>`;
    /// subsequent requests subscribe and await `true`. Watch (vs Notify) is
    /// race-free: `wait_for` inspects the current value at first poll, so
    /// even if the fetcher completes between our get() and our .await we
    /// still observe the wake instead of hanging until the client times out.
    /// Sender drop without sending `true` (fetch aborted) yields Err on the
    /// receiver side and waiters fall through to re-check the cache.
    inflight: numa::NumaAwareMap<Arc<str>, tokio::sync::watch::Sender<bool>>,
    /// HMAC-chained audit log handle. `noop()` when audit is disabled.
    /// Cloned per request handler; `emit()` is non-blocking.
    pub(crate) audit: audit::AuditHandle,
    /// Compiled PII redaction policy. Applied at audit-event construction
    /// time. Cheap to clone (`Vec<String>`); held by Arc for ABI stability
    /// across hot-reloads of `[redact]`.
    pub(crate) redact: Arc<audit::CompiledRedaction>,
    /// AIMP serverless control plane handle (Track B). `None` when the
    /// feature is compiled in but disabled by config, or when bootstrap
    /// failed (logged at boot). The dispatcher uses this for both
    /// `lookup` (pre-WAF reputation gate) and `publish_block` (gossip a
    /// local block to the mesh). Cloning is cheap — internal `Arc`s.
    #[cfg(feature = "sovereign-aimp")]
    pub(crate) aimp_cp: Option<aimp_cp::AimpControlPlane>,
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

// ── Explicit HTTP/2 limits — CVE-2026-49975 ("HTTP/2 Bomb") hardening ──
//
// These are pinned on the server builder (see the `http_builder` block in
// `async_main`) rather than left to hyper/h2's defaults, so the
// per-connection memory ceiling is an ASSERTED property of Zion, not a
// transitive-dependency default a future bump could silently move. The
// HTTP/2 Bomb chains an HPACK decompression bomb with a flow-control "hold";
// the defence is (a) a small decoded-header-list cap that h2 enforces
// incrementally during HPACK decode, (b) a stream cap bounding how many such
// lists can be held open at once, (c) the Rapid-Reset bound, and (d)
// keep-alive PINGs that reap a connection gone silent mid-hold.
//
// Worst-case retained decoded-header memory per connection is therefore
// bounded by `H2_MAX_CONCURRENT_STREAMS * H2_MAX_HEADER_LIST_SIZE`
// (= 2 MiB here). `h2_limit_tests` pins that invariant.

/// SETTINGS_MAX_CONCURRENT_STREAMS advertised to peers. 128 matches the
/// common hardened default (e.g. nginx) and is ample for legitimate
/// multiplexing while halving hyper's 200 default.
const H2_MAX_CONCURRENT_STREAMS: u32 = 128;
/// SETTINGS_MAX_HEADER_LIST_SIZE — the decoded (post-HPACK) header-list cap
/// h2 enforces incrementally per stream. 16 KiB matches the conservative
/// default; this is the per-stream half of the bomb ceiling.
const H2_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;
/// Rapid-Reset (CVE-2023-44487) bound: peer-reset streams allowed to sit
/// pending-accept before the connection is treated as abusive.
const H2_MAX_PENDING_ACCEPT_RESET_STREAMS: usize = 20;
/// Keep-alive PING cadence / deadline. A client that opens streams and then
/// goes silent (the flow-control "hold" half of the bomb) fails the PING and
/// is dropped instead of pinning stream state indefinitely.
const H2_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const H2_KEEPALIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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

/// 405 Method Not Allowed with the mandatory `Allow` header (RFC 9110 §15.5.6:
/// "The origin server MUST generate an Allow header field in a 405"). `allow`
/// is the comma-separated method list valid at that resource, e.g.
/// `"GET, HEAD, POST"`. Static value → header parse is infallible.
pub(crate) fn method_not_allowed(allow: &'static str) -> Response<ZionBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(hyper::header::ALLOW, allow)
        .body(
            Full::new(EMPTY_BYTES.clone())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// 401 Unauthorized with the mandatory `WWW-Authenticate` challenge (RFC 9110
/// §15.5.2: "The server generating a 401 response MUST send a WWW-Authenticate
/// header field"). `challenge` is the scheme + optional params, e.g. `"Bearer"`
/// or `Bearer error="invalid_token"` (RFC 6750 §3). Static values → infallible.
// Only the `--features auth` gate emits 401s today; keep it building (and
// unit-tested) without the feature.
#[cfg_attr(not(feature = "auth"), allow(dead_code))]
pub(crate) fn unauthorized(text: &'static str, challenge: &'static str) -> Response<ZionBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(hyper::header::WWW_AUTHENTICATE, challenge)
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
        cli::Command::Suggest(opts) => {
            std::process::exit(suggest::run(opts));
        }
        cli::Command::AcmeSoak => {
            #[cfg(feature = "acme")]
            {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                std::process::exit(rt.block_on(acme::run_soak()));
            }
            #[cfg(not(feature = "acme"))]
            {
                eprintln!(
                    "zion acme-soak requires the `acme` feature.\n\
                     rebuild with: cargo build --release --features acme"
                );
                std::process::exit(2);
            }
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

    // ── PANIC DOCTRINE (release) ──
    // The release profile is `panic = "abort"` (Cargo.toml): a panic aborts the
    // process — it does NOT unwind, so `catch_unwind` is a no-op in release and
    // a single reachable panic on the request path would drop every in-flight
    // connection. The doctrine that makes this safe is therefore, in order:
    //   1. NO reachable panic on the request/reload hot path — `unwrap`/`expect`/
    //      indexing there is a bug to eliminate, not to catch (audited: none
    //      reachable with attacker-controlled input as of the W2 hardening).
    //   2. This boot panic hook: every panic emits a structured last-gasp JSON
    //      (stderr + file) so a sidecar / next-boot probe self-reports the death.
    // Switching to `panic = "unwind"` + a request-path catch_unwind→500 is a
    // deliberate trade (binary size, unwind-safety across the unsafe libc/io_uring
    // FFI) — a separate decision, not adopted here.
    //
    // 0a-pre. Install the panic hook BEFORE any worker thread is spawned so
    //         every panic — boot, async worker, anywhere — emits a structured
    //         JSON record to stderr and to a last-gasp file (so a sidecar /
    //         next-boot probe can self-report the previous death). This runs
    //         once before abort. The path is overridable via ZION_LAST_GASP_PATH.
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
        )?;

        // 4b. Predictive TTL pre-warming: pre-build the TLS config before the
        // cert expires. It hot-swaps the acceptor and rotates the session-
        // ticket key, so it must obey the same hot_reload switch as the watcher
        // — otherwise it silently rotates certs/keys (breaking resumption /
        // 0-RTT) behind an operator who set hot_reload = false.
        tls::spawn_cert_prewarm_task(tls_acceptor_store.clone(), config.tls.clone());
    }

    // 5. Build the config-derived snapshot (router, health map, trusted
    // proxies, XFF policy, rate-limit settings — everything that follows
    // from `zion.toml`). This is the single entry point that future
    // hot-reload phases will re-invoke and atomic-swap.
    let resolved = ResolvedAppConfig::try_build(&config, platform.conn_limit)?;

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

    // io_uring rw kernel probe boot line (issue #51). Emitted only when
    // the operator opted into `--features io-uring-rw`, otherwise the
    // probe result is just a Platform field surfaced on /metrics.
    // The full IoUringStream wire-up that consumes this is tracked on
    // a follow-up; the boot line lets a deployment confirm the host is
    // ready before the perf work lands.
    #[cfg(feature = "io-uring-rw")]
    {
        if platform.has_io_uring_rw_kernel {
            logging::info(
                "io_uring_rw",
                "kernel supports vectored rw (>= 5.19) — feature ready, runtime adapter pending follow-up",
            );
        } else {
            logging::warn(
                "io_uring_rw",
                "kernel does NOT support vectored rw (need >= 5.19) — feature compiled in but auto-disabled",
            );
        }
    }

    // kTLS post-handshake offload boot probe (issue #52). Surfaced
    // unconditionally when the feature is on so a deployment can
    // confirm the kernel + module set is ready for in-kernel record
    // framing + the future sendfile path. The probe itself is one
    // socket() + setsockopt(TCP_ULP, "tls") + close — cheap.
    #[cfg(all(target_os = "linux", feature = "ktls"))]
    {
        if crate::ktls::probe_kernel_support() {
            logging::info(
                "ktls",
                "kernel supports kTLS (TCP_ULP=tls) — handshake corker active, sendfile path pending follow-up",
            );
        } else {
            logging::warn(
                "ktls",
                "kernel does NOT advertise kTLS support — try_upgrade will fail and the connection will close",
            );
        }
    }

    // SO_REUSEPORT + BPF demux probe (issue #53). Reports kernel
    // version + capability state at boot so an operator can tell
    // whether the (currently-deferred) listener wire-up will be able
    // to attach the program when it lands.
    #[cfg(all(target_os = "linux", feature = "bpf-demux"))]
    {
        match crate::bpf_demux::probe() {
            crate::bpf_demux::DemuxReadiness::Ready => logging::info(
                "bpf_demux",
                "kernel + capabilities ready (>= 5.7, CAP_BPF or CAP_SYS_ADMIN) — listener wire-up pending follow-up",
            ),
            crate::bpf_demux::DemuxReadiness::KernelTooOld { release } => logging::warn(
                "bpf_demux",
                &format!(
                    "kernel {release} < 5.7 — SO_ATTACH_REUSEPORT_EBPF + UDP support unavailable; default reuseport hash will be used"
                ),
            ),
            crate::bpf_demux::DemuxReadiness::MissingCapability => logging::warn(
                "bpf_demux",
                "kernel ready but process lacks CAP_BPF/CAP_SYS_ADMIN — grant with `setcap cap_bpf+ep` or run as root",
            ),
            crate::bpf_demux::DemuxReadiness::NotLinux => {} // unreachable under cfg
        }
    }

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

    // Optionally bootstrap the AIMP serverless control plane. When
    // AIMP control plane bootstrap. Two configuration sources, in
    // order of precedence:
    //   1. `[sovereign_aimp]` block in zion.toml (preferred; reviewable
    //      and hot-reloadable along with the rest of config).
    //   2. `ZION_AIMP_*` env vars (legacy; back-compat for the v0.2.1
    //      env-only release).
    // If either says enabled = true, we bootstrap. Env-var values fill
    // in any missing TOML field, never override one that's set.
    //
    // Failure to bootstrap is non-fatal — log once at WARN and continue
    // with `aimp_cp = None`. The dispatcher already handles that case.
    #[cfg(feature = "sovereign-aimp")]
    let aimp_cp_handle: Option<aimp_cp::AimpControlPlane> = {
        let env_enabled = std::env::var("ZION_AIMP_ENABLED").ok().as_deref() == Some("1");
        let toml_cfg = &config.sovereign_aimp;
        let enabled = toml_cfg.enabled || env_enabled;
        if enabled {
            let listen_raw = if !toml_cfg.listen.is_empty() {
                toml_cfg.listen.clone()
            } else {
                std::env::var("ZION_AIMP_LISTEN").unwrap_or_else(|_| "0.0.0.0:9443".to_string())
            };
            let listen: std::net::SocketAddr = listen_raw
                .parse()
                .unwrap_or_else(|_| "0.0.0.0:9443".parse().unwrap());
            let peers: Vec<std::net::SocketAddr> = if !toml_cfg.peers.is_empty() {
                toml_cfg
                    .peers
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect()
            } else {
                std::env::var("ZION_AIMP_PEERS")
                    .unwrap_or_default()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            };
            let identity_path = if !toml_cfg.identity_path.is_empty() {
                std::path::PathBuf::from(&toml_cfg.identity_path)
            } else {
                std::env::var("ZION_AIMP_IDENTITY_PATH")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/zion/aimp-identity.bin"))
            };
            let cfg = aimp_cp::AimpControlPlaneConfig {
                enabled: true,
                listen,
                peers,
                identity_path,
                anti_entropy_secs: toml_cfg.anti_entropy_secs,
                inbound_claims_per_sec: toml_cfg.inbound_claims_per_sec,
                inbound_claim_burst: toml_cfg.inbound_claim_burst,
            };
            match aimp_cp::bootstrap(cfg).await {
                Ok(cp) => {
                    eprintln!(
                        "  AIMP control plane up: node_id[0..4]={:02x?} listen={} peers={}",
                        &cp.node_id()[..4],
                        listen,
                        cp.reputation().is_empty() as u8 // touch the handle
                    );
                    Some(cp)
                }
                Err(e) => {
                    crate::logging::warn(
                        "aimp_cp",
                        &format!("bootstrap failed: {e} — continuing without AIMP"),
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    let state = Arc::new(AppState {
        config: Arc::new(ArcSwap::from_pointee(resolved)),
        tls_acceptor: tls_acceptor_store,
        http_client: proxy::build_http_client(),
        static_cache: cache::StaticCache::new(),
        conn_limit: Arc::new(Semaphore::new(platform.conn_limit)),
        acme_challenges: acme::new_challenge_store(),
        rate_map: Arc::new(numa::NumaAwareMap::new()),
        conn_per_ip: Arc::new(connlimit::PerIpConnLimiter::new()),
        inflight: numa::NumaAwareMap::new(),
        audit: audit_handle,
        redact: compiled_redact,
        http_builder: Arc::new({
            let mut b = AutoBuilder::new(TokioExecutor::new());
            // A clock MUST be installed or hyper's header_read_timeout (and any
            // other time-based limit) is silently a no-op — hyper logs "no timer
            // set". With the timer in place, a client that opens a connection
            // and then dribbles or stalls its request headers is dropped after
            // the deadline instead of pinning a connection slot (and, on :443,
            // a conn-limit permit + per-IP slot) for up to the connection cap.
            // Basic slowloris defence, applied on both :80 and :443.
            b.http1().timer(hyper_util::rt::TokioTimer::new());
            b.http1().max_headers(64).max_buf_size(16 * 1024);
            b.http1()
                .header_read_timeout(std::time::Duration::from_secs(15));
            b.http1().preserve_header_case(false);
            b.http1().title_case_headers(false);
            // Explicit HTTP/2 limits — CVE-2026-49975 ("HTTP/2 Bomb")
            // hardening. Pinned, not inherited from hyper/h2 defaults, so the
            // per-connection memory ceiling is an asserted property (see the
            // H2_* consts + `h2_limit_tests`). max_concurrent_streams ×
            // max_header_list_size bounds retained decoded-header memory per
            // connection; the Rapid-Reset bound blunts CVE-2023-44487; the
            // keep-alive PING reaps a connection gone silent mid-hold (the
            // flow-control half of the bomb). The keep-alive PING is time-based,
            // so — exactly as on http1 above — a timer MUST be installed on the
            // http2 builder too, or hyper panics "You must supply a timer." the
            // first time it tries to schedule the PING deadline.
            b.http2().timer(hyper_util::rt::TokioTimer::new());
            b.http2().max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
            b.http2().max_header_list_size(H2_MAX_HEADER_LIST_SIZE);
            b.http2()
                .max_pending_accept_reset_streams(H2_MAX_PENDING_ACCEPT_RESET_STREAMS);
            b.http2().keep_alive_interval(H2_KEEPALIVE_INTERVAL);
            b.http2().keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);
            b
        }),
        #[cfg(feature = "sovereign-aimp")]
        aimp_cp: aimp_cp_handle,
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
        platform.conn_limit,
        Some(config_change_tx),
        Some(config.tls.cert_path.clone()),
        Some(config.tls.key_path.clone()),
    );

    // 5b. Admin API listener (#26 Phase 2) — read-only, loopback by default.
    // listen + auth were validated at config load. Phase 2 only enforces the
    // `internal-ip` gate; `mtls` is accepted by the schema but NOT yet enforced
    // (Phase 4), so refuse to spawn rather than serve admin with an unenforced
    // auth claim — fail safe.
    if let Some(ref admin_cfg) = config.admin {
        match admin_cfg.listen.parse::<std::net::SocketAddr>() {
            Ok(addr) if admin_cfg.auth == "internal-ip" => {
                admin::spawn_admin_listener(state.clone(), addr);
            }
            Ok(_) => logging::error(
                "admin",
                &format!(
                    "admin.auth = '{}' is not yet enforced (mTLS lands in #26 Phase 4) — admin API NOT spawned",
                    admin_cfg.auth
                ),
            ),
            Err(e) => logging::error("admin", &format!("admin.listen invalid: {e}")),
        }
    }

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

    // 7. Spawn rate-limit map cleanup (scavenge stale IPs every 60s).
    // This prevents the rate map from reaching MAX_RATE_MAP_ENTRIES with
    // dead entries, which would trigger the fail-closed path for legitimate
    // new IPs.
    //
    // Spawned UNCONDITIONALLY rather than gated on the boot-time
    // `rate_limit_rps`: the limiter can be turned on by a hot-reload
    // (rps 0 → N, enforced live in `check_rate_limit`), and without a running
    // scavenger the map would then grow unbounded and trip the fail-closed
    // path. The window is read live from the current snapshot each pass so a
    // window change is honored too. When the limiter is disabled the map
    // stays ~empty and the 60 s scavenge is a cheap no-op.
    {
        let state_for_scavenge = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                // `.max(1)` guards scavenge_rate_map's `now / window` against a
                // 0 window ever reaching the snapshot.
                let window = state_for_scavenge.cfg().rate_limit_window.max(1);
                let removed = security::scavenge_rate_map(&state_for_scavenge.rate_map, window);
                if removed > 0 {
                    logging::info(
                        "rate_limit",
                        &format!(
                            "scavenged {} stale IPs ({} tracked)",
                            removed,
                            state_for_scavenge.rate_map.len()
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
            // Monotonic base for every adaptive probe deadline (immune to NTP
            // jumps — all scheduling is in µs-since-base, never wall-clock).
            let base = tokio::time::Instant::now();
            const MIN_TICK_US: u64 = 10_000;
            loop {
                let now_us = base.elapsed().as_micros() as u64;
                // Probe only upstreams whose adaptive deadline is due: a HEALTHY
                // upstream every STEADY_US (unchanged 30s), a DOWN one on the
                // decorrelated-jitter backoff schedule — fast self-heal without
                // a recovery thundering-herd.
                let mut due: Vec<(String, Arc<health::UpstreamHealth>)> = Vec::new();
                for (url, up) in hm.iter() {
                    if up
                        .next_probe_at_us
                        .load(std::sync::atomic::Ordering::Relaxed)
                        <= now_us
                    {
                        due.push((url.to_string(), Arc::clone(up)));
                    }
                }

                let mut join_set = tokio::task::JoinSet::new();

                for (url, up) in due {
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
                        // Advance the adaptive probe schedule: a success resets
                        // the backoff to base and returns to the STEADY cadence;
                        // a failure draws the next decorrelated-jitter delay.
                        up.reschedule(healthy, base.elapsed().as_micros() as u64);
                        if was_healthy && !healthy {
                            let next_ms = up
                                .backoff_us
                                .load(std::sync::atomic::Ordering::Relaxed)
                                / 1000;
                            logging::warn(
                                "health",
                                &format!(
                                    "upstream {url} is DOWN — 503 until it recovers; adaptive re-probe in ~{next_ms}ms"
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

                // Sleep until the earliest upstream is next due, floored so an
                // all-due-now state cannot busy-spin.
                let now2 = base.elapsed().as_micros() as u64;
                let next_due = hm
                    .values()
                    .map(|u| {
                        u.next_probe_at_us
                            .load(std::sync::atomic::Ordering::Relaxed)
                    })
                    .min()
                    .unwrap_or_else(|| now2 + health::STEADY_US);
                let sleep_us = next_due.saturating_sub(now2).max(MIN_TICK_US);
                tokio::time::sleep(std::time::Duration::from_micros(sleep_us)).await;
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

    // io_uring single-shot accept on Linux (dedicated thread, one SQE re-submitted per connection).
    // The uring task is bound to the listener's fd at spawn time and the
    // listener supervisor explicitly does NOT manage HTTPS rebind in this
    // build flavour — that limitation is documented in `listener.rs`.
    // Operators using io_uring keep the v0.1.7 behaviour for `listen_https`
    // (restart required for port changes).
    #[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
    let https_initial: Option<(SocketAddr, tokio::net::TcpListener)> = {
        use std::os::unix::io::AsRawFd;
        let fd = https_listener.as_raw_fd();
        eprintln!("  io_uring single-shot accept enabled");
        let uring_rx = uring::spawn_uring_accept(fd, 4096);
        // Spawn the accept loop ourselves; pass `https_initial = None`
        // to the supervisor so it tracks no HTTPS slot.
        //
        // Subscribe to the REAL process shutdown signal (`super_shutdown_tx`,
        // flipped on SIGINT/SIGTERM). The earlier code created a throwaway
        // `watch::channel(false)` and then did `let _ = tx;` — which drops the
        // Sender immediately. With no live sender, the loop's very first
        // `shutdown_rx.changed()` returned `Err` → the loop `return`ed at once
        // → `uring_rx` was dropped → the accept thread's `try_send` then failed
        // (channel closed) for every accepted connection, which was silently
        // reset. Net effect: io_uring accept "listened" but served nothing
        // (curl: connection reset during the TLS ClientHello). Subscribing to a
        // sender that actually lives for the process fixes the lifetime and
        // gives the loop a working graceful-shutdown path.
        let uring_shutdown_rx = super_shutdown_tx.subscribe();
        tokio::spawn(run_https_accept_loop(
            https_listener,
            state.clone(),
            uring_shutdown_rx,
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
    // Mirror the HTTPS accept ceremony so :80 is not an unmetered bypass of
    // the connection ceiling. Without these, the :80 listener accepted
    // unbounded held connections — climbing FD/task count and starving the
    // shared runtime that also serves :443. The global conn-limit permit and
    // the per-IP slot are held for the connection's lifetime and released on
    // drop (including early return / panic).
    let _permit = match state.conn_limit.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return,
    };
    let _ip_slot = match state
        .conn_per_ip
        .try_acquire(addr.ip(), state.config.load().max_connections_per_ip)
    {
        Some(slot) => slot,
        None => {
            metrics::METRICS
                .connections_rejected_per_ip
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
    };
    let _conn_guard = metrics::ConnectionGuard::new();
    metrics::METRICS
        .connections_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // Disable Nagle on the accepted socket. Without this, response data
    // for small replies (e.g. /healthz, 301 redirects) gets coalesced
    // with the FIN handshake or paired with delayed-ACK on the client,
    // adding ~40-200ms to TTFB. The HTTPS path already does this in
    // its accept site; this is the symmetric call for HTTP.
    let _ = stream.set_nodelay(true);
    net::tune_accepted(&stream);

    let io = TokioIo::new(stream);
    // Connection-level idle timeout — matches the HTTPS path (1h, generous
    // enough for keep-alive; header_read_timeout bounds the slowloris header
    // phase, per-request limits live in handle_http).
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3600),
        builder.serve_connection(
            io,
            service_fn(move |req| {
                use http_body_util::BodyExt;
                let req_boxed = req.map(|b: hyper::body::Incoming| b.boxed());
                handle_http(req_boxed, state.clone(), addr)
            }),
        ),
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
                // Convert std -> tokio TcpStream HERE: we are in a tokio runtime
                // context, whereas the io_uring accept thread is not (its
                // `from_std` would panic "no reactor running").
                match tokio::net::TcpStream::from_std(conn.std_stream) {
                    Ok(stream) => spawn_https_handler(stream, conn.addr, state.clone()),
                    Err(e) => eprintln!("  io_uring accept: tokio from_std failed: {e}"),
                }
            }
        }
    }
}

/// Rate-limit TLS-handshake failure logging to ~one line per second,
/// process-wide. A failed handshake is per-connection — each runs on its own
/// task, so there is no shared `last_log` instant like the accept loops keep;
/// this gates on a shared timestamp instead. The `tls_handshake_errors` metric
/// still counts *every* failure; only the stderr line is throttled, so a
/// scanning/hostile client can't turn handshake failures into a log flood.
/// Best-effort: a benign race may let two lines through in the same second.
fn tls_handshake_log_allowed() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST_LOG_MS: AtomicU64 = AtomicU64::new(0);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last = LAST_LOG_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) >= 1000 {
        LAST_LOG_MS.store(now_ms, Ordering::Relaxed);
        true
    } else {
        false
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
    // Global connection ceiling — fast atomic check, no Arc clone.
    let permit = match state.conn_limit.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            drop(tcp_stream);
            return;
        }
    };

    // Per-IP concurrent-connection cap (anti-DDoS, issue #150 lever). Read
    // the cap from the live config snapshot so a hot-reload retunes it.
    // `cap == 0` short-circuits inside `try_acquire` (zero overhead). A
    // rejected source is closed immediately, before the TLS handshake.
    let ip_slot = match state
        .conn_per_ip
        .try_acquire(remote_addr.ip(), state.config.load().max_connections_per_ip)
    {
        Some(slot) => slot,
        None => {
            metrics::METRICS
                .connections_rejected_per_ip
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            drop(tcp_stream);
            return;
        }
    };

    let acceptor = state.tls_acceptor.load_full();
    let builder = state.http_builder.clone();

    tokio::spawn(async move {
        let _permit = permit;
        // Held for the connection's lifetime; releases the per-IP slot on
        // drop (including early return / panic during the handshake).
        let _ip_slot = ip_slot;
        let _conn_guard = metrics::ConnectionGuard::new();
        let _ = tcp_stream.set_nodelay(true);
        net::tune_accepted(&tcp_stream);
        metrics::METRICS
            .connections_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // kTLS upgrade requires the rustls handshake to happen on a
        // `CorkStream<TcpStream>` adapter (ktls 6.x API). Wrap up-front
        // when the feature is on; the cfg-gated branch costs nothing
        // when compiled without it.
        #[cfg(all(target_os = "linux", feature = "ktls"))]
        let inner_for_handshake = crate::ktls::cork_for_handshake(tcp_stream);
        #[cfg(not(all(target_os = "linux", feature = "ktls")))]
        let inner_for_handshake = tcp_stream;

        let tls_start = std::time::Instant::now();
        let mut tls_stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            (*acceptor).accept(inner_for_handshake),
        )
        .await
        {
            Ok(Ok(s)) => {
                metrics::METRICS
                    .tls_handshake_duration
                    .observe(tls_start.elapsed());
                s
            }
            Ok(Err(e)) => {
                if tls_handshake_log_allowed() {
                    eprintln!("  tls handshake failed from {remote_addr}: {e}");
                }
                metrics::METRICS
                    .tls_handshake_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            Err(_) => {
                if tls_handshake_log_allowed() {
                    eprintln!("  tls handshake timed out (10s) from {remote_addr}");
                }
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
        // pseudo-DN. Forwarded as `X-Client-Cert-Fingerprint`. Read the
        // peer certificates BEFORE any kTLS upgrade — after the upgrade
        // the rustls connection state is gone (kernel owns the AEAD).
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

        // Optionally swap the userspace TLS stream for an in-kernel
        // KtlsStream. The kernel takes over record framing + AEAD so
        // hyper sees plaintext directly. Failure here closes the
        // connection — there is no fall-back to userspace mode on the
        // same stream (the cork adapter is consumed by `try_upgrade`).
        //
        // The cfg-arms are mutually exclusive, so `io` resolves to a
        // single concrete type per build (no dyn / boxing needed —
        // `serve_connection_with_upgrades` is generic over the IO).
        #[cfg(all(target_os = "linux", feature = "ktls"))]
        let io = match crate::ktls::try_upgrade(tls_stream).await {
            Ok(ktls_stream) => TokioIo::new(ktls_stream),
            Err(e) => {
                eprintln!("  kTLS upgrade failed, closing connection: {e}");
                return;
            }
        };
        #[cfg(not(all(target_os = "linux", feature = "ktls")))]
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
                        // X-Client-Cert-Fingerprint is Zion's attestation of a
                        // verified client certificate; a client must never be
                        // able to set it. Strip any inbound value (and the
                        // legacy -DN) unconditionally, THEN re-inject only the
                        // verified fingerprint when the peer actually presented
                        // a cert — otherwise a forged header survives to the
                        // upstream and the access log as a fake mTLS identity.
                        req.headers_mut().remove("X-Client-Cert-Fingerprint");
                        req.headers_mut().remove("X-Client-Cert-DN");
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
    mut req: Request<ZionBody>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Plaintext :80 never has a verified client certificate, so any inbound
    // X-Client-Cert-Fingerprint / -DN is forged. Strip both before the request
    // is logged or proxied, so a client cannot smuggle a fake mTLS identity.
    req.headers_mut().remove("X-Client-Cert-Fingerprint");
    req.headers_mut().remove("X-Client-Cert-DN");

    // Rate limit HTTP/80 to prevent DoS via redirect/ACME flood
    if !check_rate_limit(&state, remote_addr.ip()) {
        metrics::METRICS
            .rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(empty_response(StatusCode::TOO_MANY_REQUESTS));
    }

    // URI length check — measure path+query, matching the HTTPS handler. The
    // old check looked at path() only, so a short path with a multi-kilobyte
    // query string slipped past the cap on :80 (reflected into the redirect
    // Location and the access log).
    let uri_len = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().len())
        .unwrap_or_else(|| req.uri().path().len());
    if uri_len > MAX_URI_LEN {
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

#[cfg(test)]
mod response_header_tests {
    use super::*;

    #[test]
    fn method_not_allowed_carries_allow_header() {
        // RFC 9110 §15.5.6 MUST: a 405 carries the Allow header.
        let resp = method_not_allowed("GET, HEAD, POST");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            resp.headers().get(hyper::header::ALLOW).unwrap(),
            "GET, HEAD, POST"
        );
    }

    #[test]
    fn unauthorized_carries_www_authenticate() {
        // RFC 9110 §15.5.2 MUST: a 401 carries the WWW-Authenticate challenge.
        let resp = unauthorized("authorization required", "Bearer");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(hyper::header::WWW_AUTHENTICATE).unwrap(),
            "Bearer"
        );
    }
}

#[cfg(test)]
mod h2_limit_tests {
    use super::*;

    /// CVE-2026-49975 regression guard. Pinning the H2 limits explicitly only
    /// buys safety if the per-connection memory ceiling stays an asserted
    /// invariant: if someone widens these, this test fails and forces a
    /// conscious re-evaluation of the bound rather than a silent regression.
    ///
    /// The floor checks deliberately assert on `const` values — that is the
    /// whole point (a tripwire on the constants), so the `assertions_on_constants`
    /// lint is intentionally allowed here.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn h2_per_connection_memory_is_bounded() {
        // Every concurrent stream may hold a decoded header list up to the cap.
        let worst_case_header_bytes =
            H2_MAX_CONCURRENT_STREAMS as u64 * H2_MAX_HEADER_LIST_SIZE as u64;
        assert!(
            worst_case_header_bytes <= 4 * 1024 * 1024,
            "H2 per-conn header ceiling {worst_case_header_bytes} B exceeds 4 MiB — \
             the HTTP/2 Bomb single-connection bound would regress"
        );
        // Functional floors: not so small they break legitimate multiplexing
        // or normal request headers.
        assert!(
            H2_MAX_CONCURRENT_STREAMS >= 64,
            "stream cap too low for legit multiplexing"
        );
        assert!(
            H2_MAX_HEADER_LIST_SIZE >= 8 * 1024,
            "header cap too low for normal requests"
        );
        // Rapid-Reset defence must stay present and bounded.
        assert!(
            (1..=100).contains(&H2_MAX_PENDING_ACCEPT_RESET_STREAMS),
            "pending-accept reset bound must be a small positive number"
        );
        // A silent-hold must be reaped before it can pin state for long.
        assert!(
            H2_KEEPALIVE_TIMEOUT <= H2_KEEPALIVE_INTERVAL,
            "keep-alive timeout should not exceed the interval"
        );
    }
}
