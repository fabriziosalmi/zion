// SPDX-License-Identifier: Apache-2.0
//! Shared runtime state: the config-derived snapshot (`ResolvedAppConfig`), the
//! behaviour-persistent limiters, and the top-level `AppState` every request
//! handler receives.
//!
//! Moved out of the crate root (`main.rs`) so the request pipeline
//! (`dispatch`, `listener`, `admin`, `quic`, `tls_fp`, `reload`) depends on this
//! module rather than on the file that wires them together (ZION-ARCH-01).
//! `main.rs` now only constructs these types.

#[cfg(feature = "sovereign-aimp")]
use crate::aimp_cp;
use crate::proxy::HttpClient;
use crate::security::RateEntry;
#[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
use crate::sovereign;
#[cfg(feature = "tls-fingerprint")]
use crate::tls_fp;
use crate::{
    acme, audit, cache, config, connlimit, error, health, logging, numa, proxy, routing, security,
};
use arc_swap::ArcSwap;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Snapshot of config-derived state. Everything in here is rebuilt from
/// `config::ZionConfig` and is intentionally independent of long-lived
/// runtime state (HTTP client pool, RAM caches, rate-limit IP map,
/// inflight singleflight, etc.) so that the whole snapshot can be
/// atomically swapped on hot-reload without disturbing in-flight
/// connections or warm caches.
///
/// `AppState` holds the snapshot as `Arc<ArcSwap<ResolvedAppConfig>>`. It is
/// built once at boot from `zion.toml`; the config watcher in `reload.rs`
/// rebuilds it on change, validates it, and `store()`s the new snapshot, so a
/// request that already loaded the old one keeps a consistent view until it
/// finishes.
pub(crate) struct ResolvedAppConfig {
    /// Host-aware L7 router (ADR-0010): a shared radix tree plus one tree per
    /// bound host. Hostless when no route declares `hosts` (zero extra cost).
    pub(crate) router: routing::HostRouter,
    /// Upstream URL → shared health/latency state. The `Arc<UpstreamHealth>`
    /// values are intentionally re-used across reloads when the URL is
    /// unchanged so the prober's accumulated state is preserved.
    pub(crate) health_map: health::HealthMap,
    /// Trusted proxy CIDRs for X-Forwarded-For IP resolution.
    pub(crate) trusted_proxies: security::TrustedProxies,
    /// Peers that count as internal for `/metrics`, the snapshot, cache purge and
    /// `internal_only` routes. See [`security::InternalNetworks`].
    pub(crate) internal_networks: security::InternalNetworks,
    /// Outbound XFF policy (append / rewrite / drop). See proxy::XffMode.
    pub(crate) xff_mode: proxy::XffMode,
    /// Per-IP rate limiter target (RPS). 0 = disabled.
    pub(crate) rate_limit_rps: u32,
    /// Rate limiter window in seconds.
    pub(crate) rate_limit_window: u64,
    pub(crate) rate_limit_max_tracked_ips: usize,
    /// Max concurrent connections per source IP. 0 = disabled. Read at
    /// accept, so a hot-reload retunes the cap without dropping live conns.
    pub(crate) max_connections_per_ip: u32,
    /// TCP keepalive idle seconds for accepted client sockets (0 = off).
    pub(crate) tcp_keepalive_secs: u64,
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
    /// Resolved JA4 fingerprinting runtime (#27). `None` when the feature is off
    /// or `[tls.fingerprint] mode = "off"` — the accept path then does no
    /// ClientHello peek (zero overhead).
    #[cfg(feature = "tls-fingerprint")]
    pub(crate) tls_fingerprint: Option<std::sync::Arc<tls_fp::TlsFpRuntime>>,
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
            router: routing::HostRouter::default(),
            health_map,
            trusted_proxies: security::TrustedProxies::from_config(&[]),
            internal_networks: security::InternalNetworks::default(),
            xff_mode: proxy::XffMode::Append,
            rate_limit_rps: 0,
            rate_limit_window: 1,
            rate_limit_max_tracked_ips: crate::security::MAX_RATE_MAP_ENTRIES,
            max_connections_per_ip: 0,
            tcp_keepalive_secs: crate::net::DEFAULT_TCP_KEEPALIVE_SECS,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            enforce: sovereign::EnforcePolicy::default(),
            listen_http: None,
            listen_https: None,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_enabled: false,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_log_classification: false,
            access_log: config::AccessLogConfig::default(),
            #[cfg(feature = "tls-fingerprint")]
            tls_fingerprint: None,
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
        let router = routing::build_router(config).map_err(error::ZionError::Config)?;
        // Process-wide upstream DNS policy (re-applied on every reload).
        crate::dns::configure(config.server.dns_stale_secs, config.server.dns_timeout_ms);

        // Health map: one entry per upstream URL referenced by any route.
        // The same URL can appear in many routes — dedup via FnvHashMap.
        let mut map = fnv::FnvHashMap::default();
        let mut outlier_claimed: std::collections::HashSet<String> = Default::default();
        for route in &config.route {
            // A static route has no upstream to probe.
            let Some(name) = route.upstream_name() else {
                continue;
            };
            let urls = if let Some(up) = config.upstream.get(name) {
                up.get_urls()
            } else if let Some(url) = config.upstreams.get(name) {
                vec![url.clone()]
            } else {
                continue;
            };
            // The breaker applies to a single-endpoint upstream: a pool already fails over
            // between its members.
            let breaker_cfg = config
                .upstream
                .get(name)
                .and_then(|u| u.circuit_breaker.as_ref())
                .filter(|_| urls.len() == 1)
                .map(|cb| cb.to_runtime());
            // Pool members (two or more endpoints) get passive health and load stats.
            let outlier_cfg = config
                .upstream
                .get(name)
                .and_then(|u| u.outlier_detection.as_ref())
                .filter(|_| urls.len() > 1)
                .map(|o| o.to_runtime());
            let is_pool = urls.len() > 1;
            for url in urls {
                let entry = map
                    .entry(url.clone())
                    .or_insert_with(|| Arc::new(health::UpstreamHealth::new_healthy()));
                // First route in config order wins; validation refuses conflicting tables.
                if breaker_cfg.is_some() && !entry.breaker.is_configured() {
                    entry.breaker.configure(breaker_cfg.clone());
                }
                if is_pool {
                    entry.pool.set_pool_member(true);
                    // The first pool route to name a URL decides its outlier detection, even
                    // when that is "off": a later route cannot switch it on for traffic that
                    // opted out.
                    if outlier_claimed.insert(url.clone()) {
                        entry.pool.configure_outlier(outlier_cfg.clone());
                    }
                }
            }
        }
        let health_map = Arc::new(map);

        let trusted_proxies = security::TrustedProxies::from_config(&config.server.trusted_proxies);
        let internal_networks =
            security::InternalNetworks::from_config(&config.server.internal_networks);

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
                // #151 self-DoS guard: the ceiling must stay a small fraction of
                // the connection pool (a held tarpit connection pins a permit +
                // per-IP slot for its whole hold). The invariant lives in the
                // policy itself; the root just wires it and logs the outcome.
                if let Some((old, cap)) = policy.clamp_tarpit_concurrency(conn_limit_max) {
                    logging::warn(
                        "sovereign",
                        &format!(
                            "[sovereign.enforce.tarpit] max_concurrent {old} exceeds 1/4 of the global connection ceiling ({conn_limit_max}) — clamping to {cap} so held connections can't pin the admission pool",
                        ),
                    );
                }
                if tp.enabled && policy.tarpit_max_concurrent > 0 {
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
            internal_networks,
            xff_mode,
            rate_limit_rps: config.server.rate_limit_rps,
            rate_limit_window: config.server.rate_limit_window_secs,
            rate_limit_max_tracked_ips: config.server.rate_limit_max_tracked_ips,
            max_connections_per_ip,
            tcp_keepalive_secs: config.server.tcp_keepalive_secs,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            enforce,
            listen_http,
            listen_https,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_enabled,
            #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
            sovereign_log_classification,
            access_log: config.access_log.clone(),
            #[cfg(feature = "tls-fingerprint")]
            tls_fingerprint: config
                .tls
                .fingerprint
                .as_ref()
                .and_then(tls_fp::TlsFpRuntime::from_config)
                .map(std::sync::Arc::new),
        })
    }
}

/// Behaviour-persistent per-source limiters, grouped so churn in one of them
/// stays local to this struct instead of rippling through the whole `AppState`
/// and all of its consumers (ZION-ARCH-02). Unlike the config-derived state
/// (isolated in `ResolvedAppConfig`), these track live client behaviour and
/// therefore persist across config reloads — a rate/conn/ban count is about the
/// client, not the config.
pub(crate) struct Limiters {
    /// Per-IP rate limiter map.
    ///
    /// NUMA wrapper (issue #50): on a single-socket box / non-Linux /
    /// `--no-default-features` build this is a transparent newtype
    /// around `DashMap`. With `--features numa-aware` on a multi-socket
    /// Linux host, `NumaAwareMap` shards by NUMA node and routes by the
    /// calling thread's current node — same-socket workers stay
    /// cache-local, cross-socket fallback scans on get-miss.
    pub(crate) rate_map: Arc<numa::NumaAwareMap<std::net::IpAddr, RateEntry>>,
    /// Per-IP concurrent-connection limiter. The cap is read from the config
    /// snapshot at accept time; the global ceiling stays the `conn_limit`
    /// semaphore on `AppState`.
    pub(crate) conn_per_ip: Arc<connlimit::PerIpConnLimiter>,
    /// Rejected-unknown JA4 ban set (#27 commit 4): fingerprint → banned until.
    /// Only ever consulted while the CURRENT config drops unknown fingerprints.
    #[cfg(feature = "tls-fingerprint")]
    pub(crate) tls_fp_bans: tls_fp::BanSet,
}

/// Global shared state — lock-free reads via Arc + ArcSwap.
pub(crate) struct AppState {
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
    pub(crate) tls_acceptor: Arc<ArcSwap<tokio_rustls::TlsAcceptor>>,
    /// Client for the default connect deadline (also used by the health prober).
    pub(crate) http_client: HttpClient,
    /// Clients for every other `connect_timeout_ms` in use, built on first use.
    /// A connector has one connect deadline, so upstreams with different values
    /// need different clients; keeping them here (not in the reloadable config
    /// snapshot) means their connection pools survive a hot reload.
    pub(crate) http_clients: dashmap::DashMap<u64, HttpClient>,
    pub(crate) static_cache: cache::StaticCache,
    pub(crate) conn_limit: Arc<Semaphore>,
    pub(crate) http_builder: Arc<AutoBuilder<TokioExecutor>>,
    /// ACME HTTP-01 challenge tokens (empty when no challenge active).
    pub(crate) acme_challenges: acme::ChallengeStore,
    /// Behaviour-persistent per-source limiters (rate map, per-IP conn cap,
    /// JA4 ban set) — grouped so subsystem churn stays local. See [`Limiters`].
    pub(crate) limiters: Limiters,
    /// Singleflight: coalesce concurrent cache misses for the same key.
    /// First request fetches from upstream and inserts a `watch::Sender<bool>`;
    /// subsequent requests subscribe and await `true`. Watch (vs Notify) is
    /// race-free: `wait_for` inspects the current value at first poll, so
    /// even if the fetcher completes between our get() and our .await we
    /// still observe the wake instead of hanging until the client times out.
    /// Sender drop without sending `true` (fetch aborted) yields Err on the
    /// receiver side and waiters fall through to re-check the cache.
    pub(crate) inflight: numa::NumaAwareMap<Arc<str>, tokio::sync::watch::Sender<bool>>,
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

    /// The pooled HTTP client whose connector enforces `connect_timeout_ms` (the
    /// route's `[upstream.*] connect_timeout_ms`). Cheap: `HttpClient` is a
    /// reference-counted handle onto the shared pool.
    pub(crate) fn client_for(&self, connect_timeout_ms: u64) -> HttpClient {
        if connect_timeout_ms == crate::proxy::DEFAULT_CONNECT_TIMEOUT_MS {
            return self.http_client.clone();
        }
        if let Some(c) = self.http_clients.get(&connect_timeout_ms) {
            return c.clone();
        }
        self.http_clients
            .entry(connect_timeout_ms)
            .or_insert_with(|| crate::proxy::build_http_client(connect_timeout_ms))
            .clone()
    }
}

#[cfg(test)]
impl AppState {
    /// A fully wired `AppState` for in-process tests of the request pipeline: no
    /// sockets, no certificate on disk (an empty SNI resolver stands in for TLS),
    /// every limiter fresh. Health starts as `new_healthy` for every upstream.
    pub(crate) fn for_tests(config: &config::ZionConfig) -> Arc<Self> {
        // The daemon installs the process-wide provider at boot; tests do it here.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let resolved = ResolvedAppConfig::try_build(config, 1024).expect("test config builds");
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new())),
        ));
        Arc::new(AppState {
            config: Arc::new(ArcSwap::from_pointee(resolved)),
            tls_acceptor: Arc::new(ArcSwap::from_pointee(tls)),
            http_client: proxy::build_http_client(proxy::DEFAULT_CONNECT_TIMEOUT_MS),
            http_clients: dashmap::DashMap::new(),
            static_cache: cache::StaticCache::new(),
            conn_limit: Arc::new(Semaphore::new(1024)),
            http_builder: Arc::new(AutoBuilder::new(TokioExecutor::new())),
            acme_challenges: acme::new_challenge_store(),
            limiters: Limiters {
                rate_map: Arc::new(numa::NumaAwareMap::new()),
                conn_per_ip: Arc::new(connlimit::PerIpConnLimiter::new()),
                #[cfg(feature = "tls-fingerprint")]
                tls_fp_bans: tls_fp::BanSet::new(),
            },
            inflight: numa::NumaAwareMap::new(),
            audit: audit::AuditHandle::noop(),
            redact: Arc::new(audit::CompiledRedaction::default()),
            #[cfg(feature = "sovereign-aimp")]
            aimp_cp: None,
        })
    }
}
