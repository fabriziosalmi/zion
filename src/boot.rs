// SPDX-License-Identifier: Apache-2.0
//! The boot sequence, one named phase at a time.
//!
//! `main.rs::async_main` calls these in order; each takes what it needs and returns what the
//! next one needs, so the order in which things start is the order of that function. The
//! pieces here are the same code that used to be one 800-line function, moved, not changed.

#[cfg(feature = "sovereign-aimp")]
use crate::aimp_cp;
#[cfg(feature = "http3")]
use crate::quic;
use crate::state::{AppState, Limiters, ResolvedAppConfig};
#[cfg(feature = "tls-fingerprint")]
use crate::tls_fp;
use crate::{
    acme, admin, audit, auth, bootstrap, cache, config, connlimit, dns, drain, error, health,
    logging, net, numa, observability, proxy, security, tls,
};
use arc_swap::ArcSwap;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;

/// Reload channel from the TLS watcher to the QUIC listener.
pub(crate) type QuicReload = watch::Receiver<Option<Arc<rustls::ServerConfig>>>;
/// A bound listener and the address it is bound to.
type Bound = Option<(SocketAddr, tokio::net::TcpListener)>;

// ── Explicit HTTP/2 limits — CVE-2026-49975 ("HTTP/2 Bomb") hardening ──
//
// These are pinned on the server builder (see `http_server_builder` below
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

/// Do the internal-only gates (`/metrics`, snapshot, cache purge, `internal_only`
/// routes) rest on "the peer has a private address" while the listener is
/// reachable from beyond loopback and nothing says which private peers are real?
/// In that shape a private-range load balancer, Kubernetes SNAT or a Docker bridge
/// makes every internet client look internal. Pure, so it is unit-tested.
fn internal_gates_trust_any_private_peer(server: &config::ServerConfig) -> bool {
    let routable = server
        .listen_https
        .parse::<std::net::SocketAddr>()
        .map(|a| !a.ip().is_loopback())
        .unwrap_or(true);
    routable && server.trusted_proxies.is_empty() && server.internal_networks.is_empty()
}

/// Warn loudly when the config uses a section whose behaviour is compiled out.
/// The silent footgun this closes: an operator sets `auth_profile` on a route
/// (or `[tls.acme]`) but built the binary without the matching feature, so the
/// section parses and validates yet does *nothing* — routes believed to be
/// authenticated serve unauthenticated, certs believed to auto-renew don't.
/// Sections gated on the struct field itself (`[sovereign_aimp]`, sovereign
/// geo) already hard-fail at parse via `deny_unknown_fields`, so they need no
/// warning here — only the parse-clean-but-inert ones do.
fn warn_feature_config_gaps(config: &config::ZionConfig) {
    if internal_gates_trust_any_private_peer(&config.server) {
        logging::warn(
            "config",
            "internal-only endpoints (/metrics, /_zion/snapshot.json, routes with internal_only) \
             accept ANY private-range peer. Behind a private-range load balancer, Kubernetes \
             SNAT or a Docker bridge, every internet client looks internal and can read metrics \
             and reach internal_only routes (the cache purge is loopback-only in this \
             configuration). Set [server] trusted_proxies (so the real client IP is used) or \
             [server] internal_networks (an explicit allowlist).",
        );
    }
    // A literal JWT HMAC secret in zion.toml is deprecated in favour of
    // `secret_env` (the key ends up in version control / config management).
    for (name, profile) in &config.auth_profile {
        if profile.secret.is_some() && profile.secret_env.is_none() {
            logging::warn(
                "config",
                &format!(
                    "auth_profile '{name}' uses a literal `secret` in zion.toml — deprecated; \
                     move the key to an environment variable and set `secret_env` instead."
                ),
            );
        }
    }
    // A profile with no lifetime cap accepts a token whatever its `exp`. The default becomes
    // 24 h in the next minor release (#553): say so now, per profile.
    for (name, profile) in &config.auth_profile {
        if profile.max_token_lifetime_secs.is_none() {
            logging::info(
                "config",
                &format!(
                    "auth_profile '{name}': max_token_lifetime_secs is not set, so the default \
                     cap of 86400 (24 h) applies and tokens that expire further out are \
                     refused (before 0.10.0 there was no cap). Set it to the longest lifetime \
                     you issue, or to 0 for no cap."
                ),
            );
        }
    }
    // Same for the IP pseudonymisation key: with it, every logged token can be reversed.
    if config.redact.ip_hmac_key.is_some() {
        logging::warn(
            "config",
            "[redact] ip_hmac_key is a literal in zion.toml — deprecated; move the key to an \
             environment variable and set `ip_hmac_key_env` instead.",
        );
    }
    // (A route with auth_profile on a build without `--features auth` is a config
    // error, see config::semantic_errors: it would serve unauthenticated.)
    #[cfg(not(feature = "auth"))]
    {
        if !config.auth_profile.is_empty() {
            logging::warn(
                "config",
                "[auth_profile] is defined but this binary was built WITHOUT \
                 `--features auth`; no route uses it, so nothing is served \
                 unauthenticated, but it would be refused if one did.",
            );
        }
    }
    #[cfg(not(feature = "acme"))]
    {
        if config.tls.acme.is_some() {
            logging::warn(
                "config",
                "[tls.acme] is configured but this binary was built WITHOUT \
                 `--features acme` — certificates will NOT be obtained or \
                 auto-renewed. Rebuild with `--features acme`, or manage certs \
                 externally.",
            );
        }
    }
    #[cfg(not(feature = "tls-fingerprint"))]
    {
        let fp_active = config
            .tls
            .fingerprint
            .as_ref()
            .is_some_and(|fp| fp.mode != config::FingerprintMode::Off);
        if fp_active {
            logging::warn(
                "config",
                "[tls.fingerprint] is set to a non-off mode but this binary was \
                 built WITHOUT `--features tls-fingerprint` — JA4 fingerprints \
                 are NOT computed and no connection is observed or gated. \
                 Rebuild with `--features tls-fingerprint`.",
            );
        }
    }
    // NOTE: the allowlist "open side door" (on_unknown = drop + on_unfingerprintable
    // = allow) is now a HARD config-validation error (see config::semantic_errors),
    // so it can never reach this post-load warning — the earlier warn here was
    // promoted to a fail-closed boot error and removed.

    // Auth profile with no audience/issuer scoping: signature+exp are still
    // checked, but ANY token signed by the same key/issuer is accepted — a
    // confused-deputy risk in a fleet that shares an HMAC secret or OIDC issuer.
    // Warn (not fatal — some single-tenant setups legitimately omit them).
    #[cfg(feature = "auth")]
    for (name, p) in &config.auth_profile {
        if p.audience.is_none() || p.issuer.is_none() {
            logging::warn(
                "config",
                &format!(
                    "auth_profile '{name}' has no {} — signature and expiry are still \
                     validated, but a token minted for a DIFFERENT audience/issuer sharing \
                     the same key would be accepted (confused-deputy). Set issuer and \
                     audience to scope acceptance.",
                    match (p.issuer.is_none(), p.audience.is_none()) {
                        (true, true) => "issuer or audience",
                        (true, false) => "issuer",
                        _ => "audience",
                    }
                ),
            );
        }
    }
    // In a build where every referenced feature is present, all blocks above
    // compile out and `config` is otherwise unused here.
    let _ = config;
}

/// Read `zion.toml`, start logging and tracing, and warn about what the file asks for that this build cannot do.
pub(crate) fn load_config() -> error::ZionResult<(String, config::ZionConfig)> {
    let config_path = std::env::var("ZION_CONFIG").unwrap_or_else(|_| "zion.toml".to_string());
    let config = config::load_config(&config_path).map_err(error::ZionError::Config)?;
    logging::init(&config.server.log_format);
    // tracing-subscriber init mirrors the log_format choice — JSON for
    // production, pretty for dev. Boot-line output continues to use
    // `logging::*` (those run before the runtime exists, so they cannot
    // depend on tracing's executor-aware machinery); request-path events
    // will go through tracing once the worker pool is up.
    observability::init_subscriber(
        observability::LogFormat::parse_or_text(&config.server.log_format),
        config.server.log_queue_lines,
    );
    logging::info("config", &format!("loaded from {config_path}"));
    warn_feature_config_gaps(&config);
    Ok((config_path, config))
}

/// Load the first TLS configuration, and start the watchers that keep it current.
///
/// Returns the acceptor store and the receiver the QUIC listener reloads from.
pub(crate) fn load_tls(
    config: &config::ZionConfig,
) -> error::ZionResult<(Arc<ArcSwap<TlsAcceptor>>, QuicReload)> {
    tls::recover_interrupted_renewals(&config.tls);
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
    Ok((tls_acceptor_store, _quic_reload_rx))
}

/// Build the config-derived snapshot (router, health map, trusted proxies, XFF policy, rate-limit
/// settings: everything that follows from `zion.toml`) and fix the connection ceiling.
///
/// Returns the snapshot and the ceiling, which holds for the life of the process.
pub(crate) fn resolve_config(
    config: &config::ZionConfig,
    platform: &bootstrap::Platform,
) -> error::ZionResult<(ResolvedAppConfig, usize)> {
    // The connection ceiling, fixed here for the life of the process: the configured
    // `max_connections`, or the value derived from memory (the cgroup limit when there
    // is one). The per-IP default and the tarpit cap below are derived from it.
    let conn_ceiling = bootstrap::set_conn_ceiling(config.server.max_connections);
    if let Some(configured) = config.server.max_connections {
        let derived = platform.conn_limit;
        let needs_mb = configured as u64 * 256 / 1024;
        if configured > derived {
            logging::warn(
                "boot",
                &format!(
                    "server.max_connections = {configured} is above the {derived} derived from {} MB of memory: at 256 KB a connection that many need about {needs_mb} MB",
                    platform.ram_mb
                ),
            );
        } else {
            logging::info(
                "boot",
                &format!(
                    "connection ceiling {configured} (server.max_connections; {derived} would be derived from {} MB of memory)",
                    platform.ram_mb
                ),
            );
        }
    }
    let resolved = ResolvedAppConfig::try_build(&config, conn_ceiling)?;
    dns::configure(resolved.dns_stale_secs, resolved.dns_timeout_ms);
    cache::configure(resolved.cache_budget_bytes);
    logging::info(
        "boot",
        &match (
            resolved.cache_budget_bytes / (1024 * 1024),
            config.server.cache_max_memory_mb,
        ) {
            (0, _) => {
                "response cache: no memory budget (server.cache_max_memory_mb = 0)".to_string()
            }
            (mb, Some(_)) => format!("response cache budget {mb} MiB (server.cache_max_memory_mb)"),
            (mb, None) => format!(
                "response cache budget {mb} MiB (an eighth of {} MB of memory)",
                platform.ram_mb
            ),
        },
    );

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
    logging::info("proxy", &format!("xff_mode: {:?}", resolved.xff_mode));

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
    Ok((resolved, conn_ceiling))
}

#[cfg(feature = "sovereign-aimp")]
/// AIMP control plane bootstrap. Two configuration sources, in order of precedence:
///   1. `[sovereign_aimp]` in zion.toml (preferred; reviewable and hot-reloadable with the rest).
///   2. `ZION_AIMP_*` env vars (legacy; back-compat for the v0.2.1 env-only release).
///
/// If either says enabled = true, we bootstrap. Env-var values fill in any missing TOML field,
/// never override one that is set.
///
/// Failure to bootstrap is non-fatal: it is logged once at WARN and the result is `None`, which
/// the dispatcher already handles.
pub(crate) async fn start_aimp_control_plane(
    config: &config::ZionConfig,
) -> Option<aimp_cp::AimpControlPlane> {
    let env_enabled = std::env::var("ZION_AIMP_ENABLED").ok().as_deref() == Some("1");
    let toml_cfg = &config.sovereign_aimp;
    let enabled = toml_cfg.enabled || env_enabled;
    if enabled {
        let listen_raw = if !toml_cfg.listen.is_empty() {
            toml_cfg.listen.clone()
        } else {
            // Fail closed on an ENABLED-but-unconfigured listen: default to
            // LOOPBACK, never `0.0.0.0` — an operator who enabled the mesh
            // without naming an interface must not get the gossip control
            // plane bound to every interface by accident (the world-open
            // default was the ZION-CONF gap). Set `sovereign_aimp.listen`
            // (or ZION_AIMP_LISTEN) explicitly to expose it on a real NIC.
            std::env::var("ZION_AIMP_LISTEN").unwrap_or_else(|_| "127.0.0.1:9443".to_string())
        };
        // Fail closed: a malformed listen address must NOT silently fall back
        // to a default — that could bind the gossip control plane somewhere
        // unintended. The TOML path is already rejected at config validation;
        // this also covers the `ZION_AIMP_LISTEN` env override, which bypasses
        // that check. On a bad value, skip mesh bootstrap (aimp_cp = None) —
        // bootstrap failure is non-fatal by design.
        let listen: Option<std::net::SocketAddr> = match listen_raw.parse() {
            Ok(addr) => Some(addr),
            Err(e) => {
                eprintln!(
                    "  AIMP control plane disabled: listen '{listen_raw}' is not a valid \
                     socket address: {e}"
                );
                None
            }
        };
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
        // Trusted node ids: TOML, else ZION_AIMP_TRUSTED_KEYS (comma-separated).
        // Validation already refused a malformed TOML entry; the env path is
        // checked here, and bootstrap refuses an empty list (fail closed).
        let trusted_raw: Vec<String> = if !toml_cfg.trusted_keys.is_empty() {
            toml_cfg.trusted_keys.clone()
        } else {
            std::env::var("ZION_AIMP_TRUSTED_KEYS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string)
                .collect()
        };
        let trusted_keys: Option<Vec<[u8; 32]>> = trusted_raw
            .iter()
            .map(|k| aimp_cp::parse_node_key(k))
            .collect();
        if trusted_keys.is_none() {
            eprintln!(
                "  AIMP control plane disabled: a trusted key is not a node id \
                 (64 hex characters)"
            );
        }
        match listen.zip(trusted_keys) {
            None => None, // invalid listen or keys already reported; fail closed
            Some((listen, trusted_keys)) => {
                let cfg = aimp_cp::AimpControlPlaneConfig {
                    enabled: true,
                    listen,
                    peers,
                    identity_path,
                    anti_entropy_secs: toml_cfg.anti_entropy_secs,
                    inbound_claims_per_sec: toml_cfg.inbound_claims_per_sec,
                    inbound_claim_burst: toml_cfg.inbound_claim_burst,
                    trusted_keys,
                };
                match aimp_cp::bootstrap(cfg).await {
                    Ok(cp) => {
                        // The full id: it is what the other nodes put in trusted_keys.
                        eprintln!(
                            "  AIMP control plane up: node_id={} listen={}",
                            aimp_cp::node_key_hex(&cp.node_id()),
                            listen,
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
            }
        }
    } else {
        None
    }
}

/// The connection builder shared by :80 and :443: timeouts, header limits, and the explicit HTTP/2 limits above.
fn http_server_builder() -> AutoBuilder<TokioExecutor> {
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
}

/// The shared state every request reads: the config snapshot, the TLS acceptor, the upstream clients, the caches and limiters.
pub(crate) fn build_state(
    resolved: ResolvedAppConfig,
    tls_acceptor_store: Arc<ArcSwap<TlsAcceptor>>,
    conn_ceiling: usize,
    audit_handle: audit::AuditHandle,
    compiled_redact: Arc<audit::CompiledRedaction>,
    #[cfg(feature = "sovereign-aimp")] aimp_cp_handle: Option<aimp_cp::AimpControlPlane>,
) -> Arc<AppState> {
    Arc::new(AppState {
        config: Arc::new(ArcSwap::from_pointee(resolved)),
        tls_acceptor: tls_acceptor_store,
        http_client: proxy::build_http_client(proxy::DEFAULT_CONNECT_TIMEOUT_MS, false),
        http_clients: dashmap::DashMap::new(),
        static_cache: cache::StaticCache::new(),
        conn_limit: Arc::new(Semaphore::new(conn_ceiling)),
        acme_challenges: acme::new_challenge_store(),
        limiters: Limiters {
            rate_map: Arc::new(numa::NumaAwareMap::new()),
            rate_sweep: security::RateSweep::default(),
            conn_per_ip: Arc::new(connlimit::PerIpConnLimiter::new()),
            #[cfg(feature = "tls-fingerprint")]
            tls_fp_bans: tls_fp::BanSet::new(),
        },
        inflight: numa::NumaAwareMap::new(),
        audit: audit_handle,
        redact: compiled_redact,
        http_builder: Arc::new(http_server_builder()),
        #[cfg(feature = "sovereign-aimp")]
        aimp_cp: aimp_cp_handle,
    })
}

/// The admin API listener (#26), loopback by default.
pub(crate) fn spawn_admin_api(
    config: &config::ZionConfig,
    state: &Arc<AppState>,
    conn_ceiling: usize,
    config_path: &str,
    config_change_tx: &watch::Sender<u64>,
) -> error::ZionResult<()> {
    // validated at config load (auth ∈ {internal-ip, mtls}; mtls ⇒ client_ca_path
    // is set). `internal-ip` gates on the peer IP over plain HTTP; `mtls` requires
    // a client cert chaining to `admin.client_ca_path` (the handshake is the auth).
    if let Some(ref admin_cfg) = config.admin {
        // Revocations recorded by earlier runs come back before any request is served. A
        // file that cannot be read stops the boot: starting without it would make every
        // revoked token valid again.
        if let Some(path) = admin_cfg.revocations_path.as_deref() {
            match auth::revocation::load(std::path::Path::new(path)) {
                Ok((live, skipped)) => {
                    logging::info(
                        "auth",
                        &format!("{live} revoked token id(s) loaded from {path}"),
                    );
                    if skipped > 0 {
                        logging::warn(
                            "auth",
                            &format!("{skipped} unreadable line(s) in {path} were skipped"),
                        );
                    }
                }
                Err(e) => {
                    return Err(error::ZionError::Config(format!(
                        "admin.revocations_path: cannot load the revocation list: {e}"
                    )));
                }
            }
        }
        match admin_cfg.listen.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                let auth = match admin_cfg.auth.as_str() {
                    "mtls" => match admin_cfg.client_ca_path.as_deref() {
                        Some(ca) => match tls::admin_mtls_acceptor(
                            &config.tls.cert_path,
                            &config.tls.key_path,
                            ca,
                            admin_cfg.client_crl_path.as_deref(),
                            admin_cfg.client_crl_enforce_next_update,
                        ) {
                            Ok(acc) => {
                                let store = std::sync::Arc::new(ArcSwap::from_pointee(acc));
                                // The admin listener re-reads its certificate, CA and CRL
                                // when they change, like the data plane: revoking an admin
                                // certificate must not need a restart.
                                if config.tls.hot_reload {
                                    tls::spawn_admin_tls_watcher(
                                        store.clone(),
                                        config.tls.cert_path.clone(),
                                        config.tls.key_path.clone(),
                                        ca.to_string(),
                                        admin_cfg.client_crl_path.clone(),
                                        admin_cfg.client_crl_enforce_next_update,
                                    );
                                }
                                Some(admin::AdminAuth::Mtls(store))
                            }
                            Err(e) => {
                                logging::error(
                                    "admin",
                                    &format!("mTLS acceptor: {e} — admin API NOT spawned"),
                                );
                                None
                            }
                        },
                        // Guarded by validation; defensive.
                        None => {
                            logging::error(
                                "admin",
                                "admin.auth=mtls requires admin.client_ca_path — admin API NOT spawned",
                            );
                            None
                        }
                    },
                    _ => Some(admin::AdminAuth::InternalIp),
                };
                // A configured write token that cannot be loaded must not silently
                // open writes to every peer that passes `auth`: no admin API at all.
                let write_token = match admin_cfg.write_token_env.as_deref() {
                    None => Ok(None),
                    Some(name) => match std::env::var(name) {
                        Ok(v) if v.len() >= 32 => Ok(Some(zeroize::Zeroizing::new(v.into_bytes()))),
                        Ok(v) if !v.is_empty() => Err(format!(
                            "{name} holds {} bytes; a write token needs at least 32",
                            v.len()
                        )),
                        _ => Err(format!("{name} is unset or empty")),
                    },
                };
                let auth_and_token = match write_token {
                    Err(e) => {
                        logging::error(
                            "admin",
                            &format!("admin.write_token_env: {e} — admin API NOT spawned"),
                        );
                        None
                    }
                    Ok(t) => auth.map(|a| (a, t)),
                };
                if matches!(auth_and_token, Some((_, None))) {
                    logging::warn(
                        "admin",
                        "admin.write_token_env is not set: the admin API answers reads, but \
                         config pushes, reloads and revocations are refused (403) until a \
                         write token is configured",
                    );
                }
                if let Some((auth, write_token)) = auth_and_token {
                    let ctx = std::sync::Arc::new(admin::AdminReloadCtx {
                        conn_limit_max: conn_ceiling,
                        change_notifier: Some(config_change_tx.clone()),
                        config_path: config_path.into(),
                        boot_tls_cert: Some(config.tls.cert_path.clone()),
                        boot_tls_key: Some(config.tls.key_path.clone()),
                        rate_limiter: admin::AdminRateLimiter::new(admin_cfg.rate_limit_rps),
                        write_token,
                        persist_push: admin_cfg.persist_push,
                        revocations_path: admin_cfg
                            .revocations_path
                            .as_deref()
                            .map(std::path::PathBuf::from),
                    });
                    admin::spawn_admin_listener(state.clone(), addr, ctx, auth);
                }
            }
            Err(e) => logging::error("admin", &format!("admin.listen invalid: {e}")),
        }
    }
    Ok(())
}

/// Spawn the ACME auto-renewal task, if `[tls.acme]` is configured.
pub(crate) fn spawn_acme_renewal(config: &config::ZionConfig, state: &AppState) {
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
}

/// Scavenge stale IPs out of the rate-limit map every 60 s.
pub(crate) fn spawn_rate_map_scavenger(
    state: &Arc<AppState>,
    super_shutdown_tx: &watch::Sender<bool>,
) {
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
    let state_for_scavenge = state.clone();
    // Subscribe to the process shutdown signal so this loop exits cleanly
    // on SIGINT/SIGTERM instead of being force-aborted mid-iteration when
    // the runtime is dropped (#151 follow-up / ZION-CONC-03). The work here
    // is idempotent stale-entry cleanup, so a lost iteration is harmless —
    // but a deterministic exit keeps shutdown ordering predictable and
    // matches the accept loops' shutdown idiom. The sibling maintenance
    // loops (health checker, ACME renewal, AIMP mesh) similarly tolerate an
    // abort: health probing is idempotent, ACME cert writes are atomic
    // (see src/atomic_file.rs), and the audit writer flushes per event.
    let mut scavenge_shutdown = super_shutdown_tx.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                res = scavenge_shutdown.changed() => {
                    if res.is_err() || *scavenge_shutdown.borrow() {
                        break; // shutting down (or sender dropped) — stop cleanly
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    // `.max(1)` guards scavenge_rate_map's `now / window`
                    // against a 0 window ever reaching the snapshot.
                    let window = state_for_scavenge.cfg().rate_limit_window.max(1);
                    let removed = security::scavenge_rate_map(
                        &state_for_scavenge.limiters.rate_map,
                        window,
                    );
                    if removed > 0 {
                        logging::info(
                            "rate_limit",
                            &format!(
                                "scavenged {} stale IPs ({} tracked)",
                                removed,
                                state_for_scavenge.limiters.rate_map.len()
                            ),
                        );
                    }
                }
            }
        }
    });
}

/// Spawn the upstream health checker, and warm the connection pool to each upstream.
pub(crate) fn spawn_upstream_health(state: &Arc<AppState>, health_map: health::HealthMap) {
    // 8. Spawn the upstream health checker. It reads the health map of the LIVE
    // config on every round, so upstreams added by a reload or an admin push are
    // probed too (it used to iterate the map captured at boot), and it runs even
    // when the boot config has no upstream yet.
    logging::info(
        "health",
        &format!("monitoring {} upstreams", health_map.len()),
    );
    tokio::spawn(health::run_prober(
        state.clone(),
        state.http_client.clone(),
        proxy::build_http_client(proxy::DEFAULT_CONNECT_TIMEOUT_MS, true),
    ));

    // 8b. Pre-warm upstream connection pool (first health check warms TLS + DNS)
    // This eliminates cold-start latency on the first real request.
    if !health_map.is_empty() {
        let client = state.http_client.clone();
        let hm = health_map.clone();
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            for url in hm.keys() {
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
}

#[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
/// Hand the HTTPS listener to the io_uring accept thread. The supervisor gets no HTTPS slot.
fn adopt_https_listener(
    _https_addr: SocketAddr,
    https_listener: tokio::net::TcpListener,
    state: &Arc<AppState>,
    super_shutdown_tx: &watch::Sender<bool>,
) -> Bound {
    // io_uring single-shot accept on Linux (dedicated thread, one SQE re-submitted per connection).
    // The uring task is bound to the listener's fd at spawn time and the
    // listener supervisor explicitly does NOT manage HTTPS rebind in this
    // build flavour — that limitation is documented in `listener.rs`.
    // Operators using io_uring keep the v0.1.7 behaviour for `listen_https`
    // (restart required for port changes).
    use std::os::unix::io::AsRawFd;
    let fd = https_listener.as_raw_fd();
    eprintln!("  io_uring single-shot accept enabled");
    let uring_rx = crate::uring::spawn_uring_accept(fd, 4096);
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
    tokio::spawn(crate::accept::run_https_accept_loop(
        https_listener,
        state.clone(),
        uring_shutdown_rx,
        Some(uring_rx),
    ));
    None
}

#[cfg(not(all(target_os = "linux", feature = "io-uring-accept")))]
/// Leave the HTTPS listener to the listener supervisor, which can re-bind it on a reload.
fn adopt_https_listener(
    https_addr: SocketAddr,
    https_listener: tokio::net::TcpListener,
    _state: &Arc<AppState>,
    _super_shutdown_tx: &watch::Sender<bool>,
) -> Bound {
    Some((https_addr, https_listener))
}

/// Bind HTTP (port 80, optional) and HTTPS (port 443, primary).
pub(crate) fn bind_listeners(
    config: &config::ZionConfig,
    state: &Arc<AppState>,
    super_shutdown_tx: &watch::Sender<bool>,
) -> error::ZionResult<(Bound, Bound)> {
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

    let https_initial = adopt_https_listener(https_addr, https_listener, state, super_shutdown_tx);
    Ok((http_initial, https_initial))
}

#[cfg(feature = "http3")]
/// The HTTP/3 (QUIC) listener on UDP, independent of the supervisor. Its listen-port hot reload is out of scope.
pub(crate) fn spawn_quic(
    config: &config::ZionConfig,
    state: &Arc<AppState>,
    quic_reload_rx: QuicReload,
) -> error::ZionResult<()> {
    // QUIC listen-port hot-reload is out of scope for Phase 1.5.
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
    quic::spawn_quic_listener(quic_addr, &config.tls, state.clone(), Some(quic_reload_rx))
        .map_err(error::ZionError::Tls)?;
    Ok(())
}

/// Everything after the shutdown signal: retire the listeners, drain connections, flush the audit log.
pub(crate) async fn drain_and_exit(
    state: &Arc<AppState>,
    conn_ceiling: usize,
    supervisor_handle: tokio::task::JoinHandle<()>,
    super_shutdown_tx: &watch::Sender<bool>,
    audit_writer: Option<audit::AuditWriter>,
) {
    logging::info(
        "shutdown",
        "signal received, draining in-flight connections...",
    );
    // Tell the supervisor to retire all listeners. Its accept loops stop
    // on the next iteration; spawned per-connection tasks continue and
    // are drained by the semaphore wait below.
    let _ = super_shutdown_tx.send(true);
    // Open connections wind down now: idle keep-alive ones close, HTTP/2 ones get GOAWAY, and
    // a request in flight is finished first (see `drain`).
    drain::begin();
    // Best-effort wait on the supervisor to exit cleanly. Bounded by 2s
    // so a stuck reconcile does not block process shutdown.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), supervisor_handle).await;

    // Graceful drain: wait for in-flight connections to complete.
    // conn_limit has MAX permits; available = MAX - in_flight.
    // We try to acquire ALL permits (meaning all connections finished).
    let drain_timeout = std::time::Duration::from_secs(30);
    let max = conn_ceiling;
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

    // Flush the audit queue last, after connections stopped producing events. The
    // queue holds up to `queue_depth` events; dropping the runtime without this
    // would abort the writer before it drained them.
    if let Some(writer) = audit_writer {
        if writer.shutdown(std::time::Duration::from_secs(5)).await {
            logging::info("shutdown", "audit log drained and synced");
        } else {
            logging::warn(
                "shutdown",
                "audit writer did not finish within 5s — the newest audit events may be missing",
            );
        }
    }

    logging::info("shutdown", "ZION offline.");
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

#[cfg(test)]
mod internal_gate_warning_tests {
    use super::*;

    fn server(https: &str, proxies: &[&str], nets: &[&str]) -> config::ServerConfig {
        let toml = format!(
            "listen_http=\"0.0.0.0:80\"\nlisten_https=\"{https}\"\ntrusted_proxies={proxies:?}\ninternal_networks={nets:?}\n"
        );
        toml::from_str(&toml).unwrap()
    }

    #[test]
    fn warns_only_when_routable_and_nothing_names_the_real_peers() {
        // ZION-AUTH-03: the risky shape is a reachable listener + "private address"
        // as the only proof of being internal.
        assert!(internal_gates_trust_any_private_peer(&server(
            "0.0.0.0:443",
            &[],
            &[]
        )));
        assert!(internal_gates_trust_any_private_peer(&server(
            "10.0.0.5:443",
            &[],
            &[]
        )));
        // loopback-only listener: nobody remote can reach it
        assert!(!internal_gates_trust_any_private_peer(&server(
            "127.0.0.1:443",
            &[],
            &[]
        )));
        // trusted_proxies lets Zion see the real client; an allowlist names the peers
        assert!(!internal_gates_trust_any_private_peer(&server(
            "0.0.0.0:443",
            &["10.0.0.0/8"],
            &[]
        )));
        assert!(!internal_gates_trust_any_private_peer(&server(
            "0.0.0.0:443",
            &[],
            &["10.20.0.0/24"]
        )));
    }
}
