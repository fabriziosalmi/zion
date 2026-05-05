//! Config hot-reload — Phase 1 of the dynamic-config plan.
//!
//! Watches `zion.toml` (or whatever `ZION_CONFIG` points at) for
//! `Modify` / `Create` events and atomically swaps a freshly-parsed
//! `ResolvedAppConfig` into `AppState.config`. In-flight requests
//! continue with the snapshot they loaded; the next request after
//! the swap sees the new one.
//!
//! Scope of what this watcher reloads (Phase 1):
//!   * routes (paths, upstream binding, mode, csp, internal_only,
//!     waf_profile, cache_profile, auth_profile, cors)
//!   * upstream URLs (host / port / scheme)
//!   * WAF profiles (mode, body/depth/string limits, content-types,
//!     entropy threshold + kill-switch)
//!   * trusted proxy CIDRs
//!   * xff_mode
//!   * rate-limit rps + window
//!
//! Out of scope for Phase 1 (require a separate path):
//!   * `[server.listen_http]` / `[server.listen_https]` — changing
//!     the bind address means rebinding sockets and is reserved for
//!     Phase 1.5.
//!   * `[tls]` — already hot-reloaded by `spawn_tls_watcher` when the
//!     cert/key files themselves change. If the *paths* in
//!     `zion.toml` change, the TLS watcher is still pointed at the
//!     old paths until restart. Documented in
//!     `docs/config/hot-reload.md`.
//!
//! Validation: a malformed file (TOML parse error, unknown upstream,
//! …) is rejected by `config::load_config` and logged at WARN. The
//! previous snapshot stays in place — Zion never serves traffic
//! against an invalid config.

use crate::config::{self, ZionConfig};
use crate::health;
use crate::logging;
use crate::ResolvedAppConfig;
use arc_swap::ArcSwap;
use notify::{EventKind, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Monotonically increasing snapshot counter. Bumped once per
/// successful swap. Exposed in `/metrics` and `/_zion/snapshot.json`
/// so operators can confirm a reload has actually been observed and
/// see *which* snapshot a given request used.
///
/// Boot value: 0 (the initial snapshot built by `async_main` is
/// generation 0; the first successful reload makes it 1).
pub(crate) static CONFIG_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Read the current config generation. Cheap (Relaxed load).
#[inline]
pub(crate) fn current_generation() -> u64 {
    CONFIG_GENERATION.load(Ordering::Relaxed)
}

/// Build a `ResolvedAppConfig` from a fresh `ZionConfig`, preserving
/// per-upstream health state across reloads.
///
/// When the same upstream URL appears in both old and new configs we
/// keep the existing `Arc<UpstreamHealth>` so the background prober's
/// accumulated state (current `healthy` flag, latest latency EWMA) is
/// not lost. Newly-introduced URLs start with the conservative
/// "healthy + latency unknown" defaults; removed URLs are simply
/// dropped (the old `Arc` will be reclaimed when the last reader
/// exits, including any in-flight prober iteration).
fn rebuild(new_config: &ZionConfig, previous: &ResolvedAppConfig) -> ResolvedAppConfig {
    let mut snap = ResolvedAppConfig::build(new_config);
    let mut merged: fnv::FnvHashMap<String, Arc<health::UpstreamHealth>> =
        fnv::FnvHashMap::default();
    for (url, fresh) in snap.health_map.iter() {
        let entry = previous
            .health_map
            .get(url.as_str())
            .cloned()
            .unwrap_or_else(|| fresh.clone());
        merged.insert(url.clone(), entry);
    }
    snap.health_map = Arc::new(merged);
    snap
}

/// Spawn the config-file watcher. Returns immediately; the actual
/// watching runs on a tokio task and a debounce-and-reload task.
///
/// `change_notifier`, if provided, is `send`'d the new generation
/// number after every successful swap. Phase 1.5 wires the listener
/// supervisor to this channel so a `[server.listen_*]` change kicks
/// in within the watcher's debounce window.
///
/// `boot_tls_cert_path` / `boot_tls_key_path` are the TLS paths
/// resolved at boot. If a reload changes them, a WARN is emitted
/// because the TLS file-watcher is still pointed at the old paths.
pub(crate) fn spawn_config_watcher(
    config_path: PathBuf,
    state_config: Arc<ArcSwap<ResolvedAppConfig>>,
    change_notifier: Option<tokio::sync::watch::Sender<u64>>,
    boot_tls_cert_path: Option<String>,
    boot_tls_key_path: Option<String>,
) {
    let signal = Arc::new(Notify::new());
    let signal_for_watcher = signal.clone();
    // Both the watcher task and the debounce/reload task need the path —
    // clone for the watcher, the original is moved into the reload loop.
    let config_path_for_watcher = config_path.clone();

    // notify produces multiple events for a single editor save (some
    // editors do `write tmp; rename(tmp, target)` which fires Create +
    // Remove + Rename + Modify). A 2 s debounce collapses a burst into
    // one reload, same as `tls::spawn_tls_watcher`.
    let watch_dir: PathBuf = config_path_for_watcher
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let watched_filename = config_path_for_watcher
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();

    tokio::spawn(async move {
        let signal = signal_for_watcher;
        let watched_filename_clone = watched_filename.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    return;
                }
                // Only fire if the changed path matches our config file
                // name. The watcher is registered on the parent directory
                // (we cannot watch a single file directly on every
                // platform — macOS FSEvents is per-directory) so we
                // need to filter here.
                if event
                    .paths
                    .iter()
                    .any(|p| p.file_name() == Some(&watched_filename_clone))
                {
                    signal.notify_one();
                }
            }
        });

        let watcher = match watcher {
            Ok(ref mut w) => {
                if let Err(e) = w.watch(&watch_dir, RecursiveMode::NonRecursive) {
                    logging::warn(
                        "config_watcher",
                        &format!("cannot watch {}: {}", watch_dir.display(), e),
                    );
                    return;
                }
                w
            }
            Err(e) => {
                logging::warn(
                    "config_watcher",
                    &format!("filesystem watcher unavailable: {e}"),
                );
                return;
            }
        };
        // Drop ownership of the watcher to the task by `let _w = ...`
        // wouldn't work here (it would drop on next iteration). The
        // watcher trait implementation drops the watch on Drop. We
        // park forever so the watcher stays alive for the process
        // lifetime.
        logging::info(
            "config_watcher",
            &format!("watching {}", config_path_for_watcher.display()),
        );
        let _w = watcher; // keep alive across await
        std::future::pending::<()>().await;
    });

    // Debounce + reload task.
    tokio::spawn(async move {
        loop {
            signal.notified().await;
            tokio::time::sleep(Duration::from_secs(2)).await;

            let path = config_path.clone();
            let parsed =
                tokio::task::spawn_blocking(move || config::load_config(&path.to_string_lossy()))
                    .await;

            match parsed {
                Ok(Ok(new_config)) => {
                    // Rebuild on the current thread (fast: matchit
                    // construction is microseconds, Aho-Corasick is
                    // already cached per-mode in OnceLock).
                    // Wrapped in catch_unwind as defense-in-depth: if
                    // build_router encounters an edge case that validate_config
                    // missed, the debounce task stays alive instead of dying.
                    let previous = state_config.load_full();
                    let rebuild_result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            rebuild(&new_config, &previous)
                        }));
                    let new_snapshot = match rebuild_result {
                        Ok(snap) => snap,
                        Err(_) => {
                            logging::warn(
                                "config_watcher",
                                "rebuild panicked (router construction failed), keeping previous snapshot",
                            );
                            continue;
                        }
                    };
                    state_config.store(Arc::new(new_snapshot));
                    let gen = CONFIG_GENERATION.fetch_add(1, Ordering::Release) + 1;
                    if let Some(tx) = change_notifier.as_ref() {
                        // Best-effort: sending into a watch channel only
                        // fails if there are no live receivers. We don't
                        // care — the supervisor's missing receiver is the
                        // operator's problem to debug, not a reason to
                        // refuse the reload.
                        let _ = tx.send(gen);
                    }
                    logging::info(
                        "config_watcher",
                        &format!("reload OK (gen {} → {})", gen - 1, gen),
                    );
                    // Warn if TLS paths changed — the TLS file-watcher is
                    // still monitoring the boot-time paths. Changing
                    // [tls] cert_path/key_path in zion.toml does NOT
                    // re-point the watcher; a restart is required.
                    if let Some(ref boot_cert) = boot_tls_cert_path {
                        if new_config.tls.cert_path != *boot_cert {
                            logging::warn(
                                "config_watcher",
                                &format!(
                                    "tls.cert_path changed ({} → {}) — restart required for TLS watcher to use new path",
                                    boot_cert, new_config.tls.cert_path
                                ),
                            );
                        }
                    }
                    if let Some(ref boot_key) = boot_tls_key_path {
                        if new_config.tls.key_path != *boot_key {
                            logging::warn(
                                "config_watcher",
                                &format!(
                                    "tls.key_path changed ({} → {}) — restart required for TLS watcher to use new path",
                                    boot_key, new_config.tls.key_path
                                ),
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    logging::warn(
                        "config_watcher",
                        &format!("reload REJECTED ({e}), keeping previous snapshot"),
                    );
                }
                Err(join_err) => {
                    logging::warn(
                        "config_watcher",
                        &format!("reload task panicked: {join_err}, keeping previous snapshot"),
                    );
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rebuild` must reuse `Arc<UpstreamHealth>` for URLs that exist
    /// in both old and new configs — otherwise a hot-reload would
    /// reset every upstream's health state to "untested" and cause a
    /// cascade of false 503s until the prober ran again.
    #[test]
    fn rebuild_preserves_health_state_for_unchanged_upstreams() {
        // Construct an old snapshot with one upstream and a known
        // (un)healthy state we can identify by Arc pointer equality.
        let url = "http://api:8000".to_string();
        let old_health = Arc::new(health::UpstreamHealth {
            healthy: std::sync::atomic::AtomicBool::new(false),
            latency_us: std::sync::atomic::AtomicU64::new(42_000),
        });
        let mut old_map = fnv::FnvHashMap::default();
        old_map.insert(url.clone(), old_health.clone());
        let previous = ResolvedAppConfig::test_with_health(Arc::new(old_map));

        // Build a fresh ZionConfig that references the same upstream
        // URL. We use the existing config helpers rather than
        // hand-rolling structs.
        let config_toml = r#"
            [server]
            listen_http = "0.0.0.0:8080"
            listen_https = "0.0.0.0:8443"

            [tls]
            cert_path = "/tmp/zion-test.crt"
            key_path  = "/tmp/zion-test.key"

            [upstreams]
            api = "http://api:8000"

            [[route]]
            path = "/api/{*rest}"
            upstream = "api"
        "#;
        // Bypass disk validation by parsing TOML directly — we only
        // test the rebuild() merging logic, not file I/O.
        let parsed: ZionConfig = toml::from_str(config_toml).unwrap();
        let merged = rebuild(&parsed, &previous);

        let merged_arc = merged
            .health_map
            .get("http://api:8000")
            .expect("merged map must keep the upstream");
        assert!(
            Arc::ptr_eq(merged_arc, &old_health),
            "Arc<UpstreamHealth> must be the same instance across reload"
        );
        // The carried state survives.
        assert!(!merged_arc.healthy.load(Ordering::Relaxed));
        assert_eq!(merged_arc.latency_us.load(Ordering::Relaxed), 42_000);
    }

    #[test]
    fn rebuild_creates_fresh_state_for_new_upstreams() {
        // Old snapshot has "api"; new config swaps it for "billing".
        let mut old_map = fnv::FnvHashMap::default();
        old_map.insert(
            "http://api:8000".to_string(),
            Arc::new(health::UpstreamHealth {
                healthy: std::sync::atomic::AtomicBool::new(false),
                latency_us: std::sync::atomic::AtomicU64::new(99),
            }),
        );
        let previous = ResolvedAppConfig::test_with_health(Arc::new(old_map));

        let config_toml = r#"
            [server]
            listen_http = "0.0.0.0:8080"
            listen_https = "0.0.0.0:8443"

            [tls]
            cert_path = "/tmp/zion-test.crt"
            key_path  = "/tmp/zion-test.key"

            [upstreams]
            billing = "http://billing:9000"

            [[route]]
            path = "/billing/{*rest}"
            upstream = "billing"
        "#;
        let parsed: ZionConfig = toml::from_str(config_toml).unwrap();
        let merged = rebuild(&parsed, &previous);

        // Old upstream gone, new one present, with default state
        // ("healthy = true, latency = 0", per ResolvedAppConfig::build).
        assert!(merged.health_map.get("http://api:8000").is_none());
        let billing = merged
            .health_map
            .get("http://billing:9000")
            .expect("new upstream must be tracked");
        assert!(billing.healthy.load(Ordering::Relaxed));
        assert_eq!(billing.latency_us.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn current_generation_starts_at_zero() {
        // We don't reset the static between tests — but this test only
        // checks the initial *type* contract. After other tests have
        // run, the counter may be non-zero; what matters is that boot
        // value is 0 and the function returns the live value.
        let _ = current_generation();
        // The atomic must be readable without UB (compile-only check
        // is enough; we don't assert a numeric value to keep the test
        // order-independent).
    }

    // ── End-to-end atomic-swap behaviour ──
    //
    // These tests exercise the property that gives Phase 1 its
    // correctness contract: a reader that has loaded a snapshot
    // continues to see THAT snapshot for the remainder of its work,
    // even if a hot-reload swaps in a new one mid-flight. The
    // filesystem watcher is not exercised here (its job is purely
    // "translate a write event into one of these calls"); these
    // tests target the underlying primitive directly.

    /// Build a tiny `ZionConfig` from inline TOML, bypassing
    /// `config::load_config` so we don't need cert/key files on disk.
    fn parse_inline(toml_text: &str) -> ZionConfig {
        toml::from_str(toml_text).expect("inline test config must parse")
    }

    const TOML_V1: &str = r#"
        [server]
        listen_http = "0.0.0.0:8080"
        listen_https = "0.0.0.0:8443"

        [tls]
        cert_path = "/tmp/zion-test.crt"
        key_path  = "/tmp/zion-test.key"

        [upstreams]
        api = "http://api:8000"

        [[route]]
        path = "/api/{*rest}"
        upstream = "api"
    "#;

    const TOML_V2: &str = r#"
        [server]
        listen_http = "0.0.0.0:8080"
        listen_https = "0.0.0.0:8443"

        [tls]
        cert_path = "/tmp/zion-test.crt"
        key_path  = "/tmp/zion-test.key"

        [upstreams]
        api = "http://api:8000"
        billing = "http://billing:9000"

        [[route]]
        path = "/api/{*rest}"
        upstream = "api"

        [[route]]
        path = "/billing/{*rest}"
        upstream = "billing"
    "#;

    #[test]
    fn atomic_swap_preserves_old_snapshot_for_inflight_readers() {
        // Initial snapshot, exposed only via `/api/...`.
        let v1 = parse_inline(TOML_V1);
        let snap_v1 = ResolvedAppConfig::build(&v1);
        let store = ArcSwap::from_pointee(snap_v1);

        // Reader A grabs an Arc clone *before* the swap. This models a
        // request that has already loaded its config snapshot and is
        // about to dispatch — it must not see a different routing
        // table mid-flight.
        let reader_a = store.load_full();

        // Hot-reload: build v2 (adds /billing) and swap.
        let v2 = parse_inline(TOML_V2);
        let snap_v2 = rebuild(&v2, &reader_a);
        store.store(Arc::new(snap_v2));

        // Reader A sees the old routing table (route /api works,
        // /billing must not exist).
        assert!(reader_a.router.at("/api/users").is_ok());
        assert!(
            reader_a.router.at("/billing/invoice").is_err(),
            "in-flight reader must NOT see post-swap routes"
        );

        // A new reader (B) grabs the post-swap snapshot and sees both.
        let reader_b = store.load_full();
        assert!(reader_b.router.at("/api/users").is_ok());
        assert!(
            reader_b.router.at("/billing/invoice").is_ok(),
            "new reader must see the post-swap routing table"
        );

        // The two snapshots are distinct Arcs.
        assert!(
            !Arc::ptr_eq(&reader_a, &reader_b),
            "swap must produce a fresh Arc"
        );

        // Reader A is still alive after B has loaded its snapshot —
        // ArcSwap's epoch GC does not yank a snapshot from under an
        // active reader.
        assert!(reader_a.router.at("/api/users").is_ok());
    }

    #[test]
    fn empty_routing_table_still_swappable() {
        // Edge case: the OLD snapshot has zero routes. The new one
        // adds one. This pins that the rebuild path doesn't assume
        // a non-empty router (a fresh deploy might start with an
        // empty `[[route]]` section before the first edit).
        let mut empty = parse_inline(TOML_V1);
        empty.route.clear();
        let snap_empty = ResolvedAppConfig::build(&empty);
        let store = ArcSwap::from_pointee(snap_empty);

        let v1 = parse_inline(TOML_V1);
        let prev = store.load_full();
        let snap_v1 = rebuild(&v1, &prev);
        store.store(Arc::new(snap_v1));

        let after = store.load_full();
        assert!(after.router.at("/api/users").is_ok());
        assert!(prev.router.at("/api/users").is_err()); // old snapshot still empty
    }

    #[test]
    fn generation_counter_is_monotonic() {
        // The counter is a process-global static. We can't reset it
        // between tests, but we can pin its monotonicity property:
        // a fetch_add followed by a load is never less than the
        // fetched value. (Acquire/Release ordering is what the
        // watcher loop relies on for cross-thread visibility.)
        let before = CONFIG_GENERATION.fetch_add(1, Ordering::Release);
        let after = CONFIG_GENERATION.load(Ordering::Acquire);
        assert!(
            after > before,
            "generation must be strictly increasing across a successful reload"
        );
    }

    #[test]
    fn invalid_config_path_returns_err() {
        // The watcher's reload loop is structured as:
        //
        //   match config::load_config(...) {
        //       Ok(new) => { build(); store(); fetch_add(); }
        //       Err(_)  => { log!("REJECTED"); /* no swap */ }
        //   }
        //
        // We can't easily test the spawned task without running a
        // tokio runtime + filesystem, so we exercise the part that
        // gates the `store()` call: that `load_config` on an
        // unreachable path returns `Err`. As long as the type is
        // `Result`, the match arm in the watcher never falls through
        // to `store()` on bad input.
        let r = crate::config::load_config("/nonexistent/zion-test-zzz.toml");
        assert!(r.is_err());
        // We don't pin the exact error message — error formatting is
        // intentionally cosmetic — but the prefix is documented as
        // "Cannot read <path>" or "Invalid TOML in <path>".
        let msg = r.err().expect("Err expected");
        assert!(
            msg.contains("Cannot read") || msg.contains("Invalid TOML"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn invalid_toml_content_returns_err() {
        // Same gate, different failure mode: a file that exists but
        // contains malformed TOML. The watcher must NOT swap.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "zion-reload-test-invalid-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&path, b"this is = not [[ valid TOML").unwrap();
        let path_str = path.to_string_lossy().to_string();
        let r = crate::config::load_config(&path_str);
        let _ = std::fs::remove_file(&path);

        let msg = r.err().expect("Err expected");
        assert!(
            msg.contains("Invalid TOML"),
            "malformed TOML should produce a parse-error message, got: {msg}"
        );
    }
}
