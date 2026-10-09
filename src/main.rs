// SPDX-License-Identifier: Apache-2.0
//! Zion Edge Gateway — binary entry point.
//!
//! Boots the daemon: parses CLI flags (`zion`, `zion init`, `zion top`,
//! `zion doctor`, `zion bootstrap`, `zion auto`), loads `zion.toml`,
//! builds the resolved runtime config (`ResolvedAppConfig::try_build`),
//! starts the TLS acceptor + listeners (HTTP/HTTPS, optional QUIC),
//! spawns the cert-watcher, the config-reload watcher, the cache prober
//! and the audit writer, and finally hands every accepted connection to
//! [`dispatch::process_request`].
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

mod accept;
mod acme;
mod admin;
mod alloc_tuning;
mod atomic_file;
mod audit;
mod auth;
mod boot;
mod bootstrap;
mod breaker;
mod bulkhead;
mod cache;
mod cli;
mod config;
mod connlimit;
mod crl;
mod dns;
mod doctor;
mod drain;
mod error;
mod h2_guard;
mod health;
mod http_conditional;
mod import;
mod init;
mod listener;
mod logging;
mod logq;
mod metrics;
mod net;
mod numa;
mod observability;
mod pem;
mod pool;
mod proxy;
#[cfg(feature = "http3")]
mod quic;
mod reload;
mod reserved_headers;
mod routing;
mod security;
#[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
mod sovereign;
mod static_files;
mod suggest;
mod tarpit;
mod tls;
#[cfg(feature = "tui")]
mod tui;
mod uri_norm;
mod vary;
mod via;
// `uring.rs` compiles on every target — the io_uring-accept inner
// module (spawn_uring_accept, issue #51) is feature-gated *inside* the
// file, so on non-Linux or without `io-uring-accept` this module is
// simply empty.
mod uring;
mod waf;

// ── Experimental, feature-gated tracks ───────────────────────────────
// kTLS post-handshake offload (Linux >= 5.10 + CONFIG_TLS). EXPERIMENTAL:
// the offload path is wired but not yet exercised end-to-end over a socket
// in CI — treat as opt-in / not production-guaranteed.
#[cfg(all(target_os = "linux", feature = "ktls"))]
mod ktls;
// ML-augmented WAF scoring (ONNX via tract). EXPERIMENTAL: the inference
// path is wired but ships no model — enabling it is inert until you train
// and drop your own scorer.
#[cfg(feature = "ml-waf")]
mod waf_ml;
// TLS client fingerprinting (JA4). Phase 3a (#27): a pure JA4 library over the
// ClientHello; the allowlist gate, config, and peek hook land in later commits.
#[cfg(feature = "tls-fingerprint")]
mod tls_fp;
// AIMP-as-control-plane: serverless gossip of WAF rules and IP reputation
// via Merkle-CRDT. Top-level `aimp_cp` instead of nesting under `sovereign::`
// so it does not pull in geo-* features by accident.
#[cfg(feature = "sovereign-aimp")]
mod aimp_cp;

// ── Global allocator: mimalloc ──────────────────────────────────
// ~2-3x faster than system malloc on small allocations.
// Reduces allocator contention under high concurrency.
// Not under Miri (it cannot call mimalloc's C functions) and not under
// ThreadSanitizer (`--cfg zion_tsan`, set by `.github/workflows/concurrency.yml`):
// TSAN does not intercept mimalloc, so memory freed by one thread and reused by
// another looks like a data race. Both tools run against the system allocator.
#[cfg(not(any(miri, zion_tsan)))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::sync::Arc;

mod dispatch;
#[cfg(test)]
mod gate_order_tests;
mod http_util;
mod state;
#[cfg(test)]
mod swr_tests;
#[cfg(test)]
mod vary_tests;

// (Cache size limit lives in dispatch::MAX_CACHEABLE_BODY where it is
//  actually consumed by the static-cache pipeline.)

// Security headers, rate limiter constants, and validators are in security.rs.

fn main() {
    // Before anything allocates much: how mimalloc commits its arena (#590).
    alloc_tuning::tune();
    // Map a structured boot failure to its conventional exit code so process
    // supervisors (systemd Restart=, k8s restartPolicy) can branch: a config
    // error (2) must NOT trigger a restart loop, a bind error (4) should. The
    // default `fn main() -> Result` termination collapses every error to exit
    // 1 — hence this explicit boundary. The `kind=` prefix gives log scrapers
    // a stable field without parsing the message.
    let result = run();
    // Whatever was logged last must reach stderr before the process ends.
    logq::flush(std::time::Duration::from_secs(2));
    if let Err(e) = result {
        eprintln!("zion: fatal [{}] {}", e.kind(), e);
        std::process::exit(e.to_exit_code());
    }
}

fn run() -> error::ZionResult<()> {
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
        cli::Command::Usage { message, exit } => {
            eprintln!("{message}\nRun `zion --help` for the flags each subcommand takes.");
            std::process::exit(exit);
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
        cli::Command::Audit(args) => {
            std::process::exit(audit::run_cli(&args));
        }
        cli::Command::Import(opts) => {
            std::process::exit(import::run(opts));
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
        // Poll the global queue on every scheduler tick. A worker's local run queue holds 256
        // tasks; when more are runnable (more than ~256 busy connections on one worker) the
        // overflow goes to the global queue, which the default (tuned, ~31+ ticks) polls far
        // less often than the local one. The connections that landed there were served at a
        // fraction of the rate of the others: at 1024 connections the median request took
        // 9.5 ms and the 90th percentile 157 ms, with the same total throughput (nginx: 34 and
        // 35 ms). Polling it every tick serves both queues at the same rate; measured, the
        // 90th percentile at 1024 connections fell to 29 ms and throughput rose 8 %.
        .global_queue_interval(1)
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

    let (config_path, config) = boot::load_config()?;
    let (tls_acceptor_store, _quic_reload_rx) = boot::load_tls(&config)?;
    let (resolved, conn_ceiling) = boot::resolve_config(&config, platform)?;
    // The background tasks below (health prober, pool pre-warm) are spawned before the
    // snapshot moves into `AppState`, and need the upstream URL -> health map.
    let health_map = resolved.health_map.clone();

    // The audit writer is a tokio task spawned now; its handle clones into AppState.
    // A missing/short HMAC key or missing path with `[audit] enabled = true` is a boot error,
    // not a silent downgrade: the operator asked for a tamper-evident trail. `audit_writer`
    // is kept to drain the queue on shutdown.
    let (audit_handle, audit_writer) =
        audit::spawn_writer(&config.audit).map_err(error::ZionError::Config)?;
    let compiled_redact = Arc::new(config.redact.compile());
    #[cfg(feature = "sovereign-aimp")]
    let aimp_cp_handle = boot::start_aimp_control_plane(&config).await;

    let state = boot::build_state(
        resolved,
        tls_acceptor_store,
        conn_ceiling,
        audit_handle,
        compiled_redact,
        #[cfg(feature = "sovereign-aimp")]
        aimp_cp_handle,
    );

    // `config_change_*` is bumped by the config watcher after every successful swap; the
    // listener supervisor uses it to know when to reconcile bind addresses. `super_shutdown_*`
    // is flipped to `true` on SIGINT/SIGTERM and tells the supervisor to retire all listeners.
    let (config_change_tx, config_change_rx) = tokio::sync::watch::channel(0u64);
    let (super_shutdown_tx, super_shutdown_rx) = tokio::sync::watch::channel(false);

    // Watch `zion.toml` for changes; a valid one is atomic-swapped into `state.config`, an
    // invalid one is rejected with a WARN and the previous snapshot stays. `[tls]` paths are
    // not re-applied through this watcher: the TLS watcher covers cert/key file changes.
    reload::spawn_config_watcher(
        config_path.clone().into(),
        state.config.clone(),
        conn_ceiling,
        // Cloned: the admin API shares the SAME change channel, so an admin push notifies the
        // listener supervisor exactly like a file edit.
        Some(config_change_tx.clone()),
        Some(config.tls.cert_path.clone()),
        Some(config.tls.key_path.clone()),
    );

    boot::spawn_admin_api(
        &config,
        &state,
        conn_ceiling,
        &config_path,
        &config_change_tx,
    )?;
    boot::spawn_acme_renewal(&config, &state);
    boot::spawn_rate_map_scavenger(&state, &super_shutdown_tx);
    boot::spawn_upstream_health(&state, health_map);

    let (http_initial, https_initial) = boot::bind_listeners(&config, &state, &super_shutdown_tx)?;
    #[cfg(feature = "http3")]
    boot::spawn_quic(&config, &state, _quic_reload_rx)?;

    bootstrap::print_ready_banner(&config.server.listen_http, &config.server.listen_https);

    // The supervisor owns the HTTP/HTTPS accept loops and reconciles them when `state.config`
    // is swapped for a snapshot whose `listen_*` differs. On io_uring it has no HTTPS slot: it
    // logs a WARN and refuses to rebind HTTPS.
    let supervisor = listener::ListenerSupervisor::new(state.clone(), http_initial, https_initial);
    let supervisor_handle =
        supervisor.spawn_reconciler(state.config.clone(), config_change_rx, super_shutdown_rx);

    shutdown_signal().await;
    boot::drain_and_exit(
        &state,
        conn_ceiling,
        supervisor_handle,
        &super_shutdown_tx,
        audit_writer,
    )
    .await;
    Ok(())
}

// Network socket helpers (bind_with_reuseport, tune_accepted) are in net.rs.

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
