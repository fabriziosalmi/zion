// SPDX-License-Identifier: Apache-2.0
//! Connection acceptance: the accept loops, the per-connection services, and the :80 handler.
//!
//! Everything here runs between a socket being accepted and a request reaching
//! [`crate::dispatch::process_request`]. `main.rs` only builds the listeners and spawns these
//! functions; the listener supervisor (`listener.rs`) re-spawns them when `[server.listen_*]`
//! changes.

use crate::dispatch::{self, process_request};
use crate::http_util::{empty_response, text_response, ZionBody, HEX_DIGITS};
use crate::state::AppState;
#[cfg(feature = "tls-fingerprint")]
use crate::tls_fp;
use crate::{
    acme, bootstrap, drain, h2_guard, logging, logq, metrics, net, proxy, security, uri_norm,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::net::SocketAddr;
use std::sync::Arc;

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
pub(crate) async fn run_http_accept_loop(
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
                            logq::line(&format!("  http accept error: {e}"));
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
        Err(_) => {
            metrics::METRICS
                .connections_rejected_global
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
    };
    let _ip_slot = match state
        .limiters
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
    net::set_keepalive(&stream, state.config.load().tcp_keepalive_secs);
    net::set_user_timeout(&stream, state.config.load().tcp_user_timeout_secs);

    // The plaintext listener speaks HTTP/2 to a client that opens with the preface, so the
    // control-frame bound (#475) applies here as on :443.
    let io = h2_guard::H2Guard::new(
        stream,
        h2_guard::Limits {
            control_per_sec: state.cfg().h2_control_frames_per_sec,
        },
    );
    let (h2_verdict, flood_log_state) = (io.verdict(), state.clone());
    let io = TokioIo::new(io);
    // Connection-level idle timeout — matches the HTTPS path (1h, generous
    // enough for keep-alive; header_read_timeout bounds the slowloris header
    // phase, per-request limits live in handle_http).
    let conn = builder.serve_connection(
        io,
        service_fn(move |req| {
            use http_body_util::BodyExt;
            let req_boxed = req.map(|b: hyper::body::Incoming| b.boxed());
            handle_http(req_boxed, state.clone(), addr)
        }),
    );
    tokio::pin!(conn);
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3600),
        drain::serve(conn.as_mut(), drain::subscribe(), |c| c.graceful_shutdown()),
    )
    .await;
    log_h2_flood(&h2_verdict, &flood_log_state, addr);
}

/// Run the HTTPS / TLS accept loop. On non-Linux or without the
/// `io-uring-accept` feature this is a plain `listener.accept()` loop;
/// with `io-uring-accept` the accepted-connection stream is consumed
/// from the kernel-batched receiver instead. The two paths are
/// cfg-gated to avoid pulling io_uring symbols on platforms that
/// don't have them.
#[cfg(not(all(target_os = "linux", feature = "io-uring-accept")))]
pub(crate) async fn run_https_accept_loop(
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
                            logq::line(&format!("  https accept error: {e}"));
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
pub(crate) async fn run_https_accept_loop(
    _listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut uring_rx: Option<tokio::sync::mpsc::Receiver<crate::uring::AcceptedConn>>,
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
                    Err(e) => logq::line(&format!("  io_uring accept: tokio from_std failed: {e}")),
                }
            }
        }
    }
}

/// Say that a connection was closed by the HTTP/2 control-frame bound (#475). The metric
/// counts every one; the line is throttled to about one a second, process-wide, so the
/// client that floods frames cannot flood the log by reconnecting.
fn log_h2_flood(verdict: &h2_guard::Verdict, state: &AppState, peer: SocketAddr) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST_LOG_MS: AtomicU64 = AtomicU64::new(0);
    let Some(flood) = verdict.get() else {
        return;
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if now_ms.saturating_sub(LAST_LOG_MS.load(Ordering::Relaxed)) < 1000 {
        return;
    }
    LAST_LOG_MS.store(now_ms, Ordering::Relaxed);
    logging::warn(
        "h2_flood",
        &format!(
            "{} from {}: connection closed (h2_control_frames_per_sec = {})",
            flood.as_str(),
            state.redact.ip_label(peer.ip()),
            state.cfg().h2_control_frames_per_sec
        ),
    );
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
            metrics::METRICS
                .connections_rejected_global
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            drop(tcp_stream);
            return;
        }
    };

    // Per-IP concurrent-connection cap (anti-DDoS, issue #150 lever). Read
    // the cap from the live config snapshot so a hot-reload retunes it.
    // `cap == 0` short-circuits inside `try_acquire` (zero overhead). A
    // rejected source is closed immediately, before the TLS handshake.
    let ip_slot = match state
        .limiters
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
        net::set_keepalive(&tcp_stream, state.config.load().tcp_keepalive_secs);
        net::set_user_timeout(&tcp_stream, state.config.load().tcp_user_timeout_secs);
        // JA4 fingerprint gate (#27): peek the ClientHello before the handshake,
        // compute JA4, count known/unknown. MSG_PEEK leaves the bytes in the
        // kernel buffer for rustls to re-read. In allowlist mode a rejected
        // fingerprint closes the connection HERE, before any handshake. No peek —
        // no syscall — when the feature is off or mode = off (runtime `None`).
        #[cfg(feature = "tls-fingerprint")]
        let tls_fp_identity: Option<std::sync::Arc<tls_fp::TlsFpIdentity>> = {
            let outcome = tls_fp::fingerprint_gate(&tcp_stream, &state).await;
            if outcome.decision == tls_fp::GateDecision::Reject {
                // Dropping tcp_stream closes the socket; the connection permit
                // and per-IP slot release when their guards drop at end of scope.
                return;
            }
            // Stash the computed identity (#27 commit 5): the JA4 exists only
            // pre-handshake, so it must ride the connection to become the
            // X-Client-TLS-JA4 / -Allowlisted upstream headers per request —
            // the same lifecycle as the mTLS client_cert_fingerprint below.
            outcome.identity.map(std::sync::Arc::new)
        };
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
                    logq::line(&format!(
                        "  tls handshake failed from {}: {e}",
                        state.redact.ip_label(remote_addr.ip())
                    ));
                }
                metrics::METRICS
                    .tls_handshake_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            Err(_) => {
                if tls_handshake_log_allowed() {
                    logq::line(&format!(
                        "  tls handshake timed out (10s) from {remote_addr}"
                    ));
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
        // HTTP/2 control-frame bound (#475): the guard reads the frame headers as they go by
        // and stops reading from a connection that floods.
        let h2_limits = h2_guard::Limits {
            control_per_sec: state.cfg().h2_control_frames_per_sec,
        };
        #[cfg(all(target_os = "linux", feature = "ktls"))]
        let io = match crate::ktls::try_upgrade(tls_stream).await {
            Ok(ktls_stream) => h2_guard::H2Guard::new(ktls_stream, h2_limits),
            Err(e) => {
                logq::line(&format!("  kTLS upgrade failed, closing connection: {e}"));
                return;
            }
        };
        #[cfg(not(all(target_os = "linux", feature = "ktls")))]
        let io = h2_guard::H2Guard::new(tls_stream, h2_limits);
        let (h2_verdict, flood_log_state) = (io.verdict(), state.clone());
        let io = TokioIo::new(io);
        // Connection-level idle timeout. 1h to cover long-lived HTTP/2
        // mux / WebSocket / SSE; per-request timeouts are in process_request.
        let conn = builder.serve_connection_with_upgrades(
            io,
            service_fn(move |mut req: Request<Incoming>| {
                let state = state.clone();
                let early_flag = early_flag.clone();
                let client_fp = client_fp.clone();
                #[cfg(feature = "tls-fingerprint")]
                let tls_fp_identity = tls_fp_identity.clone();
                async move {
                    // Fast-path: health probes bypass the full pipeline (~1us vs ~5us).
                    let path = req.uri().path();
                    if path == "/healthz" {
                        return Ok(text_response(StatusCode::OK, "ok"));
                    }
                    if path == "/readyz" {
                        return Ok(text_response(StatusCode::OK, "ready"));
                    }

                    // RFC 9112 §3.2: an HTTP/1.1 request without exactly one valid Host is a 400.
                    if http1_host_is_wrong(&req) {
                        return Ok(bad_request_and_close());
                    }
                    // RFC 9110 §7.6.1: headers named in `Connection` are not for the next hop.
                    // Before the attestations below, so nothing zion sets can be named away.
                    crate::http_util::strip_connection_listed(req.headers_mut());

                    // Consume early_data flag on first request.
                    let was_early = early_flag.swap(false, std::sync::atomic::Ordering::Relaxed);
                    // The client-cert fingerprint is Zion's attestation of what TLS verified:
                    // inbound values are dropped and the verified one (if any) is set.
                    security::attest_client_cert(
                        req.headers_mut(),
                        client_fp.as_ref().map(|fp| fp.as_str()),
                    );
                    // Same discipline for the JA4 identity headers (#27
                    // commit 5): strip any inbound forgery, re-inject the
                    // gate-computed values. Feature-off builds never
                    // compute an identity, so they strip only.
                    // (feature off: already stripped above, nothing to inject)
                    #[cfg(feature = "tls-fingerprint")]
                    tls_fp::apply_headers(&mut req, tls_fp_identity.as_deref());
                    use http_body_util::BodyExt;
                    let req_boxed = req.map(|b: hyper::body::Incoming| b.boxed());
                    process_request(req_boxed, state, remote_addr, was_early).await
                }
            }),
        );
        tokio::pin!(conn);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(3600),
            drain::serve(conn.as_mut(), drain::subscribe(), |c| c.graceful_shutdown()),
        )
        .await;
        log_h2_flood(&h2_verdict, &flood_log_state, remote_addr);
    });
}

/// Whether an HTTP/1.1 request breaks RFC 9112 §3.2 on `Host`: none, more than one, or a value
/// that is not a host. HTTP/1.0 may omit it and HTTP/2 and HTTP/3 carry the authority in the
/// request target, so only `Version::HTTP_11` is checked.
fn http1_host_is_wrong<B>(req: &Request<B>) -> bool {
    if req.version() != hyper::Version::HTTP_11 {
        return false;
    }
    let mut hosts = req.headers().get_all(hyper::header::HOST).iter();
    match (hosts.next(), hosts.next()) {
        (Some(only), None) => !only.to_str().is_ok_and(security::is_valid_host),
        _ => true,
    }
}

/// A 400 that also ends the connection: a client that sends a request the protocol forbids is not
/// one whose next request on the same connection is worth parsing.
fn bad_request_and_close() -> Response<ZionBody> {
    let mut resp = text_response(StatusCode::BAD_REQUEST, "bad request");
    resp.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    resp
}

#[cfg(test)]
mod host_tests {
    use super::http1_host_is_wrong;
    use hyper::{Request, Version};

    fn req(version: Version, hosts: &[&str]) -> Request<()> {
        let mut b = Request::builder().version(version).uri("/p");
        for h in hosts {
            b = b.header("host", *h);
        }
        b.body(()).unwrap()
    }

    #[test]
    fn an_http11_request_needs_exactly_one_valid_host() {
        assert!(!http1_host_is_wrong(&req(Version::HTTP_11, &["a.example"])));
        assert!(!http1_host_is_wrong(&req(
            Version::HTTP_11,
            &["a.example:8443"]
        )));
        assert!(!http1_host_is_wrong(&req(
            Version::HTTP_11,
            &["[::1]:8443"]
        )));
        assert!(http1_host_is_wrong(&req(Version::HTTP_11, &[])), "none");
        assert!(
            http1_host_is_wrong(&req(Version::HTTP_11, &["a.example", "b.example"])),
            "two"
        );
        assert!(
            http1_host_is_wrong(&req(Version::HTTP_11, &["a.example", "a.example"])),
            "two, even equal"
        );
        for bad in ["exa mple.com", "", "user@a.example", "a/b", "a\\b"] {
            assert!(
                http1_host_is_wrong(&req(Version::HTTP_11, &[bad])),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn http10_and_http2_may_have_no_host() {
        assert!(!http1_host_is_wrong(&req(Version::HTTP_10, &[])));
        assert!(!http1_host_is_wrong(&req(Version::HTTP_2, &[])));
        assert!(!http1_host_is_wrong(&req(Version::HTTP_3, &[])));
    }
}

/// Validate Host header to prevent header injection in redirects.
fn is_valid_host(host: &str) -> bool {
    security::is_valid_host(host)
}

/// The port the plain-HTTP listener is bound to, if any.
fn cfg_http_port(state: &AppState) -> Option<u16> {
    state.cfg().listen_http.map(|a| a.port())
}

/// The authority the `:80` redirect sends the client to, given the `Host` it used.
///
/// A `Host` that names our own HTTP port (`localhost:8080`) reached this listener directly,
/// so the HTTPS listener's port is what it must go to: keeping `:8080` sent the browser back
/// to the plaintext port over TLS, a redirect that could never work (`zion auto`, any
/// non-standard pair of ports). A `Host` without a port, or with a port that is not ours (a
/// port mapping in front), is left alone: there the public ports are not something zion knows.
fn https_authority(host: &str, http_port: Option<u16>, https_port: Option<u16>) -> String {
    // `name:port` or `[v6]:port`; a bare IPv6 literal has colons but no port.
    let split = match host.rfind(':') {
        Some(i) if !host[i..].contains(']') => Some((&host[..i], &host[i + 1..])),
        _ => None,
    };
    let (Some((name, port)), Some(http_port)) = (split, http_port) else {
        return host.to_string();
    };
    if port.parse::<u16>().ok() != Some(http_port) {
        return host.to_string();
    }
    match https_port {
        None | Some(443) => name.to_string(),
        Some(p) => format!("{name}:{p}"),
    }
}

/// HTTP (port 80) handler — ACME challenge proxy or 301 redirect to HTTPS.
pub(crate) async fn handle_http(
    mut req: Request<ZionBody>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Plaintext :80 never has a verified client certificate, so any inbound
    // X-Client-Cert-Fingerprint / -DN is forged. Strip both before the request
    // is logged or proxied, so a client cannot smuggle a fake mTLS identity.
    // Likewise for the JA4 identity headers — no TLS on :80, so any inbound
    // copy is forged.
    security::strip_transport_attestations(req.headers_mut());

    // Rate limit HTTP/80 to prevent DoS via redirect/ACME flood
    if !check_rate_limit(&state, remote_addr.ip()) {
        metrics::METRICS
            .rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(empty_response(StatusCode::TOO_MANY_REQUESTS));
    }

    // URI length cap: the same function the HTTPS pipeline's gate uses.
    if dispatch::uri_too_long(&req) {
        return Ok(empty_response(StatusCode::URI_TOO_LONG));
    }

    // Normalize the path before ANYTHING below decides from it (RFC 3986 §6.2.2): this
    // handler matches the snapshot / ACME paths and routes ACME fallbacks on its own,
    // outside the HTTPS pipeline, so `/.well-known/acme-challenge/../../x` must not be
    // treated as a challenge path and forwarded raw. Same rewrite as the pipeline's gate.
    if uri_norm::rewrite_request(&mut req).is_err() {
        return Ok(empty_response(StatusCode::BAD_REQUEST));
    }

    let path = req.uri().path();

    // Live JSON snapshot — exposed on the plain-HTTP listener too so that
    // `zion top` can connect from the same host without dragging in a TLS
    // client. Same internal-IP gate as the HTTPS handler.
    if path == "/_zion/snapshot.json" {
        let cfg = state.cfg();
        if !cfg.internal_networks.contains(&remote_addr.ip()) {
            return Ok(empty_response(StatusCode::FORBIDDEN));
        }
        let platform = bootstrap::detect();
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
        // Fallback: proxy to upstream (for external ACME clients like certbot).
        // Honor host routing here too so a host-bound route is reachable on :80.
        // Resolve inside a block so the borrow of `req` ends before it is moved.
        let cfg = state.cfg();
        let rule = {
            let host = if cfg.router.host_routing_active() {
                security::request_host(&req)
            } else {
                None
            };
            cfg.router.at(host.as_deref(), path).cloned()
        };
        // Only a route with nothing to bypass may take this shortcut; otherwise fall
        // through to the redirect (the HTTPS pipeline then applies auth/WAF).
        if let Some(rule) = rule.filter(|r| r.serves_acme_fallback()) {
            // This path skips process_request, so drop the identity headers the
            // pipeline would have scrubbed: upstreams trust X-Auth-* as verified.
            dispatch::scrub_reserved_identity_headers(req.headers_mut());
            if !cfg.trusted_proxies.is_trusted(&remote_addr.ip()) {
                security::scrub_client_override_headers(req.headers_mut());
            }
            if rule.preserve_host {
                req.extensions_mut().insert(proxy::PreserveHost);
            }
            if let Some(t) = rule.request_timeout() {
                req.extensions_mut().insert(t);
            }
            return proxy::proxy_pass(
                &state.client_for(rule.client_spec()),
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

    let authority = https_authority(
        host,
        cfg_http_port(&state),
        state.cfg().listen_https.map(|a| a.port()),
    );
    let redirect_uri = format!("https://{authority}{safe_path}");
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
        cfg.rate_limit_max_tracked_ips,
        &state.limiters.rate_map,
        &state.limiters.rate_sweep,
        ip,
    )
}

#[cfg(test)]
mod redirect_tests {
    use super::https_authority;

    #[test]
    fn the_redirect_goes_to_the_https_port_not_back_to_the_http_one() {
        // (Host, http port, https port) -> authority
        let cases: &[(&str, Option<u16>, Option<u16>, &str)] = &[
            // The client reached the HTTP listener on its own port: send it to the HTTPS one.
            ("localhost:8080", Some(8080), Some(8443), "localhost:8443"),
            ("app.example:8080", Some(8080), Some(443), "app.example"),
            ("[::1]:8080", Some(8080), Some(8443), "[::1]:8443"),
            ("127.0.0.1:8080", Some(8080), Some(8443), "127.0.0.1:8443"),
            // Standard ports: no port in the Host, none added.
            ("app.example", Some(80), Some(443), "app.example"),
            // A port mapping in front (Docker -p 80:8080 -p 443:8443): the Host has no port,
            // and the public HTTPS port is 443 whatever zion is bound to.
            ("app.example", Some(8080), Some(8443), "app.example"),
            // A port that is not ours: the public mapping is not something zion knows.
            (
                "app.example:8000",
                Some(8080),
                Some(8443),
                "app.example:8000",
            ),
            // A bare IPv6 literal has colons but no port.
            ("[::1]", Some(8080), Some(8443), "[::1]"),
            // No listener information: unchanged.
            ("localhost:8080", None, Some(8443), "localhost:8080"),
            ("localhost:8080", Some(8080), None, "localhost"),
        ];
        for (host, http, https, want) in cases {
            assert_eq!(
                https_authority(host, *http, *https),
                *want,
                "{host} {http:?} {https:?}"
            );
        }
    }
}
