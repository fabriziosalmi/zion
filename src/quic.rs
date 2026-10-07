// SPDX-License-Identifier: Apache-2.0
//! Zion HTTP/3 (QUIC) listener — feature-gated via `--features http3`.
//!
//! Architecture: runs alongside the TCP TLS listener on the same port (UDP :443).
//! Clients discover HTTP/3 via the `Alt-Svc: h3=":443"; ma=86400` header
//! injected on all HTTP/1.1 and H2 responses.
//!
//! Security: shares the same security pipeline as the TCP path (URI check,
//! method whitelist, rate limit, WAF, security headers).
//!
//! The module-level `#![cfg(feature = "http3")]` was removed in v0.1.5 — the
//! caller already gates the module declaration with `#[cfg(feature = "http3")]
//! mod quic;` in main.rs, so the inner attribute was redundant and triggered
//! `clippy::duplicated_attributes`.

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::TlsConfig;
use crate::metrics;

/// Pre-built Alt-Svc header value for HTTP/3 advertisement.
pub static ALT_SVC_H3: hyper::header::HeaderValue =
    hyper::header::HeaderValue::from_static("h3=\":443\"; ma=86400");

/// Build a quinn ServerConfig from Zion's TLS config.
/// QUIC mandates TLS 1.3 — we reuse the same cert/key as the TCP listener.
///
/// Returns a `String` error on every failure mode (file open, PEM parse,
/// rustls build, quinn config conversion) so the caller can surface a
/// `ZionError::Tls` to the operator instead of aborting the daemon.
pub fn build_quinn_server_config(tls: &TlsConfig) -> Result<quinn::ServerConfig, String> {
    let cert_pem =
        std::fs::read(&tls.cert_path).map_err(|e| format!("QUIC cert {}: {e}", tls.cert_path))?;
    let key_pem =
        std::fs::read(&tls.key_path).map_err(|e| format!("QUIC key {}: {e}", tls.key_path))?;

    let certs = crate::pem::certs(&cert_pem).map_err(|e| format!("parse QUIC cert PEM: {e}"))?;

    let key = crate::pem::private_key(&key_pem)
        .map_err(|e| format!("parse QUIC key PEM: {e}"))?
        .ok_or_else(|| "no private key in PEM".to_string())?;

    let mut tls_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("build QUIC TLS config: {e}"))?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| format!("create QUIC server config: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    // Transport config tuning
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(64u32.into());
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

pub fn quinn_server_config_from_rustls(
    arc_config: Arc<rustls::ServerConfig>,
) -> Result<quinn::ServerConfig, String> {
    let mut cloned = (*arc_config).clone();
    cloned.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(cloned)
        .map_err(|e| format!("convert rustls config to QUIC config: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(64u32.into());
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

/// Spawn the QUIC listener on the given address.
/// Runs in a background tokio task, accepting connections forever.
/// Returns a `String` error on configuration / bind failures so the caller
/// can surface a `ZionError::{Tls,Listener}` instead of aborting the daemon.
pub fn spawn_quic_listener(
    addr: SocketAddr,
    tls: &TlsConfig,
    state: Arc<crate::state::AppState>,
    reload_rx: Option<tokio::sync::watch::Receiver<Option<Arc<rustls::ServerConfig>>>>,
) -> Result<(), String> {
    let server_config = build_quinn_server_config(tls)?;

    let endpoint = quinn::Endpoint::server(server_config, addr)
        .map_err(|e| format!("bind QUIC on {addr}: {e}"))?;

    eprintln!("  listening HTTP/3 (QUIC) on {addr}");

    if let Some(mut rx) = reload_rx {
        let endpoint_clone = endpoint.clone();
        tokio::spawn(async move {
            while rx.changed().await.is_ok() {
                if let Some(arc_config) = rx.borrow().clone() {
                    match quinn_server_config_from_rustls(arc_config) {
                        Ok(new_quinn_cfg) => {
                            endpoint_clone.set_server_config(Some(new_quinn_cfg));
                            eprintln!("  h3: certificates hot-reloaded.");
                        }
                        Err(e) => {
                            // Non-fatal — keep the previous config running.
                            crate::logging::warn(
                                "quic",
                                &format!("hot-reload rejected: {e}; keeping previous config"),
                            );
                        }
                    }
                }
            }
        });
    }

    tokio::spawn(async move {
        // On shutdown stop accepting new QUIC connections, like the TCP listeners.
        let mut drain_rx = crate::drain::subscribe();
        loop {
            let incoming = tokio::select! {
                i = endpoint.accept() => match i {
                    Some(i) => i,
                    None => break,
                },
                _ = async { let _ = drain_rx.wait_for(|draining| *draining).await; } => break,
            };
            let state = state.clone();

            tokio::spawn(async move {
                // Enforce connection limit (same semaphore as TCP path)
                let _permit = match state.conn_limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // At capacity — drop QUIC connection immediately
                        return;
                    }
                };

                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("  quic accept error: {e}");
                        return;
                    }
                };

                let remote_addr = conn.remote_address();
                metrics::METRICS
                    .connections_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _conn_guard = metrics::ConnectionGuard::new();

                // Kept to close the connection ourselves once drained: after a GOAWAY an
                // idle client never closes it, so h3 would wait for the idle timeout.
                let quic = conn.clone();
                let h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await;

                let mut h3_conn = match h3_conn {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("  h3 connection error: {e}");
                        return;
                    }
                };

                // On shutdown send GOAWAY (accept nothing new), let the requests in
                // flight finish, then close: the same drain HTTP/1 and HTTP/2 get. The
                // requests are tracked, so this task (and the connection slot it holds)
                // also outlives them when the client closes first.
                let mut drain_rx = crate::drain::subscribe();
                let mut requests = tokio::task::JoinSet::new();
                loop {
                    let accepted = tokio::select! {
                        a = h3_conn.accept() => a,
                        _ = async { let _ = drain_rx.wait_for(|draining| *draining).await; } => {
                            let _ = h3_conn.shutdown(0).await;
                            break;
                        }
                        // reap finished requests so the set does not grow on a long connection
                        Some(_) = requests.join_next(), if !requests.is_empty() => continue,
                    };
                    match accepted {
                        Ok(Some(resolver)) => {
                            let state = state.clone();
                            requests.spawn(async move {
                                match resolver.resolve_request().await {
                                    Ok((req, stream)) => {
                                        if let Err(e) =
                                            handle_h3_request(req, stream, state, remote_addr).await
                                        {
                                            eprintln!("  h3 request error: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("  h3 resolve error: {e}");
                                    }
                                }
                            });
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("  h3 accept error: {e}");
                            break;
                        }
                    }
                }
                while requests.join_next().await.is_some() {}
                // Responses can still sit in the send buffer: closing now would discard
                // them. A client that got GOAWAY closes once it has read them; give it a
                // moment, then close (an idle one never would).
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(2), quic.closed()).await;
                quic.close(0u32.into(), b"shutting down");
            });
        }
    });

    Ok(())
}

/// Send an H3 error response.
///
/// Reserved for the QUIC error path; not currently called by the
/// `quic.rs` request loop, which lets hyper translate WAF/router denials
/// into HTTP responses on the H3 stream like any other status. Kept as a
/// documented helper because reaching for it again is the natural fix
/// the next time the H3 path needs to short-circuit before constructing
/// a `Response`.
#[allow(dead_code)]
async fn h3_error_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    status: hyper::StatusCode,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: h3::quic::BidiStream<Bytes>,
{
    // INVARIANT: a fresh `Response::builder()` configured only with a
    // valid `StatusCode` and a unit body never fails to build — `body()`
    // returns `Err` only when the builder accumulated a header parse
    // error, which we don't introduce here.
    let resp = hyper::Response::builder().status(status).body(()).unwrap();
    stream.send_response(resp).await?;
    stream.finish().await?;
    Ok(())
}

/// The HTTP/3 request as the shared pipeline sees it.
///
/// It keeps the client's method, URI with its authority, version and every header, minus
/// the transport attestations no client may set: this listener verifies no client
/// certificate and computes no JA4. The forwarding headers are the pipeline's job, from
/// the real peer address, as for HTTP/1 and HTTP/2.
pub(crate) fn bridge_request(
    req: hyper::Request<()>,
    body: crate::ZionBody,
) -> hyper::Request<crate::ZionBody> {
    let (mut parts, ()) = req.into_parts();
    crate::security::strip_transport_attestations(&mut parts.headers);
    hyper::Request::from_parts(parts, body)
}

/// Log an HTTP/3 request that failed inside zion, a few lines every ten seconds at most
/// (a peer can make this happen as often as it likes). Without it the only trace is a
/// `500` in the metrics.
fn log_h3_failure(remote: &SocketAddr, method: &str, path: &str, what: &str) {
    static LOG: crate::logging::Throttle = crate::logging::Throttle::new(5, 10);
    if LOG.allow() {
        crate::logging::warn(
            "http3",
            &format!("{what} remote={remote} method={method} path={path}"),
        );
    }
}

/// Handle a single HTTP/3 request through the Zion security pipeline.
///
/// Gates applied (same as handle_https in main.rs):
///   1. URI length check
///   2. Method whitelist
///   3. Rate limiting
///   4. Health endpoint interception (/healthz, /readyz)
///   5. Radix tree routing
///   6. Internal-only check
///   7. Upstream health check
///   8. WAF URI scan
///   9. Security headers on response
///  10. Metrics recording
async fn handle_h3_request<S>(
    req: hyper::Request<()>,
    stream: h3::server::RequestStream<S, Bytes>,
    state: Arc<crate::state::AppState>,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: h3::quic::BidiStream<Bytes>,
    <S as h3::quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
{
    // Bridge HTTP/3 QUIC connection directly into the universal pipeline
    let (mut send_stream, mut recv_stream) = stream.split();
    let (tx, rx) =
        tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(16);
    let stream_body =
        http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));

    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // Spawn task to sequentially copy HTTP/3 request payload chunks into the Request stream body
    let body_log = (remote_addr, method.clone(), path.clone());
    tokio::spawn(async move {
        loop {
            let mut buf = match recv_stream.recv_data().await {
                Ok(Some(buf)) => buf,
                Ok(None) => break,
                // The stream broke: the pipeline sees the body end where it did.
                Err(e) => {
                    log_h3_failure(
                        &body_log.0,
                        &body_log.1,
                        &body_log.2,
                        &format!("request body stream broke: {e}"),
                    );
                    break;
                }
            };
            use bytes::Buf;
            let rem = buf.remaining();
            let bytes = bytes::Buf::copy_to_bytes(&mut buf, rem);
            if tx.send(Ok(hyper::body::Frame::data(bytes))).await.is_err() {
                break;
            }
        }
    });

    let uni_req = bridge_request(req, stream_body.boxed());

    // Dispatch the bridged request through the single source of truth HTTP processing engine
    // (This automatically executes all Gates: WAF, CORS, Auth, Rate Limits, and Routes).
    let resp_result = crate::process_request(uni_req, state, remote_addr, false).await;

    // Transform upstream pipeline output to stream HTTP/3 responses back to the client natively
    let resp: hyper::Response<crate::ZionBody> = match resp_result {
        Ok(r) => r,
        Err(e) => {
            // Fail safe on generic HTTP internal pipeline errors
            log_h3_failure(
                &remote_addr,
                &method,
                &path,
                &format!("pipeline error: {e}"),
            );
            crate::metrics::METRICS.record_status(500);
            // INVARIANT: builder configured with a single static StatusCode and
            // a unit body never fails — same rationale as the helper above.
            let err_resp = hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(())
                .unwrap();
            send_stream.send_response(err_resp).await?;
            send_stream.finish().await?;
            return Ok(());
        }
    };

    let status = resp.status();
    let mut h3_resp_builder = hyper::Response::builder().status(status);

    for (name, value) in resp.headers() {
        let skip = matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        );
        if !skip {
            h3_resp_builder = h3_resp_builder.header(name, value);
        }
    }

    // INVARIANT: hop-by-hop headers were filtered above; remaining headers
    // came from a successfully-built `Response`, so `body(())` cannot fail.
    let h3_resp = h3_resp_builder.body(()).unwrap();
    send_stream.send_response(h3_resp).await?;

    use http_body_util::BodyExt;
    let mut body = resp.into_body();

    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    send_stream.send_data(data).await?;
                }
            }
            Some(Err(_)) => {
                send_stream.finish().await?;
                return Ok(());
            }
            None => break,
        }
    }

    send_stream.finish().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> crate::ZionBody {
        use http_body_util::BodyExt;
        http_body_util::Full::new(Bytes::new())
            .map_err(|n| match n {})
            .boxed()
    }

    #[test]
    fn the_bridged_request_keeps_every_client_header() {
        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://app.example/api?q=1")
            .version(hyper::Version::HTTP_3)
            .header("authorization", "Bearer t")
            .header("cookie", "sid=1")
            .header("content-type", "application/json")
            .header("accept-encoding", "gzip")
            .header("x-custom", "a")
            .header("x-custom", "b")
            .body(())
            .unwrap();
        let out = bridge_request(req, empty());
        assert_eq!(out.method(), "POST");
        assert_eq!(out.uri(), "https://app.example/api?q=1");
        assert_eq!(out.version(), hyper::Version::HTTP_3);
        let h = out.headers();
        assert_eq!(h["authorization"], "Bearer t");
        assert_eq!(h["cookie"], "sid=1");
        assert_eq!(h["content-type"], "application/json");
        assert_eq!(h["accept-encoding"], "gzip");
        assert_eq!(h.get_all("x-custom").iter().count(), 2);
        // forwarding headers are the pipeline's job, from the real peer
        assert!(!h.contains_key("x-forwarded-for") && !h.contains_key("x-forwarded-proto"));
    }

    #[test]
    fn the_bridged_request_drops_forged_transport_attestations() {
        let mut b = hyper::Request::builder().uri("https://app.example/");
        let transport =
            || crate::reserved_headers::reserved(crate::reserved_headers::Asserter::Transport);
        for name in transport() {
            b = b.header(name, "forged").header(name, "forged-again");
        }
        let out = bridge_request(b.body(()).unwrap(), empty());
        for name in transport() {
            assert!(!out.headers().contains_key(name), "{name} survived");
        }
    }

    #[test]
    fn alt_svc_header_value() {
        assert_eq!(ALT_SVC_H3.to_str().unwrap(), "h3=\":443\"; ma=86400");
    }

    #[test]
    fn alt_svc_is_valid_header() {
        let mut map = hyper::HeaderMap::new();
        map.insert("Alt-Svc", ALT_SVC_H3.clone());
        assert!(map.contains_key("Alt-Svc"));
    }
}
