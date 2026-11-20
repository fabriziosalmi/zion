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

use crate::metrics;

/// The largest decoded header section (QPACK) an HTTP/3 request may carry, the same 16 KiB as
/// HTTP/1.1 and HTTP/2 (`H2_MAX_HEADER_LIST_SIZE`).
const H3_MAX_FIELD_SECTION_SIZE: u64 = 16 * 1024;

/// Pre-built Alt-Svc header value for HTTP/3 advertisement.
pub static ALT_SVC_H3: hyper::header::HeaderValue =
    hyper::header::HeaderValue::from_static("h3=\":443\"; ma=86400");

/// The rustls config the QUIC listener runs: `cfg` with ALPN `h3` and no 0-RTT.
///
/// QUIC allows no `max_early_data_size` but 0 and `u32::MAX`, and the check happens per
/// connection: rustls' `quic::ServerConnection::new` refuses any other value and quinn-proto
/// unwraps that refusal. The certificate hot reload hands over the TCP listener's config,
/// which allows 16384 bytes of early data, so the first HTTP/3 handshake after a reload
/// panicked, and the release profile aborts on panic. 0 rather than `u32::MAX`: HTTP/3
/// requests reach the pipeline with `is_early_data = false`, so the 425 replay gate the TCP
/// path has would not see a 0-RTT request.
fn for_quic(mut cfg: rustls::ServerConfig) -> rustls::ServerConfig {
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    cfg.max_early_data_size = 0;
    cfg
}

/// The quinn config for the TCP listener's rustls config: at boot and after every reload, so
/// HTTP/3 has the TCP listener's certificates (SNI included), client authentication, CRL and
/// ticketer. QUIC itself requires TLS 1.3, which every `[tls] min_version` enables.
pub fn quinn_server_config_from_rustls(
    arc_config: Arc<rustls::ServerConfig>,
) -> Result<quinn::ServerConfig, String> {
    let cloned = for_quic((*arc_config).clone());
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
///
/// `tls` carries the TCP listener's rustls config: its current value is the one the listener
/// starts with, and every later value is a certificate reload. The boot config used to be
/// built apart, from the certificate and key files only, so HTTP/3 ignored `client_auth`,
/// the client CA, the CRL and the SNI certificates until the first reload.
///
/// Returns a `String` error on configuration / bind failures so the caller
/// can surface a `ZionError::{Tls,Listener}` instead of aborting the daemon.
pub fn spawn_quic_listener(
    addr: SocketAddr,
    state: Arc<crate::state::AppState>,
    mut tls: tokio::sync::watch::Receiver<Option<Arc<rustls::ServerConfig>>>,
) -> Result<(), String> {
    let initial = tls
        .borrow_and_update()
        .clone()
        .ok_or_else(|| "no TLS config for the QUIC listener".to_string())?;
    let server_config = quinn_server_config_from_rustls(initial)?;

    let endpoint = quinn::Endpoint::server(server_config, addr)
        .map_err(|e| format!("bind QUIC on {addr}: {e}"))?;

    eprintln!("  listening HTTP/3 (QUIC) on {addr}");

    let endpoint_clone = endpoint.clone();
    tokio::spawn(async move {
        while tls.changed().await.is_ok() {
            let Some(arc_config) = tls.borrow_and_update().clone() else {
                continue;
            };
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
    });

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

                let remote_addr = crate::security::canonical_peer(conn.remote_address());
                // The client certificate the handshake verified (`[tls] client_auth`), attested
                // on every request of the connection as the TCP listener does.
                let client_fp: Option<Arc<str>> = conn
                    .peer_identity()
                    .and_then(|id| {
                        id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                            .ok()
                    })
                    .and_then(|certs| {
                        certs
                            .first()
                            .map(|c| crate::security::client_cert_fingerprint(c.as_ref()).into())
                    });
                metrics::METRICS
                    .connections_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _conn_guard = metrics::ConnectionGuard::new();

                // Kept to close the connection ourselves once drained: after a GOAWAY an
                // idle client never closes it, so h3 would wait for the idle timeout.
                let quic = conn.clone();
                // Header sections are bounded like HTTP/1.1 (16 KiB buffer) and HTTP/2 (16 KiB
                // header list): h3's default is no bound (VarInt::MAX), so a client could make zion
                // decode and hold a header block of any size. Advertised in SETTINGS, and a request
                // over it gets h3's own 431.
                let h3_conn = h3::server::builder()
                    .max_field_section_size(H3_MAX_FIELD_SECTION_SIZE)
                    .build(h3_quinn::Connection::new(conn))
                    .await;

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
                            let client_fp = client_fp.clone();
                            requests.spawn(async move {
                                match resolver.resolve_request().await {
                                    Ok((req, stream)) => {
                                        if let Err(e) = handle_h3_request(
                                            req,
                                            stream,
                                            state,
                                            remote_addr,
                                            client_fp,
                                        )
                                        .await
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
/// For a request refused before it is bridged into the pipeline (a `Content-Length` that is
/// not one valid length); the pipeline's own denials (WAF, router) come back as a `Response`
/// and are sent like any other status.
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
/// the transport attestations no client may set; `X-Client-Cert-Fingerprint` is then set
/// from the certificate the handshake verified, if any (`client_fp`). This listener
/// computes no JA4. The forwarding headers are the pipeline's job, from the real peer
/// address, as for HTTP/1 and HTTP/2.
pub(crate) fn bridge_request(
    req: hyper::Request<()>,
    body: crate::http_util::ReqBody,
    client_fp: Option<&str>,
) -> hyper::Request<crate::http_util::ReqBody> {
    let (mut parts, ()) = req.into_parts();
    crate::security::attest_client_cert(&mut parts.headers, client_fp);
    hyper::Request::from_parts(parts, body)
}

/// An HTTP/3 request body whose DATA frames do not add up to the `Content-Length` its headers
/// declared: RFC 9114 §4.1.2 makes the request malformed, and an intermediary must not forward
/// it. h3 does not check the length, so the bridge does.
#[derive(Debug)]
struct BodyLengthMismatch {
    declared: u64,
    /// What had arrived when the mismatch was seen: all of it at the end of the stream, or the
    /// first count past `declared`.
    received: u64,
}

impl std::fmt::Display for BodyLengthMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.received > self.declared {
            write!(
                f,
                "request body longer than its Content-Length of {} bytes ({} or more arrived)",
                self.declared, self.received
            )
        } else {
            write!(
                f,
                "request body ended at {} of the {} bytes its Content-Length declared",
                self.received, self.declared
            )
        }
    }
}

impl std::error::Error for BodyLengthMismatch {}

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
    mut stream: h3::server::RequestStream<S, Bytes>,
    state: Arc<crate::state::AppState>,
    remote_addr: SocketAddr,
    client_fp: Option<Arc<str>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: h3::quic::BidiStream<Bytes>,
    <S as h3::quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
{
    // RFC 9114 §4.1.2: a request whose `Content-Length` is not one valid length is malformed,
    // and h3 does not look at the header. Forwarded as it was, its lines reached the upstream
    // whatever the body turned out to be.
    let Ok(declared) = crate::http_util::content_length(req.headers()) else {
        log_h3_failure(
            &remote_addr,
            req.method().as_str(),
            req.uri().path(),
            "request refused: its Content-Length is not one valid length",
        );
        crate::metrics::METRICS.record_status(400);
        return h3_error_response(&mut stream, hyper::StatusCode::BAD_REQUEST).await;
    };

    // Bridge HTTP/3 QUIC connection directly into the universal pipeline
    let (mut send_stream, mut recv_stream) = stream.split();
    let (tx, rx) = tokio::sync::mpsc::channel::<
        Result<hyper::body::Frame<Bytes>, crate::http_util::BoxError>,
    >(16);
    let stream_body =
        http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));

    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // Spawn task to sequentially copy HTTP/3 request payload chunks into the Request stream body.
    // A declared `Content-Length` holds the body to it, as h2 holds an HTTP/2 one: the body ends
    // with a `BodyLengthMismatch` at a FIN short of the length, or instead of the DATA that
    // would go past it, so whatever reads it (the WAF, a buffer, the upstream request) sees a
    // broken body and never a whole one of another length.
    let body_log = (remote_addr, method.clone(), path.clone());
    tokio::spawn(async move {
        let mut received: u64 = 0;
        loop {
            let mut buf = match recv_stream.recv_data().await {
                Ok(Some(buf)) => buf,
                Ok(None) => {
                    if let Some(declared) = declared.filter(|&d| d != received) {
                        let e = BodyLengthMismatch { declared, received };
                        log_h3_failure(&body_log.0, &body_log.1, &body_log.2, &e.to_string());
                        let _ = tx.send(Err(Box::new(e))).await;
                    }
                    break;
                }
                // The stream broke: the body ends with the error, so whatever reads it (the
                // WAF, a buffer, the upstream request) sees a broken body. Ending it cleanly
                // would hand on what had arrived as the whole body.
                Err(e) => {
                    log_h3_failure(
                        &body_log.0,
                        &body_log.1,
                        &body_log.2,
                        &format!("request body stream broke: {e}"),
                    );
                    let _ = tx.send(Err(Box::new(e))).await;
                    break;
                }
            };
            use bytes::Buf;
            let rem = buf.remaining();
            received = received.saturating_add(rem as u64);
            if let Some(declared) = declared.filter(|&d| received > d) {
                let e = BodyLengthMismatch { declared, received };
                log_h3_failure(&body_log.0, &body_log.1, &body_log.2, &e.to_string());
                recv_stream.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
                let _ = tx.send(Err(Box::new(e))).await;
                break;
            }
            let bytes = bytes::Buf::copy_to_bytes(&mut buf, rem);
            if tx.send(Ok(hyper::body::Frame::data(bytes))).await.is_err() {
                break;
            }
        }
    });

    let uni_req = bridge_request(req, stream_body.boxed(), client_fp.as_deref());

    // Dispatch the bridged request through the single source of truth HTTP processing engine
    // (This automatically executes all Gates: WAF, CORS, Auth, Rate Limits, and Routes).
    let resp_result = crate::dispatch::process_request(uni_req, state, remote_addr, false).await;

    // Transform upstream pipeline output to stream HTTP/3 responses back to the client natively
    let resp: hyper::Response<crate::http_util::ZionBody> = match resp_result {
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

    fn empty() -> crate::http_util::ReqBody {
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
        let out = bridge_request(req, empty(), None);
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
        let out = bridge_request(b.body(()).unwrap(), empty(), None);
        for name in transport() {
            assert!(!out.headers().contains_key(name), "{name} survived");
        }
    }

    #[test]
    fn the_bridged_request_carries_the_verified_client_certificate_only() {
        let forged = || {
            hyper::Request::builder()
                .uri("https://app.example/")
                .header("x-client-cert-fingerprint", "sha256:forged")
                .body(())
                .unwrap()
        };
        let fp = crate::security::client_cert_fingerprint(b"a certificate");
        let out = bridge_request(forged(), empty(), Some(&fp));
        let got: Vec<_> = out
            .headers()
            .get_all("x-client-cert-fingerprint")
            .iter()
            .collect();
        assert_eq!(got, [fp.as_str()], "only the verified one");
        assert!(fp.starts_with("sha256:") && fp.len() == 7 + 64);
        let out = bridge_request(forged(), empty(), None);
        assert!(!out.headers().contains_key("x-client-cert-fingerprint"));
    }

    #[test]
    fn the_quic_tls_config_takes_no_early_data_whatever_the_tcp_one_allows() {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tcp = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        // What tls::load_tls_config sets for the TCP listener (0-RTT behind the 425 gate).
        tcp.max_early_data_size = 16384;
        let session = |cfg: rustls::ServerConfig| {
            rustls::quic::ServerConnection::new(Arc::new(cfg), rustls::quic::Version::V1, vec![])
                .map(drop)
        };
        // rustls refuses a QUIC connection on it, and quinn-proto unwraps that refusal.
        assert!(session(tcp.clone()).is_err());
        let quic = for_quic(tcp);
        assert_eq!(quic.max_early_data_size, 0);
        assert_eq!(quic.alpn_protocols, vec![b"h3".to_vec()]);
        assert!(session(quic).is_ok());
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
