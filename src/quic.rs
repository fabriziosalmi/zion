//! Zion HTTP/3 (QUIC) listener — feature-gated via `--features http3`.
//!
//! Architecture: runs alongside the TCP TLS listener on the same port (UDP :443).
//! Clients discover HTTP/3 via the `Alt-Svc: h3=":443"; ma=86400` header
//! injected on all HTTP/1.1 and H2 responses.
//!
//! Security: shares the same security pipeline as the TCP path (URI check,
//! method whitelist, rate limit, WAF, security headers).

#![cfg(feature = "http3")]

use bytes::Buf;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::TlsConfig;
use crate::metrics;
use crate::proxy::ZionBody;
use crate::{logging, waf};

/// Pre-built Alt-Svc header value for HTTP/3 advertisement.
pub static ALT_SVC_H3: hyper::header::HeaderValue =
    hyper::header::HeaderValue::from_static("h3=\":443\"; ma=86400");

/// Build a quinn ServerConfig from Zion's TLS config.
/// QUIC mandates TLS 1.3 — we reuse the same cert/key as the TCP listener.
pub fn build_quinn_server_config(tls: &TlsConfig) -> quinn::ServerConfig {
    let cert_file = std::fs::File::open(&tls.cert_path)
        .unwrap_or_else(|e| panic!("QUIC cert {}: {}", tls.cert_path, e));
    let key_file = std::fs::File::open(&tls.key_path)
        .unwrap_or_else(|e| panic!("QUIC key {}: {}", tls.key_path, e));

    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse QUIC cert PEM");

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
        .expect("Failed to parse QUIC key PEM")
        .expect("No private key in PEM");

    let mut tls_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("Failed to build QUIC TLS config");

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .expect("Failed to create QUIC server config"),
    ));

    // Transport config tuning
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(64u32.into());
    server_config.transport_config(Arc::new(transport));

    server_config
}

pub fn quinn_server_config_from_rustls(
    arc_config: Arc<rustls::ServerConfig>,
) -> quinn::ServerConfig {
    let mut cloned = (*arc_config).clone();
    cloned.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(cloned)
            .expect("Failed to convert rustls config to QUIC config"),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(64u32.into());
    server_config.transport_config(Arc::new(transport));
    server_config
}

/// Spawn the QUIC listener on the given address.
/// Runs in a background tokio task, accepting connections forever.
pub fn spawn_quic_listener(
    addr: SocketAddr,
    tls: &TlsConfig,
    state: Arc<crate::AppState>,
    reload_rx: Option<tokio::sync::watch::Receiver<Option<Arc<rustls::ServerConfig>>>>,
) {
    let server_config = build_quinn_server_config(tls);

    let endpoint = quinn::Endpoint::server(server_config, addr)
        .unwrap_or_else(|e| panic!("Failed to bind QUIC on {}: {}", addr, e));

    eprintln!("  listening HTTP/3 (QUIC) on {}", addr);

    if let Some(mut rx) = reload_rx {
        let endpoint_clone = endpoint.clone();
        tokio::spawn(async move {
            while rx.changed().await.is_ok() {
                if let Some(arc_config) = rx.borrow().clone() {
                    let new_quinn_cfg = quinn_server_config_from_rustls(arc_config);
                    endpoint_clone.set_server_config(Some(new_quinn_cfg));
                    eprintln!("  h3: certificates hot-reloaded.");
                }
            }
        });
    }

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
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
                        eprintln!("  quic accept error: {}", e);
                        return;
                    }
                };

                let remote_addr = conn.remote_address();
                metrics::METRICS
                    .connections_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _conn_guard = metrics::ConnectionGuard::new();

                let h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await;

                let mut h3_conn = match h3_conn {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("  h3 connection error: {}", e);
                        return;
                    }
                };

                loop {
                    match h3_conn.accept().await {
                        Ok(Some(resolver)) => {
                            let state = state.clone();
                            tokio::spawn(async move {
                                match resolver.resolve_request().await {
                                    Ok((req, stream)) => {
                                        if let Err(e) =
                                            handle_h3_request(req, stream, state, remote_addr).await
                                        {
                                            eprintln!("  h3 request error: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("  h3 resolve error: {}", e);
                                    }
                                }
                            });
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("  h3 accept error: {}", e);
                            break;
                        }
                    }
                }
            });
        }
    });
}

/// Send an H3 error response.
async fn h3_error_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    status: hyper::StatusCode,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let resp = hyper::Response::builder().status(status).body(()).unwrap();
    stream.send_response(resp).await?;
    stream.finish().await?;
    Ok(())
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
    state: Arc<crate::AppState>,
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

    // Spawn task to sequentially copy HTTP/3 request payload chunks into the Request stream body
    tokio::spawn(async move {
        while let Ok(Some(mut buf)) = recv_stream.recv_data().await {
            use bytes::Buf;
            let rem = buf.remaining();
            let bytes = bytes::Buf::copy_to_bytes(&mut buf, rem);
            if tx.send(Ok(hyper::body::Frame::data(bytes))).await.is_err() {
                break;
            }
        }
    });

    let uni_req: hyper::Request<crate::ZionBody> = hyper::Request::builder()
        .method(req.method().clone())
        .uri(req.uri().clone())
        // Apply connection properties
        .header("X-Forwarded-For", remote_addr.ip().to_string())
        .header("X-Forwarded-Proto", "https") // H3 is virtually synonymous with TLS
        .body(stream_body.boxed())?;

    // Dispatch the bridged request through the single source of truth HTTP processing engine
    // (This automatically executes all Gates: WAF, CORS, Auth, Rate Limits, and Routes).
    let resp_result = crate::process_request(uni_req, state, remote_addr, false).await;

    // Transform upstream pipeline output to stream HTTP/3 responses back to the client natively
    let resp: hyper::Response<crate::ZionBody> = match resp_result {
        Ok(r) => r,
        Err(_) => {
            // Fail safe on generic HTTP internal pipeline errors
            crate::metrics::METRICS.record_status(500);
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
