//! Zion HTTP/3 (QUIC) listener — feature-gated via `--features http3`.
//!
//! Architecture: runs alongside the TCP TLS listener on the same port (UDP :443).
//! Clients discover HTTP/3 via the `Alt-Svc: h3=":443"; ma=86400` header
//! injected on all HTTP/1.1 and H2 responses.

#![cfg(feature = "http3")]

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::TlsConfig;
use crate::metrics;
use crate::proxy::ZionBody;

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

    let mut tls_config = rustls::ServerConfig::builder_with_protocol_versions(
        &[&rustls::version::TLS13],
    )
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

/// Spawn the QUIC listener on the given address.
/// Runs in a background tokio task, accepting connections forever.
pub fn spawn_quic_listener(
    addr: SocketAddr,
    tls: &TlsConfig,
    state: Arc<crate::AppState>,
) {
    let server_config = build_quinn_server_config(tls);

    let endpoint = quinn::Endpoint::server(server_config, addr)
        .unwrap_or_else(|e| panic!("Failed to bind QUIC on {}: {}", addr, e));

    eprintln!("  listening HTTP/3 (QUIC) on {}", addr);

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let state = state.clone();

            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("  quic accept error: {}", e);
                        return;
                    }
                };

                metrics::METRICS.connections_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                                        if let Err(e) = handle_h3_request(req, stream, state).await {
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

/// Handle a single HTTP/3 request through the Zion pipeline.
async fn handle_h3_request<S>(
    req: hyper::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    state: Arc<crate::AppState>,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let request_start = std::time::Instant::now();

    // Route through radix tree
    let path = req.uri().path();
    let rule = match state.router.at(path) {
        Ok(m) => m.value.clone(),
        Err(_) => {
            let resp = hyper::Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    // Build upstream URI
    let path_and_query = req.uri().path_and_query().cloned()
        .unwrap_or_else(|| "/".parse().unwrap());
    let upstream_uri = hyper::Uri::builder()
        .scheme(rule.upstream_scheme.clone())
        .authority(rule.upstream_authority.clone())
        .path_and_query(path_and_query)
        .build()?;

    // Forward to upstream via HTTP/1.1 client (QUIC→TCP bridge)
    let upstream_req: hyper::Request<ZionBody> = hyper::Request::builder()
        .method(req.method().clone())
        .uri(upstream_uri)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )?;

    let upstream_start = std::time::Instant::now();
    let resp = match state.http_client.request(upstream_req).await {
        Ok(resp) => {
            metrics::METRICS.upstream_duration.observe(upstream_start.elapsed());
            resp
        }
        Err(_) => {
            let resp = hyper::Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    // Send response back over QUIC
    let status = resp.status();
    let h3_resp = hyper::Response::builder()
        .status(status)
        .body(())
        .unwrap();
    stream.send_response(h3_resp).await?;

    // Stream body
    let body_bytes = resp.into_body().collect().await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    if !body_bytes.is_empty() {
        stream.send_data(body_bytes).await?;
    }
    stream.finish().await?;

    metrics::METRICS.record_status(status.as_u16());
    metrics::METRICS.request_duration.observe(request_start.elapsed());

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
