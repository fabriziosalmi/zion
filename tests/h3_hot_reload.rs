// SPDX-License-Identifier: Apache-2.0
//! HTTP/3 keeps working after a TLS hot reload, against the real binary.
//!
//! Boot zion with `--features http3` and the default `[tls] hot_reload` (true), make one
//! HTTP/3 request (the boot QUIC config), rewrite the certificate file in place (what an ACME
//! or certbot renewal does), wait for the QUIC listener to install the reloaded config, and
//! make a second HTTP/3 request. The second handshake must succeed and the daemon must not
//! panic.
//!
//! The reload handed the TCP listener's rustls config to QUIC as it was, with 16384 bytes of
//! early data allowed; QUIC allows only 0 or `u32::MAX`, rustls refused the connection and
//! quinn-proto unwrapped the refusal, so every HTTP/3 handshake after a renewal panicked (and
//! the release profile aborts on panic).
//!
//! Needs `--features http3` and `openssl` (skipped without).
#![cfg(all(unix, feature = "http3"))]

use bytes::Buf;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

mod common;
use common::free_port;

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug)]
struct AnyCert;
impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A plain HTTP/1.0 upstream on a thread that answers `ok` to anything.
fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\ncontent-length: 2\r\n\r\nok");
            });
        }
    });
    port
}

/// One HTTP/3 GET on a fresh QUIC connection; the status, or what went wrong.
async fn h3_get(port: u16) -> Result<u16, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut ep =
        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).map_err(|e| e.to_string())?;
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(qc)));
    let conn = ep
        .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
        .map_err(|e| format!("connect: {e}"))?
        .await
        .map_err(|e| format!("QUIC handshake: {e}"))?;
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| format!("h3 setup: {e}"))?;
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = hyper::Request::get("https://localhost/x").body(()).unwrap();
    let mut stream = send
        .send_request(req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    stream.finish().await.map_err(|e| format!("finish: {e}"))?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| format!("response: {e}"))?;
    while let Ok(Some(mut c)) = stream.recv_data().await {
        c.advance(c.remaining());
    }
    drive.abort();
    Ok(resp.status().as_u16())
}

/// The same GET, bounded: a handshake the server never answers is an error, not a hang.
async fn h3_get_within(port: u16, within: Duration) -> Result<u16, String> {
    match tokio::time::timeout(within, h3_get(port)).await {
        Ok(r) => r,
        Err(_) => Err(format!("no HTTP/3 response within {within:?}")),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn h3_still_handshakes_after_a_tls_hot_reload() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-reload-{}-{}",
        std::process::id(),
        free_port()
    ));
    // The certificate lives in its own directory, the one the TLS watcher watches; the logs
    // stay outside it, so only the rewrite below fires a reload.
    let tls_dir = dir.join("tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    let ok = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        ])
        .args([
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ])
        .arg("-keyout")
        .arg(tls_dir.join("k.pem"))
        .arg("-out")
        .arg(tls_dir.join("c.pem"))
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        common::skip("openssl not available");
        return;
    }
    let https = free_port();
    let t = tls_dir.to_string_lossy();
    // No `hot_reload` line: the default (true) is what an operator runs.
    std::fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
             [tls]\ncert_path = \"{t}/c.pem\"\nkey_path = \"{t}/k.pem\"\n\
             [upstreams]\nbe = \"http://127.0.0.1:{}\"\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"be\"\n",
            free_port(),
            upstream()
        ),
    )
    .unwrap();
    let log = dir.join("daemon.log");
    let gasp = dir.join("gasp.jsonl");
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", dir.join("zion.toml"))
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", &gasp)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .expect("spawn zion");
    let mut daemon = Daemon(child);
    common::wait_for_log(&log, "listening HTTP/3", Duration::from_secs(20));
    common::wait_for_log(&log, "tls watcher active", Duration::from_secs(20));

    // 1. The boot QUIC config works.
    let before = h3_get_within(https, Duration::from_secs(10)).await;
    assert_eq!(before, Ok(200), "HTTP/3 before the reload");

    // 2. A renewal rewrites the certificate in place: the watcher reloads TLS and hands the
    //    new rustls config to the QUIC listener.
    let pem = std::fs::read(tls_dir.join("c.pem")).unwrap();
    std::fs::write(tls_dir.join("c.pem"), pem).unwrap();
    common::wait_for_log(
        &log,
        "h3: certificates hot-reloaded",
        Duration::from_secs(30),
    );

    // 3. The next HTTP/3 client, any client, must still get through.
    let after = h3_get_within(https, Duration::from_secs(10)).await;
    std::thread::sleep(Duration::from_millis(500)); // let the panic hook finish writing
    let gasp_text = std::fs::read_to_string(&gasp).unwrap_or_default();
    let alive = daemon.0.try_wait().unwrap().is_none();
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    let panics: Vec<&str> = log_text.lines().filter(|l| l.contains("panic")).collect();
    assert!(
        after == Ok(200) && !gasp_text.contains("\"event\":\"panic\""),
        "HTTP/3 after a TLS hot reload\n  request: {after:?}\n  daemon still running: {alive}\n  \
         last gasp: {gasp_text}\n  panic lines in the daemon log:\n{}",
        panics.join("\n")
    );
    let _ = std::fs::remove_dir_all(dir);
}
