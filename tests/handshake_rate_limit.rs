// SPDX-License-Identifier: Apache-2.0
//! Per-IP new-handshake rate limit (#718), against the real binary: a single source IP that
//! starts TLS handshakes faster than `[server] max_handshakes_per_ip_per_sec` is shed at accept,
//! before the handshake. The limiter is keyed on the peer IP, so on loopback every connection in
//! this test shares one bucket.
//!
//! Three cases: a low rate sheds a flood (most handshakes fail); `0` disables the limit so the
//! same flood all succeeds (the break-test — remove the gate, nothing is shed); an allowlisted
//! source is never limited.
//!
//! Unix only, and skipped when `openssl` is not installed (it makes the throwaway certificate).
#![cfg(unix)]

use std::net::TcpStream as StdTcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

mod common;
use common::free_port;

struct Zion {
    child: Child,
    https: u16,
    dir: PathBuf,
}
impl Drop for Zion {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
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

/// Start zion with `server` appended to `[server]`; `None` when `openssl` is unavailable.
fn start(server: &str) -> Option<Zion> {
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-hsrate-{}-{http}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
    let made = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        ])
        .args([
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !made {
        eprintln!("SKIP: openssl not available");
        return None;
    }
    let cfg = dir.join("zion.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n{server}\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\
             [upstreams]\nbackend = \"http://127.0.0.1:1\"\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n",
            cert.display(),
            key.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", &cfg)
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("zion.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let zion = Zion { child, https, dir };
    // Readiness is probed on the HTTP port on purpose: a bare TCP connect to the HTTPS port counts
    // as a handshake attempt against the very limit under test.
    let deadline = Instant::now() + Duration::from_secs(20);
    while StdTcpStream::connect(("127.0.0.1", http)).is_err() {
        assert!(Instant::now() < deadline, "zion did not start listening");
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(300));
    Some(zion)
}

fn connector() -> tokio_rustls::TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(tls))
}

/// Attempt one TLS handshake to the HTTPS port. `true` if it completed (admitted), `false` if the
/// connection was closed first (sheddd at accept) or the connect failed.
async fn handshake_ok(https: u16, connector: &tokio_rustls::TlsConnector) -> bool {
    let Ok(tcp) = TcpStream::connect(("127.0.0.1", https)).await else {
        return false;
    };
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    connector.connect(name, tcp).await.is_ok()
}

/// Fire `n` handshakes back to back from one IP; returns how many completed.
async fn flood(https: u16, n: usize) -> usize {
    let connector = connector();
    let mut ok = 0;
    for _ in 0..n {
        if handshake_ok(https, &connector).await {
            ok += 1;
        }
    }
    ok
}

#[tokio::test(flavor = "multi_thread")]
async fn a_single_ip_handshake_flood_is_shed() {
    // rate 5/s, burst 5: a back-to-back flood of 60 completes in well under a second, so only the
    // burst (plus the trickle one second of refill would add) gets through; the rest are shed.
    let Some(zion) = start("max_handshakes_per_ip_per_sec = 5\nhandshake_burst_per_ip = 5") else {
        return;
    };
    let admitted = flood(zion.https, 60).await;
    assert!(
        admitted <= 20,
        "a flood past the rate must be shed; {admitted}/60 completed the handshake"
    );
    assert!(
        admitted >= 1,
        "the burst allowance must let the first few through; {admitted}/60 completed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_zero_disables_the_limit_and_the_flood_is_not_shed() {
    // The break-test: with the gate off (rate 0), the same flood all completes.
    let Some(zion) = start("max_handshakes_per_ip_per_sec = 0") else {
        return;
    };
    let admitted = flood(zion.https, 60).await;
    assert!(
        admitted >= 58,
        "a disabled limit must shed nothing; only {admitted}/60 completed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowlisted_source_is_never_limited() {
    // Same low rate as the shed test, but loopback is allowlisted: nothing is shed.
    let Some(zion) = start(
        "max_handshakes_per_ip_per_sec = 5\nhandshake_burst_per_ip = 5\n\
         handshake_rate_allowlist = [\"127.0.0.0/8\", \"::1/128\"]",
    ) else {
        return;
    };
    let admitted = flood(zion.https, 60).await;
    assert!(
        admitted >= 58,
        "an allowlisted source must not be limited; only {admitted}/60 completed"
    );
}
