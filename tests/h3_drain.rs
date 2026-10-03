//! HTTP/3 connections are drained on shutdown like HTTP/1 and HTTP/2 ones, against the
//! real binary: an idle QUIC connection no longer holds SIGTERM for the 30 s drain limit,
//! and a request in flight when SIGTERM arrives still gets its response.
//!
//! Needs `--features http3` (CI's all-features test job) and `openssl` (skipped without).
#![cfg(all(unix, feature = "http3"))]

use bytes::Buf;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// A plain HTTP/1.0 upstream on a thread: `/slow` answers after 2 s, anything else at once.
fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                if String::from_utf8_lossy(&buf[..n]).contains("/slow") {
                    std::thread::sleep(Duration::from_secs(2));
                }
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\ncontent-length: 2\r\n\r\nok");
            });
        }
    });
    port
}

/// Boot zion with HTTP/3 on a fresh port; None when openssl is missing.
fn boot(dir: &std::path::Path, upstream: u16) -> Option<(Daemon, u16)> {
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
        .arg(dir.join("k.pem"))
        .arg("-out")
        .arg(dir.join("c.pem"))
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: openssl not available");
        return None;
    }
    let https = free_port();
    let d = dir.to_string_lossy();
    std::fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
             [tls]\ncert_path = \"{d}/c.pem\"\nkey_path = \"{d}/k.pem\"\nhot_reload = false\n\
             [upstreams]\nbe = \"http://127.0.0.1:{upstream}\"\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"be\"\n",
            free_port()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", dir.join("zion.toml"))
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("daemon.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = std::fs::read_to_string(dir.join("daemon.log")).unwrap_or_default();
        if log.contains("listening HTTP/3") {
            return Some((daemon, https));
        }
        assert!(Instant::now() < deadline, "no HTTP/3 listener:\n{log}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Open an HTTP/3 connection, GET `path`, and return the status; the connection (and
/// its driver) stay alive in the returned guard.
async fn h3_get(port: u16, path: &str) -> (u16, Box<dyn std::any::Any + Send>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(qc)));
    let conn = ep
        .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = hyper::Request::get(format!("https://localhost{path}"))
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    while let Ok(Some(mut c)) = stream.recv_data().await {
        c.advance(c.remaining());
    }
    (resp.status().as_u16(), Box::new((ep, send, drive)))
}

fn sigterm_and_time(d: &mut Daemon) -> Duration {
    let t = Instant::now();
    let _ = Command::new("kill")
        .args(["-TERM", &d.0.id().to_string()])
        .status();
    let deadline = t + Duration::from_secs(40);
    while d.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "zion never exited");
        std::thread::sleep(Duration::from_millis(50));
    }
    t.elapsed()
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-{tag}-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn an_idle_h3_connection_does_not_hold_shutdown() {
    let dir = tmpdir("idle");
    let Some((mut d, port)) = boot(&dir, upstream()) else {
        return;
    };
    let (status, _keep_open) = h3_get(port, "/x").await;
    assert_eq!(status, 200);
    let took = tokio::task::spawn_blocking(move || sigterm_and_time(&mut d))
        .await
        .unwrap();
    // it used to wait for the QUIC idle timeout (~30 s, the drain limit)
    assert!(took < Duration::from_secs(10), "shutdown took {took:?}");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_h3_request_in_flight_at_sigterm_still_completes() {
    let dir = tmpdir("inflight");
    let Some((mut d, port)) = boot(&dir, upstream()) else {
        return;
    };
    let pid = d.0.id();
    let req = tokio::spawn(async move { h3_get(port, "/slow").await.0 });
    tokio::time::sleep(Duration::from_millis(700)).await; // the request is at the upstream
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    assert_eq!(
        req.await.unwrap(),
        200,
        "the request in flight was finished"
    );
    let took = tokio::task::spawn_blocking(move || {
        let t = Instant::now();
        while d.0.try_wait().unwrap().is_none() {
            assert!(t.elapsed() < Duration::from_secs(40), "zion never exited");
            std::thread::sleep(Duration::from_millis(50));
        }
        t.elapsed()
    })
    .await
    .unwrap();
    assert!(
        took < Duration::from_secs(10),
        "then it exited ({took:?} after the response)"
    );
    let _ = std::fs::remove_dir_all(dir);
}
