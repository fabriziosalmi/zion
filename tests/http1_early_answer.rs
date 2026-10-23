// SPDX-License-Identifier: Apache-2.0
//! An HTTP/1.1 client still sending a body when zion answers gets the answer, against the real
//! binary: a chunked upload of 3 MiB to a route with `max_body_mb = 1` is answered `413`, and the
//! client, which only reads once it has sent everything, reads that `413`. Without the lingering
//! close (`src/linger.rs`) zion closed the connection on the unread bytes, the client's writes
//! met a reset, and it read nothing (0 of 20 tries, measured).
//!
//! Unix only, and skipped when `openssl` is not installed (it makes the certificate).
#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod common;
use common::free_port;

struct Proc(Child);
impl Drop for Proc {
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

/// An upstream that reads a chunked request to its last chunk and answers `200`; a body cut off
/// on the way gets no answer.
fn origin() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 65536];
                let mut tail: Vec<u8> = Vec::new();
                loop {
                    let n = match s.read(&mut buf) {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    tail.extend_from_slice(&buf[..n]);
                    if tail.ends_with(b"\r\n0\r\n\r\n") {
                        break;
                    }
                    let keep = tail.len().saturating_sub(16);
                    tail.drain(..keep);
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
            });
        }
    });
    port
}

/// Boot zion with one route capped at 1 MB; None when openssl is missing.
fn start(dir: &Path, origin_port: u16) -> Option<(Proc, u16)> {
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    let made = Command::new("openssl")
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
    let https_port = free_port();
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\n\
             [upstreams]\nbackend = \"http://127.0.0.1:{origin_port}\"\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\nmax_body_mb = 1\n",
            free_port(),
            cert.to_string_lossy(),
            key.to_string_lossy()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", dir.join("zion.toml"))
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(dir.join("daemon.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let z = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https_port)).is_err() {
        assert!(Instant::now() < deadline, "zion never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    Some((z, https_port))
}

/// Send a chunked body of `len` bytes over HTTP/1.1, then read whatever the server answered.
/// The client reads nothing until it has sent everything, as a simple uploader does.
fn upload_then_read(port: u16, len: usize) -> String {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    let conn =
        rustls::ClientConnection::new(Arc::new(tls), "localhost".try_into().unwrap()).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let head = "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut sent = s.write_all(head.as_bytes()).is_ok();
    let chunk = vec![b'x'; 65536];
    let mut left = len;
    while sent && left > 0 {
        let n = left.min(chunk.len());
        sent = s.write_all(format!("{n:x}\r\n").as_bytes()).is_ok()
            && s.write_all(&chunk[..n]).is_ok()
            && s.write_all(b"\r\n").is_ok();
        left -= n;
    }
    if sent {
        let _ = s.write_all(b"0\r\n\r\n");
    }
    let mut answer = Vec::new();
    let _ = s.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
}

#[test]
fn a_client_still_sending_reads_the_413() {
    let dir = std::env::temp_dir().join(format!(
        "zion-http1-early-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    let Some((_zion, port)) = start(&dir, origin()) else {
        return;
    };
    for attempt in 1..=5 {
        let answer = upload_then_read(port, 3 * 1_048_576);
        assert!(
            answer.starts_with("HTTP/1.1 413"),
            "attempt {attempt}: the client read {:?}",
            answer.lines().next().unwrap_or("nothing")
        );
    }
    // a body within the cap still goes through
    assert!(upload_then_read(port, 512 * 1024).starts_with("HTTP/1.1 200"));
    let _ = fs::remove_dir_all(dir);
}
