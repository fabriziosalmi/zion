// SPDX-License-Identifier: Apache-2.0
//! An HTTP/3 request body that breaks on the way is never handed on as a whole one, against the
//! real binary: a client sends part of a body without `Content-Length` and resets the stream. The
//! upstream must not receive what had arrived as a complete body, whether zion streams it (no
//! WAF), reads it first (a WAF) or reads it to give it a length (`require_content_length`). A body
//! that arrives whole still reaches the upstream whole.
//!
//! Needs `--features http3` (CI's all-features test job) and `openssl` (skipped without).
#![cfg(all(unix, feature = "http3"))]

use bytes::Buf;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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

/// What the upstream made of one request body.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    received: usize,
    complete: bool,
}

/// An HTTP/1.1 upstream that reads each request body by its framing (`Content-Length` or
/// chunked) and records how much arrived and whether the body ended as its framing says.
fn upstream(seen: Arc<Mutex<Vec<Seen>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("?").to_string();
                let (mut length, mut chunked) = (None::<usize>, false);
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    let h = h.to_ascii_lowercase();
                    if let Some(v) = h.strip_prefix("content-length:") {
                        length = v.trim().parse().ok();
                    }
                    if h.starts_with("transfer-encoding:") && h.contains("chunked") {
                        chunked = true;
                    }
                }
                let (mut received, mut complete) = (0, false);
                if let Some(n) = length {
                    let mut buf = vec![0u8; n];
                    while received < n {
                        match r.read(&mut buf[received..]) {
                            Ok(0) | Err(_) => break,
                            Ok(k) => received += k,
                        }
                    }
                    complete = received == n;
                } else if chunked {
                    loop {
                        let mut size = String::new();
                        if r.read_line(&mut size).unwrap_or(0) == 0 {
                            break;
                        }
                        let Ok(n) = usize::from_str_radix(size.trim(), 16) else {
                            break;
                        };
                        if n == 0 {
                            complete = true;
                            break;
                        }
                        let mut buf = vec![0u8; n + 2];
                        if r.read_exact(&mut buf).is_err() {
                            break;
                        }
                        received += n;
                    }
                } else {
                    complete = true;
                }
                seen.lock().unwrap().push(Seen {
                    path,
                    received,
                    complete,
                });
                if complete {
                    let mut s = s;
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    );
                }
            });
        }
    });
    port
}

/// Boot zion with HTTP/3 and three routes to the upstream; None when openssl is missing.
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
             [waf_profile.lenient]\ndeny_unknown_content_types = false\n\
             [[route]]\npath = \"/waf/{{*rest}}\"\nupstream = \"be\"\nwaf_profile = \"lenient\"\n\
             [[route]]\npath = \"/framed/{{*rest}}\"\nupstream = \"be\"\nrequire_content_length = true\n\
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

/// POST 1000 bytes over HTTP/3 without `Content-Length`. With `reset`, the client then resets
/// the stream instead of finishing the body, and gets no answer; otherwise it returns the status.
async fn h3_post(port: u16, path: &str, reset: bool) -> Option<u16> {
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
    let _drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = hyper::Request::post(format!("https://localhost{path}"))
        // a content-type the lenient WAF profile lets through without structural
        // parsing (not multipart/json), so the body itself is what is tested
        .header("content-type", "application/octet-stream")
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.unwrap();
    stream
        .send_data(bytes::Bytes::from(vec![b'a'; 1000]))
        .await
        .unwrap();
    if reset {
        // let the bytes reach zion and the upstream before the stream breaks
        tokio::time::sleep(Duration::from_millis(300)).await;
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        return None;
    }
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    while let Ok(Some(mut c)) = stream.recv_data().await {
        c.advance(c.remaining());
    }
    Some(resp.status().as_u16())
}

/// Send an HTTP/3 request whose HEADERS declare `content-length = declared` but whose stream is
/// finished immediately with no DATA frame (HEADERS carrying FIN). Returns the client-visible
/// status, or None if the request was rejected at the stream level (#697 form 9).
async fn h3_headers_fin_with_cl(port: u16, path: &str, declared: usize) -> Option<u16> {
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
    let _drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = hyper::Request::post(format!("https://localhost{path}"))
        .header("content-type", "application/octet-stream")
        .header("content-length", declared.to_string())
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.ok()?;
    // Finish the stream with no DATA: the headers promised `declared` bytes that never come.
    stream.finish().await.ok()?;
    let resp = stream.recv_response().await.ok()?;
    Some(resp.status().as_u16())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broken_h3_body_never_reaches_the_upstream_as_a_whole_one() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-body-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };

    // streamed (no WAF), read by the WAF, read to be given a length
    for path in ["/open/x", "/waf/x", "/framed/x"] {
        assert_eq!(h3_post(port, path, true).await, None);
        let whole: Vec<Seen> = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path && s.complete)
            .cloned()
            .collect();
        assert!(
            whole.is_empty(),
            "{path}: the upstream took a broken body as a whole one: {whole:?}"
        );
    }

    // a body that arrives whole still goes through whole, on every route
    for path in ["/open/y", "/waf/y", "/framed/y"] {
        assert_eq!(h3_post(port, path, false).await, Some(200), "{path}");
        let got: Vec<Seen> = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path)
            .cloned()
            .collect();
        assert!(
            got.len() == 1 && got[0].complete && got[0].received == 1000,
            "{path}: {got:?}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_h3_headers_fin_with_content_length_is_not_a_phantom_body() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-phantom-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };

    // The headers promise 1000 bytes; the stream ends with none. zion must not forward a request
    // the upstream would wait on, and must not fabricate a 2xx for a body that never arrived.
    let status = match tokio::time::timeout(
        Duration::from_secs(10),
        h3_headers_fin_with_cl(port, "/open/z", 1000),
    )
    .await
    {
        Ok(s) => s,
        Err(_) => panic!("zion hung on a HEADERS+FIN request that declared a Content-Length"),
    };
    std::thread::sleep(Duration::from_millis(300));
    let recs: Vec<Seen> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.path == "/open/z")
        .cloned()
        .collect();
    assert!(
        recs.is_empty(),
        "a HEADERS+FIN request with a non-zero Content-Length reached the upstream: {recs:?}"
    );
    assert!(
        status.is_none_or(|s| s >= 400),
        "a request whose promised body never arrived must not get a 2xx: {status:?}"
    );

    let _ = std::fs::remove_dir_all(dir);
}
