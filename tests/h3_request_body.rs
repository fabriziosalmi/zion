// SPDX-License-Identifier: Apache-2.0
//! An HTTP/3 request body that breaks on the way is never handed on as a whole one, against the
//! real binary: a client sends part of a body without `Content-Length` and resets the stream. The
//! upstream must not receive what had arrived as a complete body, whether zion streams it (no
//! WAF), reads it first (a WAF) or reads it to give it a length (`require_content_length`). A body
//! that arrives whole still reaches the upstream whole.
//!
//! The same holds for a body that does not match its `Content-Length` (h3 checks neither the
//! header nor the DATA against it): shorter, longer, or declared by lines that disagree, it is
//! refused and never forwarded with a length it does not have, which on a pooled keep-alive
//! upstream connection made the upstream read the next request as the rest of the body.
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
        common::skip("openssl not available");
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
    h3_post_declaring(port, path, &[&declared.to_string()], 0).await
}

/// POST over HTTP/3 whose HEADERS carry one `content-length` line per entry of `declared`, then
/// `sent` bytes of DATA (none: the stream ends right after the HEADERS) and FIN, whatever the
/// lines say. Returns the client-visible status, or None if the request got no response.
async fn h3_post_declaring(port: u16, path: &str, declared: &[&str], sent: usize) -> Option<u16> {
    let parts: &[usize] = if sent > 0 { &[sent] } else { &[] };
    h3_post_parts(port, path, declared, parts, Duration::ZERO, true).await
}

/// POST over HTTP/3 whose HEADERS carry one `content-length` line per entry of `declared`, then
/// one DATA frame per entry of `parts`, of that many bytes, `gap` apart, whatever the lines say.
/// With `fin` the stream then ends; without it the client sends nothing more and keeps the
/// stream open while it waits for the answer. Returns the client-visible status, or None if the
/// request got no response.
async fn h3_post_parts(
    port: u16,
    path: &str,
    declared: &[&str],
    parts: &[usize],
    gap: Duration,
    fin: bool,
) -> Option<u16> {
    let end = if fin { End::Fin } else { End::Open };
    h3_post_frames(port, path, declared, parts, gap, end).await
}

/// How the client ends a request stream after its DATA frames.
#[derive(Clone, Copy, Debug)]
enum End {
    /// FIN.
    Fin,
    /// A trailer section, then FIN.
    Trailers,
    /// Nothing: the stream stays open while the client waits for the answer.
    Open,
}

/// A body that is to reach the upstream whole: a name, its `content-length` lines, the sizes of
/// its DATA frames, how the stream ends, and the bytes the upstream is to receive.
type WholeCase<'a> = (&'a str, &'a [&'a str], &'a [usize], End, usize);

/// [`h3_post_parts`], ending the stream as `end` says. A part of 0 is a zero-length DATA frame.
async fn h3_post_frames(
    port: u16,
    path: &str,
    declared: &[&str],
    parts: &[usize],
    gap: Duration,
    end: End,
) -> Option<u16> {
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
    let mut req = hyper::Request::post(format!("https://localhost{path}"))
        .header("content-type", "application/octet-stream");
    for value in declared {
        req = req.header("content-length", *value);
    }
    let mut stream = send.send_request(req.body(()).unwrap()).await.ok()?;
    for (i, &n) in parts.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(gap).await;
        }
        // zion may stop reading once it has seen the body is too long: the answer still comes
        let _ = stream.send_data(bytes::Bytes::from(vec![b'a'; n])).await;
    }
    match end {
        End::Fin => {
            let _ = stream.finish().await;
        }
        End::Trailers => {
            let mut trailers = hyper::HeaderMap::new();
            trailers.insert("x-checksum", hyper::header::HeaderValue::from_static("1"));
            let _ = stream.send_trailers(trailers).await;
            let _ = stream.finish().await;
        }
        End::Open => {}
    }
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

    // The headers promise 1000 bytes; the stream ends with none. The desync invariant (as for the
    // broken-body test above) is that the upstream never takes this as a WHOLE request: whether
    // zion refuses before forwarding (seen on a lean build) or forwards a body that never completes
    // (seen under all features), the upstream must never mark it complete and answer it, so there
    // is no phantom body and no fabricated 2xx.
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
    let whole: Vec<Seen> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.path == "/open/z" && s.complete)
        .cloned()
        .collect();
    assert!(
        whole.is_empty(),
        "a HEADERS+FIN request with a non-zero Content-Length reached the upstream as a whole body: {whole:?}"
    );
    assert!(
        status.is_none_or(|s| s >= 400),
        "a request whose promised body never arrived must not get a 2xx: {status:?}"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// GET over HTTP/3 with one header whose value is `len` bytes: `Ok(status)`, or `Err` with the
/// client's own refusal to send it (h3 checks the server's advertised header-section limit).
async fn h3_get_with_header(port: u16, len: usize) -> Result<u16, String> {
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
        .map_err(|e| e.to_string())?;
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| e.to_string())?;
    let _drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    // Let the server's SETTINGS arrive, as they would on any connection in use.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let req = hyper::Request::get("https://localhost/open/headers")
        .header("x-big", "a".repeat(len))
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.map_err(|e| format!("{e:?}"))?;
    stream.finish().await.map_err(|e| format!("{e:?}"))?;
    let resp = stream.recv_response().await.map_err(|e| format!("{e:?}"))?;
    while let Ok(Some(mut c)) = stream.recv_data().await {
        c.advance(c.remaining());
    }
    Ok(resp.status().as_u16())
}

/// The HTTP/3 listener bounds a request's header section at 16 KiB, as HTTP/1.1 and HTTP/2 do.
/// h3's default bound is VarInt::MAX, so a client could make zion decode and hold a header
/// block of any size. The bound is advertised in SETTINGS: a conforming client refuses to send
/// a bigger one (and its error names zion's limit), and zion answers one that arrives with 431.
#[tokio::test(flavor = "multi_thread")]
async fn a_h3_header_section_over_16_kib_is_not_served() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-hdr-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };
    assert_eq!(
        h3_get_with_header(port, 1024).await,
        Ok(200),
        "1 KiB is served"
    );
    let big = h3_get_with_header(port, 20 * 1024).await;
    assert!(
        matches!(&big, Ok(431)) || matches!(&big, Err(e) if e.contains("16384")),
        "a 20 KiB header section is refused (431, or the client refuses on zion's 16384): {big:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// What an nginx-like upstream made of one request on a keep-alive connection: the path and
/// `Content-Length` of the head zion wrote, then the bytes it drained as that declared body.
#[derive(Debug, Clone)]
#[allow(dead_code)] // `eof` is evidence, read only through the Debug of a failed assertion
struct DesyncSeen {
    path: String,
    declared: usize,
    received: usize,
    body_prefix: String,
    eof: bool,
}

/// An HTTP/1.1 keep-alive upstream that answers a request BEFORE it reads the declared body,
/// then drains `Content-Length` bytes before it parses the next request: nginx's static and
/// `discard_body` path, Node/llhttp's `req._dump`, h11's auto-drain. It hands zion a response
/// while it still expects the body it was promised, so a head that declares more than zion
/// sends leaves the pooled connection reading the next request as that body.
fn nginx_like_upstream(seen: Arc<Mutex<Vec<DesyncSeen>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                // Give up draining after 3 s so a desynced connection records and ends rather
                // than hanging the test; a well-framed body of this size arrives at once.
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                let mut r = BufReader::new(s.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    match r.read_line(&mut line) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    let path = line.split_whitespace().nth(1).unwrap_or("?").to_string();
                    let mut declared = 0usize;
                    loop {
                        let mut h = String::new();
                        match r.read_line(&mut h) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                        if h == "\r\n" {
                            break;
                        }
                        let h = h.to_ascii_lowercase();
                        if let Some(v) = h.strip_prefix("content-length:") {
                            declared = v.trim().parse().unwrap_or(0);
                        }
                    }
                    // Answer first: zion gets its 2xx and returns the connection to its idle pool.
                    {
                        let mut w = s.try_clone().unwrap();
                        let _ = w.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
                    }
                    // Only now drain the body the head declared. On a well-framed request these
                    // are this request's own bytes; on a desynced connection, the NEXT request.
                    let mut drained: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 4096];
                    let mut eof = false;
                    while drained.len() < declared {
                        let want = (declared - drained.len()).min(buf.len());
                        match r.read(&mut buf[..want]) {
                            Ok(0) => {
                                eof = true;
                                break;
                            }
                            Ok(k) => drained.extend_from_slice(&buf[..k]),
                            Err(_) => break, // read timeout: nothing (more) came
                        }
                    }
                    let body_prefix =
                        String::from_utf8_lossy(&drained[..drained.len().min(96)]).into_owned();
                    seen.lock().unwrap().push(DesyncSeen {
                        path,
                        declared,
                        received: drained.len(),
                        body_prefix,
                        eof,
                    });
                    // What the test needs is recorded; do not parse past a body.
                    if declared > 0 {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// Send an HTTP/3 POST of `n` body bytes to `path` and finish the stream, without reading the
/// response: the test reads what the upstream made of it, whatever the upstream answered.
async fn h3_send_body_no_wait(port: u16, path: &str, n: usize) {
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
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.unwrap();
    stream
        .send_data(bytes::Bytes::from(vec![b'B'; n]))
        .await
        .unwrap();
    stream.finish().await.unwrap();
    // Let zion collect the body and write it to the upstream.
    tokio::time::sleep(Duration::from_millis(600)).await;
}

/// An HTTP/3 request to a WAF route whose HEADERS declare `content-length: 1000` and whose stream
/// ends with no DATA. The WAF buffered the empty body and the client's `content-length: 1000`
/// was forwarded with it: hyper wrote no body bytes and returned the connection to its pool,
/// and the next request on it was drained by the upstream as the missing 1000 bytes (request
/// smuggling from zion into the upstream). The request is now refused, and the upstream reads
/// the next request on its own framing.
#[tokio::test(flavor = "multi_thread")]
async fn a_h3_body_shorter_than_its_content_length_is_refused_and_the_upstream_stays_in_sync() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-desync-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, nginx_like_upstream(seen.clone())) else {
        return;
    };

    // Request 1: WAF route, HEADERS declare content-length: 1000, the stream ends with no DATA.
    let status = tokio::time::timeout(
        Duration::from_secs(10),
        h3_headers_fin_with_cl(port, "/waf/x", 1000),
    )
    .await
    .expect("zion hung on a WAF-route HEADERS+FIN request that declared a Content-Length");

    // Request 2: another WAF-route request, on the connection request 1 would have left idle.
    tokio::time::sleep(Duration::from_millis(150)).await;
    h3_send_body_no_wait(port, "/waf/y", 1000).await;

    let deadline = Instant::now() + Duration::from_secs(5);
    let recorded = loop {
        let recorded = seen.lock().unwrap().clone();
        if recorded
            .iter()
            .any(|s| s.path == "/waf/y" || s.body_prefix.contains("/waf/y"))
        {
            break recorded;
        }
        assert!(
            Instant::now() < deadline,
            "the upstream never recorded the /waf/y request: {recorded:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    // A proxy declares only the length it sends: request 1 sent no body.
    for req1 in recorded.iter().filter(|s| s.path == "/waf/x") {
        assert_eq!(
            req1.declared, 0,
            "zion forwarded content-length: {} for an HTTP/3 request it sent with an EMPTY body, \
             and the upstream read the next request as that body: {req1:?}",
            req1.declared
        );
    }
    // The next request on the connection is read on its own framing, whole.
    let req2: Vec<&DesyncSeen> = recorded.iter().filter(|s| s.path == "/waf/y").collect();
    assert!(
        req2.len() == 1
            && req2[0].declared == 1000
            && req2[0].received == 1000
            && req2[0].body_prefix.bytes().all(|b| b == b'B'),
        "the request after it did not reach the upstream whole: {recorded:?}"
    );
    // And the malformed request is refused, never forwarded: RFC 9114 §4.1.2.
    assert_eq!(
        status,
        Some(400),
        "a body short of its Content-Length is a malformed request: {recorded:?}"
    );
    assert!(
        recorded.iter().all(|s| s.path != "/waf/x"),
        "the malformed request reached the upstream: {recorded:?}"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// A body longer than its `Content-Length`: refused on every route, and never handed on as a
/// whole body of either length. Streamed or buffered by the WAF, hyper cut it at the declared
/// 10 bytes and the upstream took that prefix as the whole body; `require_content_length`
/// rewrote the length and sent all 1000.
#[tokio::test(flavor = "multi_thread")]
async fn a_h3_body_longer_than_its_content_length_is_refused() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-long-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };

    for path in ["/open/long", "/waf/long", "/framed/long"] {
        let status = tokio::time::timeout(
            Duration::from_secs(10),
            h3_post_declaring(port, path, &["10"], 1000),
        )
        .await
        .unwrap_or_else(|_| panic!("{path}: zion hung on a body longer than its Content-Length"));
        std::thread::sleep(Duration::from_millis(300));
        let whole: Vec<Seen> = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path && s.complete)
            .cloned()
            .collect();
        assert!(
            whole.is_empty(),
            "{path}: the upstream took a body that did not match its Content-Length as a whole \
             one: {whole:?}"
        );
        assert_eq!(status, Some(400), "{path}");
    }

    // the same request with the length it has goes through whole
    assert_eq!(
        h3_post_declaring(port, "/waf/fits", &["1000"], 1000).await,
        Some(200)
    );
    let fits: Vec<Seen> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.path == "/waf/fits")
        .cloned()
        .collect();
    assert!(
        fits.len() == 1 && fits[0].complete && fits[0].received == 1000,
        "{fits:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// `Content-Length` lines that do not declare one length (`0` then `1000`, or a value that is no
/// number) make the request malformed: refused before routing, never forwarded. They went to
/// the upstream as written, next to whatever body zion sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_h3_request_whose_content_length_lines_disagree_is_refused() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-cl-lines-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };

    for (path, declared, sent) in [
        ("/open/two", &["0", "1000"][..], 0),
        ("/waf/two", &["0", "1000"], 0),
        ("/framed/two", &["0", "1000"], 0),
        ("/waf/nan", &["5", "five"], 5),
        ("/framed/nan", &["5", "five"], 5),
    ] {
        let status = tokio::time::timeout(
            Duration::from_secs(10),
            h3_post_declaring(port, path, declared, sent),
        )
        .await
        .unwrap_or(None);
        std::thread::sleep(Duration::from_millis(200));
        let reached: Vec<Seen> = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path)
            .cloned()
            .collect();
        assert_eq!(status, Some(400), "{path} {declared:?}: {reached:?}");
        assert!(
            reached.is_empty(),
            "{path} {declared:?} reached the upstream: {reached:?}"
        );
    }

    // one length, repeated, is one length
    assert_eq!(
        h3_post_declaring(port, "/waf/twice", &["5", "5"], 5).await,
        Some(200)
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The upstream's record of `path`: what reached it as a whole body, if anything did.
fn whole_bodies(seen: &Arc<Mutex<Vec<Seen>>>, path: &str) -> Vec<Seen> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|s| s.path == path && s.complete)
        .cloned()
        .collect()
}

/// A body that does not end at its `Content-Length` is refused on a streamed route, a WAF route
/// and a `require_content_length` route alike, and none of them hands the upstream a whole body.
/// Shorter: the stream ends with no DATA, or with 5 of 10 bytes. Longer: the declared 10 bytes
/// arrive in a DATA frame of their own and the rest 300 ms later, or a length of `0` comes with
/// 1000 bytes. On a streamed route the upstream client stops reading the body at its declared
/// length, so the 10 bytes went upstream as the whole body and the upstream's `200` came back,
/// and a declared `0` went upstream as an empty request, the 1000 bytes dropped unseen.
#[tokio::test(flavor = "multi_thread")]
async fn a_h3_body_that_does_not_end_at_its_content_length_is_refused_on_every_route() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-cl-matrix-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };
    let gap = Duration::from_millis(300);

    for route in ["open", "waf", "framed"] {
        for (case, declared, parts) in [
            ("short-none", "1000", &[][..]),
            ("short", "10", &[5]),
            ("long-later", "10", &[10, 990]),
            ("long-zero", "0", &[1000]),
        ] {
            let path = format!("/{route}/{case}");
            let status = tokio::time::timeout(
                Duration::from_secs(10),
                h3_post_parts(port, &path, &[declared], parts, gap, true),
            )
            .await
            .unwrap_or_else(|_| panic!("{path}: zion hung"));
            std::thread::sleep(Duration::from_millis(300));
            let whole = whole_bodies(&seen, &path);
            assert!(
                whole.is_empty(),
                "{path}: content-length {declared} with DATA {parts:?}: the upstream took it \
                 as a whole body: {whole:?}"
            );
            assert_eq!(
                status,
                Some(400),
                "{path}: content-length {declared} with DATA {parts:?}"
            );
        }

        // A body that matches its length still goes through whole: in two DATA frames apart,
        // and empty.
        let path = format!("/{route}/fits-later");
        let status = h3_post_parts(port, &path, &["1000"], &[10, 990], gap, true).await;
        std::thread::sleep(Duration::from_millis(300));
        let whole = whole_bodies(&seen, &path);
        assert!(
            status == Some(200) && whole.len() == 1 && whole[0].received == 1000,
            "{path}: {status:?} {whole:?}"
        );
        let path = format!("/{route}/fits-empty");
        let status = h3_post_parts(port, &path, &["0"], &[], gap, true).await;
        std::thread::sleep(Duration::from_millis(300));
        let whole = whole_bodies(&seen, &path);
        assert!(
            status == Some(200) && whole.len() == 1 && whole[0].received == 0,
            "{path}: {status:?} {whole:?}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// A body past its `Content-Length` on a stream the client keeps open: the request is refused,
/// nothing reaches the upstream as a whole body, and zion goes on serving. Asking h3-quinn to stop
/// the stream while a read on it is in flight panics there (it unwraps a stream the read holds),
/// and the release profile aborts on a panic (`panic = "abort"`), so one request would take every
/// listener down. The client here sends the DATA and no FIN, so the read after it is in flight.
#[tokio::test(flavor = "multi_thread")]
async fn a_h3_body_past_its_length_on_an_open_stream_is_refused_and_zion_keeps_serving() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-cl-open-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };

    for route in ["open", "waf", "framed"] {
        let path = format!("/{route}/held");
        let status = tokio::time::timeout(
            Duration::from_secs(10),
            h3_post_parts(port, &path, &["10"], &[1000], Duration::ZERO, false),
        )
        .await
        .unwrap_or_else(|_| panic!("{path}: zion hung"));
        std::thread::sleep(Duration::from_millis(300));
        let whole = whole_bodies(&seen, &path);
        assert!(
            whole.is_empty(),
            "{path}: the upstream took a body past its Content-Length as a whole one: {whole:?}"
        );
        assert_eq!(status, Some(400), "{path}");
    }

    let log = std::fs::read_to_string(dir.join("daemon.log")).unwrap_or_default();
    assert!(
        !log.contains("panicked"),
        "zion panicked on a body past its Content-Length:\n{log}"
    );
    // and it still serves
    assert_eq!(
        h3_post_declaring(port, "/waf/after", &["5"], 5).await,
        Some(200)
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A zero-length DATA frame does not end an HTTP/3 request body: RFC 9114 does not forbid one,
/// and more DATA may follow it. h3 0.0.8 answers `recv_data` with `Ok(None)` at such a frame as
/// at the end of the stream (hyperium/h3#372), and zion took that as the end of the body: one
/// without a `Content-Length` went upstream cut at the empty frame as a complete body, one with
/// a length was refused as short, and the bytes past a length after an empty frame were never
/// seen, so the declared bytes went upstream as the whole body. On a streamed route, a WAF route
/// and a `require_content_length` route alike, with the frames sent together and, for the short
/// sequences, 300 ms apart.
#[tokio::test(flavor = "multi_thread")]
async fn a_zero_length_h3_data_frame_does_not_end_the_body() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-empty-data-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };
    // the longest run of empty DATA frames zion reads through (src/quic.rs, H3_BODY_END_ANSWERS)
    let run = [0usize; 15];
    let with_runs: Vec<usize> = [&run[..], &[500], &run, &[500], &[0]].concat();
    let past_a_run: Vec<usize> = [&[10][..], &run, &[990]].concat();
    // the runs go together only: 300 ms apart they would take seconds each
    let skip = |gap: Duration, parts: &[usize]| !gap.is_zero() && parts.len() > 3;

    for route in ["open", "waf", "framed"] {
        for gap in [Duration::ZERO, Duration::from_millis(300)] {
            // whole bodies, each to reach the upstream whole: (case, lines, DATA, end, bytes)
            let whole_cases: [WholeCase<'_>; 7] = [
                ("unframed", &[], &[500, 0, 500], End::Fin, 1000),
                ("framed", &["1000"], &[500, 0, 500], End::Fin, 1000),
                ("runs", &["1000"], &with_runs, End::Fin, 1000),
                ("empty-last", &["10"], &[10, 0], End::Fin, 10),
                ("zero-empty", &["0"], &[0], End::Fin, 0),
                ("trailers", &["10"], &[10], End::Trailers, 10),
                (
                    "unframed-trailers",
                    &[],
                    &[500, 0, 500],
                    End::Trailers,
                    1000,
                ),
            ];
            for (case, declared, parts, end, bytes) in whole_cases {
                if skip(gap, parts) {
                    continue;
                }
                let path = format!("/{route}/{case}-{}", gap.as_millis());
                let status = tokio::time::timeout(
                    Duration::from_secs(10),
                    h3_post_frames(port, &path, declared, parts, gap, end),
                )
                .await
                .unwrap_or_else(|_| panic!("{path}: zion hung"));
                std::thread::sleep(Duration::from_millis(300));
                let whole = whole_bodies(&seen, &path);
                assert!(
                    status == Some(200) && whole.len() == 1 && whole[0].received == bytes,
                    "{path}: content-length {declared:?} with DATA {parts:?} and {end:?}: \
                     {status:?}, the upstream took {whole:?} of {bytes} bytes"
                );
            }

            // past the length after empty frames: refused, never taken whole
            let refused_cases: [(&str, &str, &[usize]); 3] = [
                ("long-after-empty", "10", &[10, 0, 990]),
                ("long-after-run", "10", &past_a_run),
                ("zero-then-data", "0", &[0, 1000]),
            ];
            for (case, declared, parts) in refused_cases {
                if skip(gap, parts) {
                    continue;
                }
                let path = format!("/{route}/{case}-{}", gap.as_millis());
                let status = tokio::time::timeout(
                    Duration::from_secs(10),
                    h3_post_frames(port, &path, &[declared], parts, gap, End::Fin),
                )
                .await
                .unwrap_or_else(|_| panic!("{path}: zion hung"));
                std::thread::sleep(Duration::from_millis(300));
                let whole = whole_bodies(&seen, &path);
                assert!(
                    status == Some(400) && whole.is_empty(),
                    "{path}: content-length {declared} with DATA {parts:?}: {status:?}, the \
                     upstream took it as a whole body: {whole:?}"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}
