// SPDX-License-Identifier: Apache-2.0
//! A request target whose authority carries userinfo is a 400 on every listener and protocol
//! that carries one, against the real binary: HTTP/1.1 and HTTP/1.0 absolute-form on the TLS
//! listener and on `:80` (its redirect, and the ACME fallback that forwards on its own), HTTP/2
//! over TLS and h2c on `:80` (`:authority`), and HTTP/3 with `--features http3`. `/healthz` and
//! `/readyz` included: the TLS listener answers them on a fast path before the pipeline, and a
//! target with userinfo does not take it.
//!
//! RFC 9110 §4.2.4: userinfo is how a link hides its real host (`http://shop.example@evil.example/`
//! goes to evil.example), and RFC 9113 §8.3.1 and RFC 9114 §4.3.1 forbid it in `:authority`.
//! hyper, h2 and h3 all accept it. Let through, such a request found no host to be routed or
//! cached on and was forwarded on the shared layer, and the origin was told its authority as
//! received in `X-Forwarded-Host`: a host its links would send browsers to, or the password.
//! Every case here asserts both halves: the status zion answers, and that the origin never saw
//! the request.
//!
//! Unix only, and skipped when `openssl` is not installed (it makes the certificate).
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::free_port;

struct Daemon {
    child: Child,
    dir: PathBuf,
}
impl Drop for Daemon {
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

fn client_tls(alpn: &[u8]) -> rustls::ClientConfig {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    tls
}

/// An HTTP/1.1 origin that records the head (start-line and header lines) of every request it
/// is sent and answers `ok`, on a keep-alive connection.
fn origin() -> (u16, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let Ok(mut w) = s.try_clone() else { return };
                let mut r = BufReader::new(s);
                loop {
                    let mut head = String::new();
                    let mut length = 0usize;
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let line = line.trim_end();
                        if line.is_empty() {
                            if head.is_empty() {
                                continue;
                            }
                            break;
                        }
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            length = v.trim().parse().unwrap_or(0);
                        }
                        if !head.is_empty() {
                            head.push('\n');
                        }
                        head.push_str(line);
                    }
                    let mut body = vec![0u8; length];
                    let _ = r.read_exact(&mut body);
                    log.lock().unwrap().push(head);
                    if w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (port, seen)
}

/// The head the origin recorded for the request whose start-line begins with `prefix`, if any.
fn origin_head(seen: &Arc<Mutex<Vec<String>>>, prefix: &str) -> Option<String> {
    seen.lock()
        .unwrap()
        .iter()
        .find(|h| h.starts_with(prefix))
        .cloned()
}

/// Boot zion with one route to the origin on both listeners (and HTTP/3 when built with it);
/// `(daemon, http port, https port)`, or None when openssl is missing.
fn boot(origin_port: u16) -> Option<(Daemon, u16, u16)> {
    let dir = std::env::temp_dir().join(format!(
        "zion-userinfo-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
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
        .arg(dir.join("k.pem"))
        .arg("-out")
        .arg(dir.join("c.pem"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !made {
        common::skip("openssl could not make a certificate");
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    let (http, https) = (free_port(), free_port());
    let d = dir.to_string_lossy();
    std::fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
             [tls]\ncert_path = \"{d}/c.pem\"\nkey_path = \"{d}/k.pem\"\nhot_reload = false\n\
             [upstreams]\nbe = \"http://127.0.0.1:{origin_port}\"\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"be\"\nmode = \"standard\"\n"
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
    let daemon = Daemon { child, dir };
    let deadline = Instant::now() + Duration::from_secs(20);
    for port in [http, https] {
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "zion never listened on {port}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    #[cfg(feature = "http3")]
    common::wait_for_log(
        &daemon.dir.join("daemon.log"),
        "listening HTTP/3",
        Duration::from_secs(20),
    );
    Some((daemon, http, https))
}

/// The status line zion answers `raw` with: over TLS (ALPN http/1.1) to `port`, or in clear.
async fn send_raw(port: u16, tls: bool, raw: &[u8]) -> String {
    async fn status_line<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        mut s: S,
        raw: &[u8],
    ) -> String {
        s.write_all(raw).await.unwrap();
        s.flush().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.windows(2).any(|w| w == b"\r\n") {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&got).into_owned();
        text.lines().next().unwrap_or_default().to_string()
    }
    let fut = async {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        if !tls {
            return status_line(tcp, raw).await;
        }
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(b"http/1.1")));
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let s = connector.connect(name, tcp).await.unwrap();
        status_line(s, raw).await
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .unwrap_or_default()
}

/// The status zion answers a GET for `uri` with over HTTP/2: over TLS (ALPN h2) to `port`, or
/// h2c with prior knowledge. hyper's client sends the URI's authority as `:authority`, userinfo
/// and all. 0 when the request got no response (a reset stream, a timeout).
async fn h2_get(port: u16, tls: bool, uri: &str) -> u16 {
    async fn get<I>(io: I, uri: &str) -> u16
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut send, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::get(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let Ok(resp) = send.send_request(req).await else {
            return 0;
        };
        let status = resp.status().as_u16();
        let _ = resp.into_body().collect().await;
        status
    }
    let fut = async {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        if !tls {
            return get(tcp, uri).await;
        }
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(b"h2")));
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let s = connector.connect(name, tcp).await.unwrap();
        assert_eq!(s.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        get(s, uri).await
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .unwrap_or(0)
}

/// The status zion answers a GET over HTTP/3 with: `uri` as the target (its authority becomes
/// `:authority`), and `host` as a `host` field when given. 0 when the request got no response.
#[cfg(feature = "http3")]
async fn h3_get(port: u16, uri: &str, host: Option<&str>) -> u16 {
    use bytes::Buf;
    let fut = async {
        let qc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(b"h3")).unwrap();
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
        let mut req = hyper::Request::get(uri);
        if let Some(h) = host {
            req = req.header("host", h);
        }
        let Ok(mut stream) = send.send_request(req.body(()).unwrap()).await else {
            return 0;
        };
        if stream.finish().await.is_err() {
            return 0;
        }
        let Ok(resp) = stream.recv_response().await else {
            return 0;
        };
        while let Ok(Some(mut c)) = stream.recv_data().await {
            c.advance(c.remaining());
        }
        resp.status().as_u16()
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_target_with_userinfo_is_refused_on_every_listener_and_never_forwarded() {
    let (origin_port, seen) = origin();
    let Some((daemon, http, https)) = boot(origin_port) else {
        return;
    };
    let wait_for_origin = |prefix: &str| {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(h) = origin_head(&seen, prefix) {
                return h.to_ascii_lowercase();
            }
            assert!(
                Instant::now() < deadline,
                "{prefix:?} never reached the origin: {:?}",
                seen.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    };

    // Controls, without userinfo: the same shapes are served, and forwarded with the target's
    // authority as `X-Forwarded-Host`.
    let line = send_raw(
        https,
        true,
        b"GET http://a.example/c-h1 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(line.starts_with("HTTP/1.1 200"), "TLS HTTP/1.1: {line:?}");
    let head = wait_for_origin("GET /c-h1 ");
    assert!(head.contains("\nx-forwarded-host: a.example"), "{head}");
    assert_eq!(h2_get(https, true, "https://a.example/c-h2").await, 200);
    wait_for_origin("GET /c-h2 ");
    let line = send_raw(
        http,
        false,
        b"GET http://a.example/.well-known/acme-challenge/c-80 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        line.starts_with("HTTP/1.1 200"),
        ":80 ACME fallback: {line:?}"
    );
    wait_for_origin("GET /.well-known/acme-challenge/c-80 ");
    let line = send_raw(
        http,
        false,
        b"GET http://a.example/c-redirect HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(line.starts_with("HTTP/1.1 301"), ":80 redirect: {line:?}");
    assert_eq!(
        h2_get(
            http,
            false,
            "http://a.example/.well-known/acme-challenge/c-h2c"
        )
        .await,
        200
    );
    wait_for_origin("GET /.well-known/acme-challenge/c-h2c ");
    // The TLS listener's health fast path answers a probe without userinfo, in origin-form, in
    // absolute-form and over HTTP/2.
    let line = send_raw(
        https,
        true,
        b"GET /healthz HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(line.starts_with("HTTP/1.1 200"), "TLS /healthz: {line:?}");
    let line = send_raw(
        https,
        true,
        b"GET http://a.example/readyz HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(line.starts_with("HTTP/1.1 200"), "TLS /readyz: {line:?}");
    assert_eq!(h2_get(https, true, "https://a.example/healthz").await, 200);

    // With userinfo: a 400 on each, and the origin never sees the request. Every case runs
    // before anything is asserted, so a failure lists each listener and protocol that let one in.
    let mut wrong = Vec::new();
    let raw_cases: &[(&str, u16, bool, &[u8])] = &[
        (
            "TLS HTTP/1.1, a familiar host in front of the real one",
            https,
            true,
            b"GET http://a.example@evil.example/u-h1-hide HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
        ),
        (
            "TLS HTTP/1.1, a password",
            https,
            true,
            b"GET http://user:pass@a.example/u-h1-pass HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
        ),
        (
            "TLS HTTP/1.0, no Host",
            https,
            true,
            b"GET http://user:pass@a.example/u-h10 HTTP/1.0\r\n\r\n",
        ),
        (
            "TLS HTTP/1.1, /healthz (the health fast path)",
            https,
            true,
            b"GET http://user:pass@a.example/healthz HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
        ),
        (
            "TLS HTTP/1.1, /readyz (the health fast path)",
            https,
            true,
            b"GET http://a.example@evil.example/readyz HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
        ),
        (
            ":80 HTTP/1.1, the ACME fallback that forwards",
            http,
            false,
            b"GET http://user:pass@a.example/.well-known/acme-challenge/u-80 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
        ),
        (
            ":80 HTTP/1.0, the ACME fallback that forwards",
            http,
            false,
            b"GET http://a.example@evil.example/.well-known/acme-challenge/u-80-10 HTTP/1.0\r\n\r\n",
        ),
        (
            ":80 HTTP/1.1, the redirect",
            http,
            false,
            b"GET http://a.example@evil.example/u-redirect HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
        ),
    ];
    for (name, port, tls, raw) in raw_cases {
        let line = send_raw(*port, *tls, raw).await;
        if !(line.starts_with("HTTP/1.1 400") || line.starts_with("HTTP/1.0 400")) {
            wrong.push(format!("{name}: {line:?}"));
        }
    }
    let h2_cases = [
        (
            "HTTP/2 over TLS, :authority a.example@evil.example",
            https,
            true,
            "https://a.example@evil.example/u-h2-hide",
        ),
        (
            "HTTP/2 over TLS, :authority user:pass@a.example",
            https,
            true,
            "https://user:pass@a.example/u-h2-pass",
        ),
        (
            "HTTP/2 over TLS, /healthz (the health fast path)",
            https,
            true,
            "https://user:pass@a.example/healthz",
        ),
        (
            "h2c on :80, the ACME fallback",
            http,
            false,
            "http://user:pass@a.example/.well-known/acme-challenge/u-h2c",
        ),
    ];
    for (name, port, tls, uri) in h2_cases {
        let status = h2_get(port, tls, uri).await;
        if status != 400 {
            wrong.push(format!("{name}: {status}"));
        }
    }

    #[cfg(feature = "http3")]
    {
        assert_eq!(h3_get(https, "https://localhost/c-h3", None).await, 200);
        wait_for_origin("GET /c-h3 ");
        let h3_cases = [
            (
                "HTTP/3, :authority user:pass@localhost",
                "https://user:pass@localhost/u-h3-pass",
                None,
            ),
            (
                "HTTP/3, :authority localhost@evil.example",
                "https://localhost@evil.example/u-h3-hide",
                None,
            ),
            (
                "HTTP/3, :authority user:pass@localhost on /healthz",
                "https://user:pass@localhost/healthz",
                None,
            ),
            // h3 makes a `host` field sent without `:authority` the target's authority.
            (
                "HTTP/3, host user:pass@localhost and no :authority",
                "/u-h3-host",
                Some("user:pass@localhost"),
            ),
        ];
        for (name, uri, host) in h3_cases {
            let status = h3_get(https, uri, host).await;
            if status != 400 {
                wrong.push(format!("{name}: {status}"));
            }
        }
    }

    std::thread::sleep(Duration::from_millis(300));
    let leaked: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|h| h.contains("/u-") || h.contains('@'))
        .cloned()
        .collect();
    assert!(
        wrong.is_empty() && leaked.is_empty(),
        "a target with userinfo was not refused with a 400:\n{}\nand reached the origin as:\n{}",
        wrong.join("\n"),
        leaked.join("\n---\n")
    );
    drop(daemon);
}
