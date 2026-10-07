// SPDX-License-Identifier: Apache-2.0
//! A request with a body, proxied to an HTTP/2 upstream, is not held back by Nagle's
//! algorithm (the real binary against an in-process TLS + HTTP/2 upstream).
//!
//! zion writes such a request as several small frames: the HEADERS, then the DATA. With
//! `TCP_NODELAY` off on the pooled upstream socket the second frame waits for the ACK of the
//! first, and the peer's delayed ACK holds that back for about 40 ms on Linux. Measured with
//! eight concurrent gRPC unary calls: 190 calls a second through zion against 14,000 direct.
//! The stall is Linux's; on other systems this test runs and measures but asserts nothing.
//!
//! Unix only, and skipped when `openssl` or `curl` is not installed.
#![cfg(unix)]

use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

mod common;
use common::free_port;

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn openssl(args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A TLS upstream that speaks only HTTP/2 and answers every request (a body read in full)
/// with two bytes. Runs on its own thread for the life of the test; returns its port.
fn h2_upstream(cert: &Path, key: &Path) -> u16 {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&fs::read(cert).unwrap())
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(&fs::read(key).unwrap()).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let port = free_port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .unwrap();
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                // The upstream's own sockets answer promptly: only zion's are under test.
                let _ = tcp.set_nodelay(true);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service =
                        service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                            let _ = req.into_body().collect().await;
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from_static(b"ok"),
                            )))
                        });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
    });
    port
}

#[test]
fn a_request_with_a_body_is_not_delayed_on_its_way_to_an_h2_upstream() {
    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("SKIP: curl not available");
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "zion-upstream-latency-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    let made = openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        // OpenSSL 3 makes a self-signed certificate a CA by default, which rustls refuses
        // as a server certificate (LibreSSL does not).
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-keyout",
        &key.to_string_lossy(),
        "-out",
        &cert.to_string_lossy(),
    ]);
    if !made {
        eprintln!("SKIP: openssl could not make a certificate");
        return;
    }
    let upstream = h2_upstream(&cert, &key);
    let https_port = free_port();
    let d = dir.to_string_lossy();
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
             [tls]\ncert_path = \"{d}/c.pem\"\nkey_path = \"{d}/k.pem\"\nhot_reload = false\n\n\
             [upstream.backend]\nurl = \"https://localhost:{upstream}\"\nca_path = \"{d}/c.pem\"\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n",
            free_port()
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
    let _z = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https_port)).is_err() {
        assert!(Instant::now() < deadline, "zion never listened");
        std::thread::sleep(Duration::from_millis(100));
    }

    const REQUESTS: usize = 40;
    let url = format!("https://127.0.0.1:{https_port}/echo");
    // One curl, one connection, the requests one after another: each is a POST with a small
    // body, so zion sends the upstream HEADERS and then DATA.
    let post = |n: usize| {
        let started = Instant::now();
        let mut cmd = Command::new("curl");
        for i in 0..n {
            if i > 0 {
                cmd.arg("--next");
            }
            cmd.args([
                "-sk",
                "--http1.1",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}\n",
            ])
            .args(["-X", "POST", "-d", "{\"a\":1}", &url]);
        }
        let out = cmd.output().expect("curl");
        let codes = String::from_utf8_lossy(&out.stdout).into_owned();
        (started.elapsed(), codes)
    };
    // Warm up: the first requests open the connections and may wait for the first probe.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (_, codes) = post(1);
        if codes.trim() == "200" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the upstream never answered: {codes:?}\n{}",
            fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let (elapsed, codes) = post(REQUESTS);
    assert_eq!(
        codes.lines().filter(|c| *c == "200").count(),
        REQUESTS,
        "{codes}"
    );
    eprintln!(
        "{REQUESTS} POSTs with a body in {:.0} ms ({:.1} ms each)",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1000.0 / REQUESTS as f64
    );
    if cfg!(target_os = "linux") {
        // 40 ms each (the stall) would be 1.6 s; without it a request is a millisecond or two.
        assert!(
            elapsed < Duration::from_millis(800),
            "{REQUESTS} POSTs took {elapsed:?}: about 40 ms each is Nagle holding the DATA frame \
             behind the HEADERS frame on the upstream socket"
        );
    }
    let _ = fs::remove_dir_all(dir);
}
