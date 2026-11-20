// SPDX-License-Identifier: Apache-2.0
//! `[tls] client_auth = "required"` holds on HTTP/3 as it does on TCP, against the real binary.
//!
//! The QUIC listener's boot config used to be built apart from the TCP one, from the
//! certificate and key files only: a client with no certificate, refused at the TCP :443
//! handshake, was served over QUIC on UDP :443 (zion has no per-request mTLS check, the
//! handshake is the only gate), until a certificate reload installed the TCP config.
//!
//! `hot_reload = false` keeps the boot config for the whole test. Controls: a client with a
//! certificate from the CA is served on TCP (the CA config is valid) and the no-certificate
//! client is refused on TCP (the gate exists). Over HTTP/3 the no-certificate client is
//! refused, and a client with a certificate is served, with the same
//! `X-Client-Cert-Fingerprint` reaching the upstream as over TCP.
//!
//! Needs `--features http3` and `openssl` (skipped without).
#![cfg(all(unix, feature = "http3"))]

use bytes::Buf;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
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

fn openssl(args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Server cert (`c.pem`/`k.pem`, CN=localhost), a client CA (`ca.pem`/`ca.key`) and a client
/// certificate it signed (`client.pem`/`client.key`, clientAuth).
fn pki(dir: &Path) -> bool {
    let p = |f: &str| dir.join(f).to_string_lossy().into_owned();
    std::fs::write(
        dir.join("ext.cnf"),
        "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n",
    )
    .unwrap();
    openssl(&[
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
        "subjectAltName=DNS:localhost",
        "-keyout",
        &p("k.pem"),
        "-out",
        &p("c.pem"),
    ]) && openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=client-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign",
        "-keyout",
        &p("ca.key"),
        "-out",
        &p("ca.pem"),
    ]) && openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=client",
        "-keyout",
        &p("client.key"),
        "-out",
        &p("client.csr"),
    ]) && openssl(&[
        "x509",
        "-req",
        "-in",
        &p("client.csr"),
        "-CA",
        &p("ca.pem"),
        "-CAkey",
        &p("ca.key"),
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        &p("ext.cnf"),
        "-out",
        &p("client.pem"),
    ])
}

/// What the upstream saw of each request: its `X-Client-Cert-Fingerprint`, if any.
type Seen = Arc<Mutex<Vec<Option<String>>>>;

/// An HTTP/1.1 upstream that answers every request `200 upstream-secret` and records it.
fn upstream(seen: Seen) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut fp = None;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = h.split_once(':') {
                        if name.eq_ignore_ascii_case("x-client-cert-fingerprint") {
                            fp = Some(value.trim().to_string());
                        }
                    }
                }
                seen.lock().unwrap().push(fp);
                let mut s = s;
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 15\r\nconnection: close\r\n\r\nupstream-secret",
                );
            });
        }
    });
    port
}

fn boot(dir: &Path, upstream: u16) -> Option<(Daemon, u16)> {
    if !pki(dir) {
        common::skip("openssl could not make the test certificates");
        return None;
    }
    let https = free_port();
    let d = dir.to_string_lossy();
    std::fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
             [tls]\ncert_path = \"{d}/c.pem\"\nkey_path = \"{d}/k.pem\"\nhot_reload = false\n\
             client_auth = \"required\"\nclient_ca_path = \"{d}/ca.pem\"\n\
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
        if log.contains("listening HTTP/3") && log.contains("mtls: client auth=required") {
            return Some((daemon, https));
        }
        assert!(Instant::now() < deadline, "no HTTP/3 listener:\n{log}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A rustls client config, presenting the test's client certificate when `client` is given.
fn client_config(client: Option<&Path>) -> rustls::ClientConfig {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let b = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert));
    match client {
        None => b.with_no_client_auth(),
        Some(dir) => {
            let certs = CertificateDer::pem_file_iter(dir.join("client.pem"))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key = PrivateKeyDer::from_pem_file(dir.join("client.key")).unwrap();
            b.with_client_auth_cert(certs, key).unwrap()
        }
    }
}

/// GET `/secret` over TLS on TCP: `Ok(status)`, or `Err` with the TLS / IO error when the
/// handshake is refused.
fn tcp_get(port: u16, client: Option<&Path>) -> Result<u16, String> {
    let conn = rustls::ClientConnection::new(
        Arc::new(client_config(client)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    tls.write_all(b"GET /secret HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(2).any(|w| w == b"\r\n") {
        match tls.read(&mut chunk) {
            Ok(0) => return Err(format!("closed, got {:?}", String::from_utf8_lossy(&buf))),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(e.to_string()),
        }
    }
    let text = String::from_utf8_lossy(&buf);
    text.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("no status in {text:?}"))
}

/// GET `/secret` over HTTP/3: `Ok(status)`, or `Err` when the handshake or the request is
/// refused.
async fn h3_get(port: u16, client: Option<&Path>) -> Result<u16, String> {
    let mut tls = client_config(client);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(qc)));
    let conn = ep
        .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
        .unwrap()
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| format!("h3 setup: {e}"))?;
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = hyper::Request::get("https://localhost/secret")
        .body(())
        .unwrap();
    let mut stream = send
        .send_request(req)
        .await
        .map_err(|e| format!("send: {e:?}"))?;
    stream
        .finish()
        .await
        .map_err(|e| format!("finish: {e:?}"))?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| format!("response: {e:?}"))?;
    while let Ok(Some(mut c)) = stream.recv_data().await {
        c.advance(c.remaining());
    }
    drive.abort();
    Ok(resp.status().as_u16())
}

async fn h3_get_within(port: u16, client: Option<&Path>) -> Result<u16, String> {
    tokio::time::timeout(Duration::from_secs(10), h3_get(port, client))
        .await
        .unwrap_or_else(|_| Err("timeout".into()))
}

#[tokio::test(flavor = "multi_thread")]
async fn client_auth_required_holds_over_http3_from_boot() {
    let dir = std::env::temp_dir().join(format!(
        "zion-h3-mtls-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen: Seen = Arc::default();
    let Some((_daemon, port)) = boot(&dir, upstream(seen.clone())) else {
        return;
    };
    let count = || seen.lock().unwrap().len();

    // Control 1: TCP with a certificate from the client CA is served, and attested.
    assert_eq!(
        tcp_get(port, Some(&dir)),
        Ok(200),
        "the mTLS config itself works on TCP"
    );
    let tcp_fp = seen.lock().unwrap().last().cloned().flatten();
    assert!(
        tcp_fp.as_deref().is_some_and(|f| f.starts_with("sha256:")),
        "TCP attests the client certificate: {tcp_fp:?}"
    );

    // Control 2: TCP with no certificate is refused at the handshake.
    let before = count();
    // (Only whether it was refused goes in the messages: the TLS error text is not needed.)
    let tcp_refused = tcp_get(port, None).is_err();
    assert!(
        tcp_refused,
        "client_auth = required refuses a client with no certificate on TCP"
    );
    assert_eq!(count(), before, "nothing reached the upstream over TCP");

    // The same client over QUIC on UDP :443 is refused too.
    let before = count();
    let h3 = h3_get_within(port, None).await;
    assert!(
        h3.is_err() && count() == before,
        "mTLS bypass over HTTP/3: the client has no certificate (refused on TCP), yet over \
         QUIC it got status {:?} and {} request(s) reached the upstream",
        h3.as_ref().ok(),
        count() - before
    );

    // A client with a certificate is served over HTTP/3, attested like on TCP.
    let before = count();
    let h3 = h3_get_within(port, Some(&dir)).await;
    assert_eq!(h3, Ok(200), "HTTP/3 with a client certificate");
    assert_eq!(count(), before + 1);
    let h3_fp = seen.lock().unwrap().last().cloned().flatten();
    assert_eq!(
        h3_fp, tcp_fp,
        "the upstream gets the same X-Client-Cert-Fingerprint over HTTP/3 as over TCP"
    );
    let _ = std::fs::remove_dir_all(dir);
}
