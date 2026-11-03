// SPDX-License-Identifier: Apache-2.0
//! JA4 / User-Agent consistency check (#720), against the real binary with real TLS.
//!
//! The JA4s are not written down here: two clients with different ClientHellos (one default
//! rustls, one restricted to a single cipher suite) connect to a zion in `shadow` with no
//! allowlist, and the backend sends back the `X-Client-TLS-JA4` zion attested for each. Those
//! measured values then go into the allowlist of the next zion, the first as a "tool", the second
//! as a "browser".
//!
//! Cases, each on its own zion: `enforce` refuses a browser User-Agent on the tool fingerprint
//! (403) and lets every other pairing through; `shadow` lets all through; with no `ua_check`
//! block the same request goes through (the break-test: remove the gate and the 403 is gone).
//!
//! Unix only, and skipped when `openssl` is not installed (it makes the throwaway certificate).
#![cfg(all(unix, feature = "tls-fingerprint"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// A backend that answers 200 and puts the `X-Client-TLS-JA4` it received in the body ("none"
/// when absent). Returns its port; the thread lives until the test process ends.
fn backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let ja4 = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("x-client-tls-ja4")
                            .then(|| v.trim().to_string())
                    })
                    .unwrap_or_else(|| "none".into());
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ja4}",
                    ja4.len()
                );
            });
        }
    });
    port
}

/// Start zion with `fingerprint` appended inside `[tls]`; `None` when `openssl` is unavailable.
fn start(backend_port: u16, fingerprint: &str) -> Option<Zion> {
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-uacheck-{}-{http}", std::process::id()));
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
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n{fingerprint}\n\
             [upstreams]\nbackend = \"http://127.0.0.1:{backend_port}\"\n\
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
    let deadline = Instant::now() + Duration::from_secs(20);
    while StdTcpStream::connect(("127.0.0.1", http)).is_err() {
        assert!(
            Instant::now() < deadline,
            "zion did not start listening; log: {}",
            std::fs::read_to_string(zion.dir.join("zion.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(300));
    Some(zion)
}

/// The two ClientHellos: `A` is rustls' default, `B` offers a single cipher suite. Their JA4s
/// differ (the cipher count and the cipher hash), which the test checks rather than assumes.
#[derive(Clone, Copy)]
enum Client {
    A,
    B,
}

fn connector(client: Client) -> tokio_rustls::TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if let Client::B = client {
        provider
            .cipher_suites
            .retain(|s| s.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
        assert_eq!(provider.cipher_suites.len(), 1);
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    // A resumed handshake adds a pre_shared_key extension and so changes the JA4: every
    // request here must present the same ClientHello.
    tls.resumption = rustls::client::Resumption::disabled();
    tokio_rustls::TlsConnector::from(Arc::new(tls))
}

/// One GET over a fresh TLS connection; `(status, body)`.
async fn get(zion: &Zion, client: Client, user_agent: &str) -> (u16, String) {
    get_with(zion, client, &[user_agent]).await
}

/// As [`get`], with one `User-Agent` header per entry of `user_agents`, in that order.
async fn get_with(zion: &Zion, client: Client, user_agents: &[&str]) -> (u16, String) {
    let headers: String = user_agents
        .iter()
        .map(|ua| format!("User-Agent: {ua}\r\n"))
        .collect();
    let tcp = TcpStream::connect(("127.0.0.1", zion.https)).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector(client).connect(name, tcp).await.unwrap();
    tls.write_all(
        format!("GET /x HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut raw = Vec::new();
    let _ = tls.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {text:?}"));
    let body = text
        .split_once("\r\n\r\n")
        .map(|x| x.1)
        .unwrap_or("")
        .to_string();
    (status, body)
}

const CHROME_UA: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36";

/// Measure the JA4 zion attests for each client.
async fn measure(backend_port: u16) -> Option<(String, String)> {
    let zion = start(backend_port, "[tls.fingerprint]\nmode = \"shadow\"")?;
    let (sa, a) = get(&zion, Client::A, "probe").await;
    let (sb, b) = get(&zion, Client::B, "probe").await;
    assert_eq!((sa, sb), (200, 200));
    for ja4 in [&a, &b] {
        assert!(
            ja4.starts_with('t') && ja4.matches('_').count() == 2,
            "the backend should have received a JA4, got {ja4:?}"
        );
    }
    assert_ne!(
        a, b,
        "the two clients must have different JA4s for this test to mean anything"
    );
    // The JA4 must be stable across connections, or the allowlist below could not match.
    let (_, a2) = get(&zion, Client::A, "probe").await;
    assert_eq!(a, a2, "the same client must keep the same JA4");
    Some((a, b))
}

/// The `[tls.fingerprint]` block naming A as a tool and B as a browser, with `ua_check`.
fn block(a: &str, b: &str, ua_check: &str) -> String {
    format!(
        "[tls.fingerprint]\nmode = \"shadow\"\n\
         allowed = [{{ name = \"tool\", ja4 = \"{a}\" }}, {{ name = \"browser\", ja4 = \"{b}\" }}]\n{ua_check}"
    )
}

const UA_CHECK: &str = "[tls.fingerprint.ua_check]\nmode = \"MODE\"\n\
                        browser_ua = [\"Chrome/\", \"Firefox/\"]\ntool_names = [\"tool\"]";

#[tokio::test(flavor = "multi_thread")]
async fn enforce_refuses_a_browser_user_agent_on_a_tool_fingerprint_and_nothing_else() {
    let bp = backend();
    let Some((a, b)) = measure(bp).await else {
        return;
    };
    let Some(zion) = start(bp, &block(&a, &b, &UA_CHECK.replace("MODE", "enforce"))) else {
        return;
    };
    // The lie: the tool's ClientHello with a browser's User-Agent.
    assert_eq!(get(&zion, Client::A, CHROME_UA).await.0, 403);
    assert_eq!(
        get(&zion, Client::A, "mozilla/5.0 chrome/131").await.0,
        403,
        "case is no way out"
    );
    // The tool honest about itself, and the browser fingerprint with a browser User-Agent.
    assert_eq!(get(&zion, Client::A, "curl/8.5.0").await.0, 200);
    assert_eq!(get(&zion, Client::B, CHROME_UA).await.0, 200);
    // The browser fingerprint with a tool User-Agent is not this check's business.
    assert_eq!(get(&zion, Client::B, "curl/8.5.0").await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_user_agent_header_does_not_hide_a_browser_claim() {
    // The proxy forwards every User-Agent header, so an upstream that reads the last one sees
    // the browser claim. Judging only the first would let the tool through.
    let bp = backend();
    let Some((a, b)) = measure(bp).await else {
        return;
    };
    let Some(zion) = start(bp, &block(&a, &b, &UA_CHECK.replace("MODE", "enforce"))) else {
        return;
    };
    assert_eq!(
        get_with(&zion, Client::A, &["curl/8.5.0", CHROME_UA])
            .await
            .0,
        403
    );
    assert_eq!(
        get_with(&zion, Client::A, &[CHROME_UA, "curl/8.5.0"])
            .await
            .0,
        403
    );
    // Two values, neither claiming a browser: nothing to compare.
    assert_eq!(
        get_with(&zion, Client::A, &["curl/8.5.0", "python-requests/2.31"])
            .await
            .0,
        200
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn shadow_observes_the_mismatch_and_blocks_nothing() {
    let bp = backend();
    let Some((a, b)) = measure(bp).await else {
        return;
    };
    let Some(zion) = start(bp, &block(&a, &b, &UA_CHECK.replace("MODE", "shadow"))) else {
        return;
    };
    assert_eq!(get(&zion, Client::A, CHROME_UA).await.0, 200);
    assert_eq!(get(&zion, Client::B, CHROME_UA).await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_ua_check_block_the_same_request_goes_through() {
    // The break-test of the enforce case: with the gate absent the 403 is gone.
    let bp = backend();
    let Some((a, b)) = measure(bp).await else {
        return;
    };
    let Some(zion) = start(bp, &block(&a, &b, "")) else {
        return;
    };
    assert_eq!(get(&zion, Client::A, CHROME_UA).await.0, 200);
}
