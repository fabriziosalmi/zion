//! Shutdown contract: on SIGTERM zion must not sit out the idle timeout of keep-alive
//! connections, and must not cut a request being served. An idle connection is closed at once
//! (HTTP/1) or told `GOAWAY` (HTTP/2), so a deploy takes as long as the work in flight, not as
//! long as the slowest idle client. Runs the real binary; Unix only (SIGTERM). Like the admin
//! API tests, a missing `openssl` (needed for a throwaway certificate) skips with a message.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Zion {
    child: Child,
    http: u16,
    https: u16,
    _dir: std::path::PathBuf,
}
impl Drop for Zion {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Zion {
    /// Start zion in front of `upstream` (a port), or `None` when `openssl` is unavailable.
    fn start(upstream: u16) -> Option<Zion> {
        let (http, https) = (free_port(), free_port());
        let dir = std::env::temp_dir().join(format!("zion-drain-{}-{http}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // a throwaway self-signed certificate (the repo tracks no key material); the SAN makes
        // it an X.509 v3 certificate, which rustls requires
        let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
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
        let cfg = dir.join("zion.toml");
        std::fs::write(
            &cfg,
            format!(
                r#"
[server]
listen_http = "127.0.0.1:{http}"
listen_https = "127.0.0.1:{https}"
[tls]
cert_path = "{cert}"
key_path = "{key}"
hot_reload = false
[upstreams]
backend = "http://127.0.0.1:{upstream}"
[[route]]
path = "/{{*rest}}"
upstream = "backend"
"#,
                http = http,
                https = https,
                cert = cert.display(),
                key = key.display(),
                upstream = upstream,
            )
            .replace('\\', "/"),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_zion"))
            .env("ZION_CONFIG", &cfg)
            .env("ZION_BOOT_FAST", "1")
            .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zion");
        Some(Zion {
            child,
            http,
            https,
            _dir: dir,
        })
    }

    fn wait_listening(&self, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "zion did not start listening");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn sigterm(&self) {
        let ok = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok);
    }

    /// Wait for exit; fail if it takes longer than `limit`.
    fn wait_exit(&mut self, limit: Duration) -> std::process::ExitStatus {
        let t = Instant::now();
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(
                t.elapsed() < limit,
                "zion was still running {:?} after SIGTERM: a connection held the drain",
                t.elapsed()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A backend that answers every request after `delay`.
fn slow_upstream(delay: Duration) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                std::thread::sleep(delay);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                );
            });
        }
    });
    port
}

#[test]
fn an_idle_keep_alive_connection_does_not_delay_shutdown() {
    let Some(mut zion) = Zion::start(1) else {
        return;
    };
    zion.wait_listening(zion.http);
    let mut conn = TcpStream::connect(("127.0.0.1", zion.http)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();

    // read the whole response, and check the connection is really being kept alive: otherwise
    // an early exit would prove nothing about the drain
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let (head_end, body_len) = loop {
        let n = conn
            .read(&mut buf)
            .expect("a response on the plain-HTTP listener");
        assert!(
            n > 0,
            "the server closed the connection before a full response"
        );
        got.extend_from_slice(&buf[..n]);
        if let Some(p) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..p]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            assert!(
                !head.contains("connection: close"),
                "not a keep-alive connection: {head}"
            );
            if got.len() >= p + 4 + len {
                break (p + 4, len);
            }
        }
    };
    assert_eq!(got.len(), head_end + body_len, "the response is complete");
    std::thread::sleep(Duration::from_millis(300)); // idle, kept alive

    zion.sigterm();
    let status = zion.wait_exit(Duration::from_secs(8));
    assert!(
        status.success(),
        "a graceful shutdown exits 0, got {status:?}"
    );
    // the idle connection was closed by zion, not left to time out
    let mut rest = Vec::new();
    let _ = conn.read_to_end(&mut rest);
}

// ── HTTP/2 over TLS ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
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

fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(9 + payload.len());
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    f.push(ty);
    f.push(flags);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// One HTTP/2 frame: (type, flags, stream, payload), or `None` on EOF / read timeout.
fn read_frame(s: &mut impl Read) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut h = [0u8; 9];
    s.read_exact(&mut h).ok()?;
    let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).ok()?;
    Some((
        h[3],
        h[4],
        u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff,
        payload,
    ))
}

#[test]
fn an_http2_connection_gets_goaway_and_its_request_in_flight_is_finished() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let upstream = slow_upstream(Duration::from_millis(1500));
    let Some(mut zion) = Zion::start(upstream) else {
        return;
    };
    zion.wait_listening(zion.https);

    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(("127.0.0.1", zion.https)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let conn = rustls::ClientConnection::new(
        Arc::new(cfg),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    // preface, empty SETTINGS, then GET / on stream 1 (HPACK: :method GET, :scheme https,
    // :path /, :authority x)
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(0x4, 0, 0, &[]));
    out.extend(frame(0x1, 0x5, 1, &[0x82, 0x87, 0x84, 0x41, 0x01, b'x']));
    tls.write_all(&out).unwrap();
    tls.flush().unwrap();

    // let the request reach the (slow) upstream, then ask zion to shut down mid-request
    let t0 = Instant::now();
    let mut sigterm_sent = false;
    let (mut goaway, mut response_done, mut closed) = (false, false, false);
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && !closed {
        if !sigterm_sent && t0.elapsed() > Duration::from_millis(500) {
            zion.sigterm();
            sigterm_sent = true;
        }
        match read_frame(&mut tls) {
            Some((0x7, _, _, _)) => goaway = true,
            Some((0x6, flags, _, payload)) if flags & 1 == 0 => {
                // a server PING (part of the two-phase GOAWAY): a real client acks it
                tls.write_all(&frame(0x6, 0x1, 0, &payload)).unwrap();
                tls.flush().unwrap();
            }
            Some((0x1 | 0x0, flags, 1, _)) if flags & 1 == 1 => response_done = true,
            Some(_) => {}
            None => {
                // read timeout or EOF: EOF means zion closed the connection
                let mut probe = [0u8; 1];
                if matches!(tls.sock.peek(&mut probe), Ok(0)) {
                    closed = true;
                }
            }
        }
    }
    assert!(sigterm_sent && goaway, "zion sent GOAWAY after SIGTERM");
    assert!(
        response_done,
        "the stream that was in flight when the drain began was finished, not cut"
    );
    assert!(closed, "and zion then closed the connection");
    let status = zion.wait_exit(Duration::from_secs(8));
    assert!(
        status.success(),
        "a graceful shutdown exits 0, got {status:?}"
    );
}
