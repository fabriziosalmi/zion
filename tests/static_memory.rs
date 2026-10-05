// SPDX-License-Identifier: Apache-2.0
//! What one client can make a static route hold in memory (#562), with the real binary.
//!
//! Every request for a file reads its own copy, and one HTTP/2 connection carries 128
//! requests. While a file of up to 64 MiB was read whole before the first byte was sent, a
//! single connection asking 100 times for a 32 MiB file made the server hold 3.2 GB, for as
//! long as the client cared not to read. A file is now streamed unless it is small, so each
//! request holds a bounded amount whatever the file's size.
//!
//! Unix only (the process's memory is read from `/proc`, `top` or `ps`). Like the drain tests, a missing `openssl` (for a
//! throwaway certificate) skips with a message.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod common;
use common::free_port;

const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const GOAWAY: u8 = 0x7;
/// The file every stream asks for.
const FILE_BYTES: usize = 32 * 1024 * 1024;
/// Streams on the one connection (the server allows 128).
const STREAMS: u32 = 100;
/// What the server may grow by while it holds them. Measured: about 100 MiB with the file
/// streamed, 3.2 GiB (the file, 100 times) when it was read whole.
const GROWTH_LIMIT_MIB: u64 = 512;

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

impl Zion {
    /// Start zion with a static route over a directory holding `big.bin`; `None` when
    /// `openssl` is unavailable.
    fn start() -> Option<Zion> {
        let (http, https) = (free_port(), free_port());
        let dir =
            std::env::temp_dir().join(format!("zion-static-mem-{}-{http}", std::process::id()));
        std::fs::create_dir_all(dir.join("www")).unwrap();
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
        std::fs::write(dir.join("www/big.bin"), noise(FILE_BYTES)).unwrap();
        let cfg = dir.join("zion.toml");
        std::fs::write(
            &cfg,
            format!(
                "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
                 [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\
                 [[route]]\npath = \"/files/{{*rest}}\"\nmode = \"static\"\nserve_dir = \"{}\"\n",
                cert.display(),
                key.display(),
                dir.join("www").display()
            ),
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
        let zion = Zion { child, https, dir };
        let deadline = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(("127.0.0.1", https)).is_err() {
            assert!(Instant::now() < deadline, "zion did not start listening");
            std::thread::sleep(Duration::from_millis(100));
        }
        Some(zion)
    }

    fn memory_mib(&self) -> u64 {
        common::process_memory_mib(self.child.id())
    }
}

/// Bytes that do not compress: an operating system that compresses idle memory would
/// otherwise hide a hundred copies of a file of one repeated byte.
fn noise(len: usize) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

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

/// The type and stream of the next HTTP/2 frame, its payload read and dropped; `None` on
/// EOF, reset or read timeout.
fn next_frame(s: &mut impl Read) -> Option<(u8, u32)> {
    let mut h = [0u8; 9];
    s.read_exact(&mut h).ok()?;
    let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).ok()?;
    Some((
        h[3],
        u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff,
    ))
}

/// One connection, 100 requests for a 32 MiB file, and a client that then stops reading:
/// HTTP/2 flow control lets the server send it 64 KiB in all, so everything else the server
/// has read for those responses stays in its memory until the client moves. That must be a
/// bounded amount per request, not the file.
#[test]
fn a_client_cannot_make_the_server_hold_a_file_once_per_request() {
    let Some(zion) = Zion::start() else {
        return;
    };
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let before = zion.memory_mib();

    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(("127.0.0.1", zion.https)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let conn = rustls::ClientConnection::new(
        Arc::new(cfg),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    // The preface, SETTINGS, and GET /files/big.bin on 100 streams (HPACK: :method GET,
    // :scheme https, then :path and :authority as literals).
    let path = b"/files/big.bin";
    let mut hpack = vec![0x82, 0x87, 0x44, path.len() as u8];
    hpack.extend_from_slice(path);
    hpack.extend_from_slice(&[0x41, 9]);
    hpack.extend_from_slice(b"localhost");
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(SETTINGS, 0, 0, &[]));
    for i in 0..STREAMS {
        out.extend(frame(HEADERS, 0x5, 1 + 2 * i, &hpack));
    }
    tls.write_all(&out).unwrap();
    tls.flush().unwrap();

    // Read until every response has begun (its HEADERS arrived): by then the server has
    // opened, and under the old behaviour read, the file for each. Then read nothing more.
    let mut begun = std::collections::HashSet::new();
    while begun.len() < STREAMS as usize {
        match next_frame(&mut tls) {
            Some((HEADERS, stream)) => {
                begun.insert(stream);
            }
            Some((GOAWAY, _)) => panic!("zion sent GOAWAY"),
            Some(_) => {}
            None => panic!(
                "the connection ended with {} of {STREAMS} responses begun",
                begun.len()
            ),
        }
    }

    // The highest the process gets while the client holds the streams.
    let mut peak = before;
    for _ in 0..4 {
        std::thread::sleep(Duration::from_millis(500));
        peak = peak.max(zion.memory_mib());
    }
    let growth = peak.saturating_sub(before);
    eprintln!("memory: {before} MiB before, {peak} MiB holding {STREAMS} streams");
    assert!(
        growth < GROWTH_LIMIT_MIB,
        "holding {STREAMS} requests for a {} MiB file grew the server by {growth} MiB \
         ({before} -> {peak}): the file is being read whole for each request",
        FILE_BYTES / (1024 * 1024)
    );
    drop(tls);
}
