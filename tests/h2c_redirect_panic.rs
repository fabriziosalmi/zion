// SPDX-License-Identifier: Apache-2.0
//! An h2c request on :80 whose `:path` carries a raw DEL byte (0x7F) gets a 400 and does not
//! crash zion, with the real binary.
//!
//! The :80 listener speaks HTTP/2 to any client that opens with the preface (no TLS, "prior
//! knowledge"). h2 accepts 0x7F in `:path`, and so does `http`'s `PathAndQuery`; the 301
//! handler folded it into the `Location` it built, `HeaderValue` refused it, and an
//! `.unwrap()` on the response builder panicked. Under the release profile
//! (`panic = "abort"`) one unauthenticated request aborted the whole process. In a debug
//! build the panic hook still writes its record to the last-gasp file, which is what this
//! test watches.
//!
//! Like the other binary-booting tests, a missing `openssl` (for a throwaway certificate)
//! skips with a message.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const GOAWAY: u8 = 0x7;
const END_STREAM: u8 = 0x1;

struct Zion {
    child: Child,
    http: u16,
    gasp: PathBuf,
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
    /// Start zion with a plaintext :80 listener (the one that speaks h2c) and a dummy TLS
    /// listener (so the mandatory `listen_https` / cert config is satisfied). `None` when
    /// `openssl` is unavailable.
    fn start() -> Option<Zion> {
        let (http, https) = (free_port(), free_port());
        let dir = std::env::temp_dir().join(format!("zion-h2c-del-{}-{http}", std::process::id()));
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
            common::skip("openssl not available");
            return None;
        }
        std::fs::write(dir.join("www/small.txt"), "hello\n").unwrap();
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
        let gasp = dir.join("gasp.jsonl");
        let child = Command::new(env!("CARGO_BIN_EXE_zion"))
            .env("ZION_CONFIG", &cfg)
            .env("ZION_BOOT_FAST", "1")
            .env("ZION_LAST_GASP_PATH", &gasp)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(dir.join("zion.log")).unwrap())
            .spawn()
            .expect("spawn zion");
        let zion = Zion {
            child,
            http,
            gasp,
            dir,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(("127.0.0.1", http)).is_err() {
            assert!(Instant::now() < deadline, "zion did not start listening");
            std::thread::sleep(Duration::from_millis(100));
        }
        Some(zion)
    }

    /// The FATAL panic record the hook writes to the last-gasp file, if any (it is written
    /// whether the panic aborts the process in release or is caught by the task in debug).
    /// Polled for up to `within`, since the hook flushes a moment after the panic.
    fn panic_record(&self, within: Duration) -> Option<String> {
        let deadline = Instant::now() + within;
        loop {
            if let Ok(s) = std::fs::read_to_string(&self.gasp) {
                if let Some(line) = s.lines().find(|l| l.contains("\"event\":\"panic\"")) {
                    return Some(line.to_string());
                }
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
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

/// A complete `GET` on `stream` with the given raw `:path` bytes, over h2c.
/// HPACK: `:method GET` (0x82), `:scheme http` (0x86), `:path` as a literal with incremental
/// indexing (name index 4, 0x44) whose length byte has no Huffman bit, so the raw bytes
/// travel verbatim, then `:authority localhost` (0x41). Every request opens its own
/// connection, so the dynamic-table entries never carry over.
fn get_raw_path(stream: u32, path: &[u8]) -> Vec<u8> {
    assert!(
        path.len() < 127,
        "test keeps the path short so HPACK length is one byte"
    );
    let mut hpack = vec![0x82, 0x86, 0x44, path.len() as u8];
    hpack.extend_from_slice(path);
    hpack.extend_from_slice(&[0x41, 9]); // :authority literal, name index 1
    hpack.extend_from_slice(b"localhost");
    frame(HEADERS, 0x5, stream, &hpack) // END_STREAM | END_HEADERS
}

/// One HTTP/2 frame header + payload, or `None` on EOF / reset / read timeout.
fn read_frame(s: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
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

fn connect(port: u16) -> TcpStream {
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_nodelay(true).unwrap();
    tcp
}

/// Send `hpack_request` as one h2c request on stream 1, then read frames until the response
/// ends or the connection does. Returns, for each HEADERS (a response) that arrived, its
/// stream id and the first byte of its header block.
fn speak_h2c(port: u16, hpack_request: &[u8]) -> Vec<(u32, Option<u8>)> {
    let mut conn = connect(port);
    let mut out = PREFACE.to_vec();
    out.extend(frame(SETTINGS, 0, 0, &[]));
    out.extend_from_slice(hpack_request);
    conn.write_all(&out).unwrap();
    conn.flush().unwrap();
    let mut responses = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match read_frame(&mut conn) {
            Some((HEADERS, flags, stream, block)) => {
                responses.push((stream, block.first().copied()));
                if flags & END_STREAM != 0 {
                    break;
                }
            }
            Some((DATA, flags, _, _)) if flags & END_STREAM != 0 => break,
            Some((RST_STREAM | GOAWAY, _, _, _)) => break,
            Some(_) => {}
            None => break,
        }
    }
    responses
}

/// HPACK's indexed `:status: 400` (static table entry 12): how h2 encodes that status.
const STATUS_400: u8 = 0x80 | 12;

/// A raw DEL byte (0x7F) in the `:path` of one h2c request to :80 gets a 400, and zion
/// neither panics nor stops answering. The control request (a plain `/`) shows the listener
/// speaks h2c and answers without a panic, which isolates the DEL byte.
#[test]
fn a_del_byte_in_the_h2c_path_is_a_400_not_a_crash() {
    let Some(zion) = Zion::start() else {
        return;
    };

    // Control: a benign h2c GET "/" is answered (a 301 redirect) and records no panic.
    let benign = speak_h2c(zion.http, &get_raw_path(1, b"/"));
    assert!(
        benign.iter().any(|(s, _)| *s == 1),
        "control: a benign h2c GET / should get a response on stream 1, got {benign:?}"
    );
    assert!(
        zion.panic_record(Duration::from_millis(500)).is_none(),
        "control: a benign request must not panic zion"
    );

    // One h2c GET with a raw 0x7F in the path.
    let bad = speak_h2c(zion.http, &get_raw_path(1, b"/\x7f"));

    if let Some(record) = zion.panic_record(Duration::from_secs(2)) {
        panic!(
            "zion panicked handling an h2c request with a raw 0x7F in :path; under the release\n\
             profile (panic = \"abort\") that aborts the whole process.\n\
             last-gasp record:\n{record}"
        );
    }
    assert_eq!(
        bad,
        vec![(1, Some(STATUS_400))],
        "the request gets one response, a 400"
    );
    let after = speak_h2c(zion.http, &get_raw_path(1, b"/"));
    assert!(
        after.iter().any(|(s, _)| *s == 1),
        "zion still answers after it: {after:?}"
    );
}
