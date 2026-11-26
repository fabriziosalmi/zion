// SPDX-License-Identifier: Apache-2.0
//! What one HTTP/2 client that does not read can make a static route hold, with the real binary.
//!
//! Every request for a file reads its own copy, and one HTTP/2 connection carries 128
//! requests. While a file of up to 64 MiB was read whole before the first byte was sent, a
//! single connection asking 100 times for a 32 MiB file made the server hold 3.2 GB, for as
//! long as the client cared not to read (#562). A file is now streamed unless it is small, so
//! each request holds a bounded amount whatever the file's size.
//!
//! A streamed file keeps its descriptor open while the client withholds its flow-control
//! window, and so did every one of the 128 streams of a connection: one client that opened the
//! streams and never the windows held 128 descriptors and their read-ahead, for the hour the
//! connection may last (the keep-alive `PING` only asks whether the client is alive). Now a
//! connection streams at most eight files at once and holds at most eight files' worth of the
//! smaller ones read whole (the others wait, holding nothing), every chunk of a response keeps
//! its slot until it has left, compressed or not, and a stream whose client takes nothing for
//! `send_stall_secs` is reset. HTTP/3 gets the same, through QUIC's stream credit (with
//! `--features http3`). One address may open many connections, so every static response, on
//! HTTP/1.1 too, also takes what it holds from its address's share of a budget for the whole
//! process, and waits at most 10 s for it before a `503`; behind a trusted proxy the share is
//! the client's the proxy names, and the proxy's connection has no per-connection slots.
//!
//! Unix only (the process's memory is read from `/proc`, `top` or `ps`, its descriptors from
//! `/proc` or `lsof`). Like the drain tests, a missing `openssl` (for a throwaway certificate)
//! or `lsof` (macOS) skips with a message.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod common;
use common::free_port;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
/// `RST_STREAM` error code `CANCEL` (RFC 9113 §7).
const CANCEL: u32 = 0x8;
/// `SETTINGS_INITIAL_WINDOW_SIZE = 0`: the server may send no `DATA` on any stream until the
/// client opens that stream's window.
const INITIAL_WINDOW_ZERO: [u8; 6] = [0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
/// The static responses one HTTP/2 connection may hold at once (`STATIC_FILES_PER_CONN` in
/// `src/h2_stream.rs`).
const STATIC_FILES_PER_CONN: usize = 8;
/// The size of a streamed file frame (`STREAM_FRAME` in `src/static_files.rs`).
const STREAM_FRAME: usize = 64 * 1024;

/// The 32 MiB file of the #562 test.
const HUGE_BYTES: usize = 32 * 1024 * 1024;
/// A file above the 576 KiB whole-buffer threshold, so it is streamed with its file open.
const BIG_BYTES: usize = 2 * 1024 * 1024;
/// The largest file that is read whole: its response is one 576 KiB chunk, no file kept open.
const WHOLE_BYTES: usize = 576 * 1024;

struct Zion {
    child: Child,
    http: u16,
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
    /// Start zion with `server` added to its `[server]` table and a static route over a
    /// directory holding `files` (name, size); `None` when `openssl` is unavailable.
    fn start(server: &str, files: &[(&str, usize)]) -> Option<Zion> {
        Zion::start_route(server, "", files)
    }

    /// [`Zion::start`] with `route` added to the static route's table.
    fn start_route(server: &str, route: &str, files: &[(&str, usize)]) -> Option<Zion> {
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
            common::skip("openssl not available");
            return None;
        }
        for (name, len) in files {
            std::fs::write(dir.join("www").join(name), noise(*len)).unwrap();
        }
        let cfg = dir.join("zion.toml");
        std::fs::write(
            &cfg,
            format!(
                "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n{server}\n\
                 [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\
                 [[route]]\npath = \"/files/{{*rest}}\"\nmode = \"static\"\nserve_dir = \"{}\"\n{route}\n",
                cert.display(),
                key.display(),
                dir.join("www").display(),
                server = server,
                route = route,
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
        let zion = Zion {
            child,
            http,
            https,
            dir,
        };
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

    /// How many descriptors the daemon holds open on `www/<name>`; `None` when they cannot
    /// be read here (macOS without `lsof`).
    fn open_fds_to(&self, name: &str) -> Option<usize> {
        open_fds_to(self.child.id(), &self.dir.join("www").join(name))
    }
}

/// Count the descriptors of `pid` whose target path contains `needle`.
///
/// Linux reads `/proc/<pid>/fd`; macOS asks `lsof`, which prints the resolved path (under
/// `/private`, which still contains the temp-dir path). `None` only when neither works, so a
/// caller skips instead of passing on a measurement that was not taken.
fn open_fds_to(pid: u32, needle: &Path) -> Option<usize> {
    let needle = needle.to_string_lossy();
    if cfg!(target_os = "linux") {
        let mut n = 0;
        for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).ok()? {
            let Ok(entry) = entry else { continue };
            if let Ok(target) = std::fs::read_link(entry.path()) {
                if target.to_string_lossy().contains(needle.as_ref()) {
                    n += 1;
                }
            }
        }
        return Some(n);
    }
    let out = Command::new("lsof")
        .args(["-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() && out.stdout.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(text.lines().filter(|l| l.contains(needle.as_ref())).count())
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

/// `WINDOW_UPDATE` opening `stream`'s window (0 = the connection's) by `n` bytes.
fn window_update(stream: u32, n: u32) -> Vec<u8> {
    frame(WINDOW_UPDATE, 0, stream, &n.to_be_bytes())
}

/// `HEADERS` for `GET /files/<name>` on `stream`, ending the request (HPACK: `:method GET`,
/// `:scheme https`, then `:path` and `:authority` as literals).
fn get(stream: u32, name: &str) -> Vec<u8> {
    get_with(stream, name, &[])
}

/// [`get`] with `extra`, more HPACK-encoded header fields, after the others.
fn get_with(stream: u32, name: &str, extra: &[u8]) -> Vec<u8> {
    request(stream, true, &format!("/files/{name}"), extra)
}

/// `HEADERS` for `GET <path>` on `stream` (`:scheme https`, or `http` for h2c), ending the
/// request, with the HPACK header fields `extra` after the others.
fn request(stream: u32, https: bool, path: &str, extra: &[u8]) -> Vec<u8> {
    let scheme = if https { 0x87 } else { 0x86 };
    let mut hpack = vec![0x82, scheme, 0x44, path.len() as u8];
    hpack.extend_from_slice(path.as_bytes());
    hpack.extend_from_slice(&[0x41, 9]);
    hpack.extend_from_slice(b"localhost");
    hpack.extend_from_slice(extra);
    frame(HEADERS, 0x5, stream, &hpack)
}

/// `accept-encoding: br`, HPACK-encoded (a literal with the static table's name 16).
#[cfg(feature = "compress")]
const ACCEPT_BR: [u8; 4] = [0x50, 2, b'b', b'r'];

/// The id of the `i`-th request a client opens (odd, from 1).
fn stream_id(i: usize) -> u32 {
    1 + 2 * i as u32
}

struct Frame {
    ty: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// A byte stream to zion: TLS, or plain TCP for h2c.
trait Io: Read + Write {}
impl<T: Read + Write> Io for T {}

/// An HTTP/2 client that reads whatever arrives without blocking on a half frame, and answers
/// `PING` and `SETTINGS` as a client must: the server sees a live peer.
struct Peer {
    io: Box<dyn Io>,
    buf: Vec<u8>,
    closed: bool,
}

impl Peer {
    /// Connect over TCP with no TLS (h2c with prior knowledge, as on the plain listener) and
    /// send the preface, a `SETTINGS` frame with `settings`, and `then`.
    fn open_plain(port: u16, settings: &[u8], then: &[u8]) -> Peer {
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        Peer::start(Box::new(tcp), settings, then)
    }

    fn start(io: Box<dyn Io>, settings: &[u8], then: &[u8]) -> Peer {
        let mut peer = Peer {
            io,
            buf: Vec::new(),
            closed: false,
        };
        let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        out.extend(frame(SETTINGS, 0, 0, settings));
        out.extend_from_slice(then);
        peer.send(&out);
        peer
    }

    /// Connect with ALPN `h2` and send the preface, a `SETTINGS` frame with `settings`, and
    /// `then`.
    fn open(port: u16, settings: &[u8], then: &[u8]) -> Peer {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        Peer::start(Box::new(tls_connect(Arc::new(cfg), tcp)), settings, then)
    }

    fn send(&mut self, bytes: &[u8]) {
        self.io.write_all(bytes).unwrap();
        self.io.flush().unwrap();
    }

    /// The frames that arrive within `wait`.
    fn frames(&mut self, wait: Duration) -> Vec<Frame> {
        let until = Instant::now() + wait;
        let mut got = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        while !self.closed && Instant::now() < until {
            match self.io.read(&mut chunk) {
                Ok(0) => self.closed = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => self.closed = true,
            }
            while self.buf.len() >= 9 {
                let len = u32::from_be_bytes([0, self.buf[0], self.buf[1], self.buf[2]]) as usize;
                if self.buf.len() < 9 + len {
                    break;
                }
                let f = Frame {
                    ty: self.buf[3],
                    flags: self.buf[4],
                    stream: u32::from_be_bytes([
                        self.buf[5],
                        self.buf[6],
                        self.buf[7],
                        self.buf[8],
                    ]) & 0x7fff_ffff,
                    payload: self.buf[9..9 + len].to_vec(),
                };
                self.buf.drain(..9 + len);
                if f.ty == PING && f.flags & ACK == 0 {
                    let pong = frame(PING, ACK, 0, &f.payload);
                    self.send(&pong);
                }
                if f.ty == SETTINGS && f.flags & ACK == 0 {
                    self.send(&frame(SETTINGS, ACK, 0, &[]));
                }
                got.push(f);
            }
        }
        got
    }

    /// Read until `n` responses have begun (their `HEADERS` arrived), panicking on `GOAWAY`,
    /// on a closed connection, and after `within`. Returns the streams that began.
    fn wait_for_responses(&mut self, n: usize, within: Duration) -> Vec<u32> {
        let until = Instant::now() + within;
        let mut begun = Vec::new();
        while begun.len() < n {
            assert!(
                Instant::now() < until,
                "{} of {n} responses began within {within:?}",
                begun.len()
            );
            for f in self.frames(Duration::from_millis(100)) {
                assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY");
                if f.ty == HEADERS {
                    begun.push(f.stream);
                }
            }
            assert!(
                !self.closed,
                "the connection ended with {} of {n} responses begun",
                begun.len()
            );
        }
        begun
    }
}

/// One connection, 100 requests for a 32 MiB file, and a client that then stops reading:
/// HTTP/2 flow control lets the server send it 64 KiB in all, so everything else the server
/// has read for those responses stays in its memory until the client moves. That must be a
/// bounded amount per request, not the file.
#[test]
fn a_client_cannot_make_the_server_hold_a_file_once_per_request() {
    /// Streams on the one connection (the server allows 128).
    const STREAMS: usize = 100;
    /// What the server may grow by while it holds them. Measured on macOS: 11 to 17 MiB for
    /// the eight responses the connection may hold at once (75 to 77 MiB for all 100, before
    /// a connection's static responses were capped); read whole, as before #562, the file
    /// alone would be 256 MiB for the eight.
    const GROWTH_LIMIT_MIB: u64 = 128;
    let Some(zion) = Zion::start("", &[("huge.bin", HUGE_BYTES)]) else {
        return;
    };
    let before = zion.memory_mib();

    let requests: Vec<u8> = (0..STREAMS)
        .flat_map(|i| get(stream_id(i), "huge.bin"))
        .collect();
    let mut peer = Peer::open(zion.https, &[], &requests);
    // Read until the responses the connection may hold have begun: by then the server has
    // opened, and under the old behaviour read, the file for each. Then read nothing more.
    let begun = peer.wait_for_responses(STATIC_FILES_PER_CONN, Duration::from_secs(20));

    // The highest the process gets while the client holds the streams.
    let mut peak = before;
    for _ in 0..4 {
        std::thread::sleep(Duration::from_millis(500));
        peak = peak.max(zion.memory_mib());
    }
    let growth = peak.saturating_sub(before);
    eprintln!(
        "memory: {before} MiB before, {peak} MiB holding {} of {STREAMS} streams",
        begun.len()
    );
    assert!(
        growth < GROWTH_LIMIT_MIB,
        "holding {} requests for a {} MiB file grew the server by {growth} MiB \
         ({before} -> {peak}): the file is being read whole for each request",
        begun.len(),
        HUGE_BYTES / (1024 * 1024)
    );
    drop(peer);
}

/// One connection, 128 streams for a streamed file, `SETTINGS_INITIAL_WINDOW_SIZE = 0`, and
/// a client that never opens a window. A streamed file keeps its descriptor open until it is
/// sent, so every stalled response pinned one: 128 for one connection (0 -> 128 measured),
/// where the descriptor ceiling is sized for about two a connection (`fd_conn_budget`). Now
/// the connection holds at most eight static responses, and the rest wait without a file.
#[test]
fn a_connection_that_never_opens_its_windows_holds_at_most_eight_files_open() {
    const STREAMS: usize = 128;
    let Some(zion) = Zion::start("", &[("big.bin", BIG_BYTES)]) else {
        return;
    };
    let Some(before) = zion.open_fds_to("big.bin") else {
        common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
        return;
    };

    let requests: Vec<u8> = (0..STREAMS)
        .flat_map(|i| get(stream_id(i), "big.bin"))
        .collect();
    let mut peer = Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &requests);
    let begun = peer.wait_for_responses(STATIC_FILES_PER_CONN, Duration::from_secs(20));

    // The most descriptors the daemon holds to the file while the client withholds window,
    // sampled over 1.5 s, the client reading (and answering PINGs) all along. Any response
    // beyond the eight would begin in that time: it needs no window to send its HEADERS.
    let mut peak = before;
    let mut more = 0;
    for _ in 0..6 {
        for f in peer.frames(Duration::from_millis(250)) {
            assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY");
            more += usize::from(f.ty == HEADERS);
        }
        if let Some(n) = zion.open_fds_to("big.bin") {
            peak = peak.max(n);
        }
    }
    let held = peak.saturating_sub(before);
    eprintln!(
        "open fds to the served file: {before} before, {peak} while {STREAMS} window-stalled \
         streams were open on one connection ({} responses begun, {more} more after)",
        begun.len()
    );
    assert!(
        held > 0,
        "the measurement saw no descriptor to the file at all ({before} -> {peak}): it is \
         not measuring what the responses hold"
    );
    assert!(
        held <= STATIC_FILES_PER_CONN,
        "one window-withholding HTTP/2 connection pinned {held} open descriptors to the served \
         file ({before} -> {peak}), over the {STATIC_FILES_PER_CONN} a connection may hold"
    );
    assert_eq!(
        more, 0,
        "{more} responses began beyond the {STATIC_FILES_PER_CONN} a connection may hold"
    );
    drop(peer);
}

/// The same hold through files small enough to be read whole: no descriptor stays open, but
/// each stalled response keeps its 576 KiB in memory. Measured on macOS, 128 of them on one
/// connection grew the server by 84 to 86 MiB; the eight a connection may now hold, by 15 to
/// 17 MiB, about 11 of them the 120 requests that wait.
#[test]
fn a_connection_that_never_opens_its_windows_holds_at_most_eight_whole_files() {
    const STREAMS: usize = 128;
    /// Over the measured growth for eight, well under the one for 128.
    const GROWTH_LIMIT_MIB: u64 = 32;
    let Some(zion) = Zion::start("", &[("whole.bin", WHOLE_BYTES)]) else {
        return;
    };
    let before = zion.memory_mib();
    let requests: Vec<u8> = (0..STREAMS)
        .flat_map(|i| get(stream_id(i), "whole.bin"))
        .collect();
    let mut peer = Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &requests);
    let begun = peer.wait_for_responses(STATIC_FILES_PER_CONN, Duration::from_secs(20));
    let mut peak = before;
    let mut more = 0;
    for _ in 0..4 {
        for f in peer.frames(Duration::from_millis(500)) {
            more += usize::from(f.ty == HEADERS);
        }
        peak = peak.max(zion.memory_mib());
    }
    let growth = peak.saturating_sub(before);
    eprintln!(
        "memory: {before} MiB before, {peak} MiB while {STREAMS} window-stalled streams were \
         open on one connection ({} responses begun, {more} more after)",
        begun.len()
    );
    assert!(
        growth < GROWTH_LIMIT_MIB,
        "one window-withholding HTTP/2 connection grew the server by {growth} MiB \
         ({before} -> {peak}) holding {} responses of {} KiB",
        begun.len() + more,
        WHOLE_BYTES / 1024
    );
    drop(peer);
}

/// The same, from a client that opens each stream's window by one byte as its response begins.
/// That is room enough for the whole 576 KiB chunk to be handed to the HTTP/2 library, and the
/// stream's task then ends with the bytes still unsent: when the slot went with the task, 112 of
/// the 128 responses began and the server grew by 82 MiB (measured on macOS, 5 -> 87). The
/// slot is kept by every chunk of the response, so eight begin.
#[test]
fn a_connection_that_opens_each_window_by_one_byte_holds_at_most_eight_whole_files() {
    let Some(zion) = Zion::start("", &[("whole.bin", WHOLE_BYTES)]) else {
        return;
    };
    one_byte_windows_hold_at_most_eight(&zion, "whole.bin", &[], 32);
}

/// The same through a route that compresses. The encoder writes its output into a buffer of
/// its own, and the file's bytes are dropped once they are in it, so the bytes that wait for
/// the client are not the file's: brotli emits the whole of a body this size as one chunk when
/// the body ends, the stream's task ends once that chunk is handed over, and when only the
/// file's bytes kept the slot every one of the 128 responses began.
#[cfg(feature = "compress")]
#[test]
fn a_compressed_response_keeps_its_slot_while_its_bytes_wait_for_the_client() {
    let Some(zion) = Zion::start_route(
        "",
        "compress = { enabled = true }",
        &[("app.js", WHOLE_BYTES)],
    ) else {
        return;
    };
    // The route does compress this file: the body that arrives is not the file's 576 KiB.
    let sent = fetch(zion.https, "/files/app.js", &ACCEPT_BR).len();
    assert_ne!(sent, WHOLE_BYTES, "the response was not compressed");
    eprintln!("app.js: {WHOLE_BYTES} bytes, {sent} sent with accept-encoding: br");
    // Over the 32 MiB of the identity test: each response compressing at once also holds its
    // encoder (brotli with a 4 MiB window, several MiB of state). Measured on macOS: 12 to
    // 79 MiB for the eight; v0.18.0, which had no slots, began all 128 and grew to 360 MiB.
    one_byte_windows_hold_at_most_eight(&zion, "app.js", &ACCEPT_BR, 160);
}

/// The body zion sends for `GET <path>` (with the HPACK header fields `extra`) to a client whose
/// windows are wide open.
fn fetch(port: u16, path: &str, extra: &[u8]) -> Vec<u8> {
    let max_window = [0x00, 0x04, 0x7f, 0xff, 0xff, 0xff];
    let mut first = window_update(0, (1 << 31) - 1 - 65_535);
    first.extend(request(1, true, path, extra));
    let mut peer = Peer::open(port, &max_window, &first);
    let started = Instant::now();
    let mut body = Vec::new();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "no whole body in 20 s"
        );
        for f in peer.frames(Duration::from_millis(100)) {
            assert!(f.ty != GOAWAY && f.ty != RST_STREAM, "frame type {}", f.ty);
            if f.ty == DATA {
                body.extend_from_slice(&f.payload);
            }
            if matches!(f.ty, DATA | HEADERS) && f.flags & END_STREAM != 0 {
                return body;
            }
        }
        assert!(!peer.closed, "the connection ended");
    }
}

/// 128 requests for `name` (with the HPACK header fields `extra`) on one connection whose
/// windows are closed, each stream's opened by one byte as its response begins: exactly eight
/// responses begin, and the server grows by less than `growth_limit_mib`.
fn one_byte_windows_hold_at_most_eight(
    zion: &Zion,
    name: &str,
    extra: &[u8],
    growth_limit_mib: u64,
) {
    const STREAMS: usize = 128;
    let before = zion.memory_mib();
    let mut first = window_update(0, 1 << 30);
    first.extend((0..STREAMS).flat_map(|i| get_with(stream_id(i), name, extra)));
    let mut peer = Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &first);
    let mut begun = std::collections::BTreeSet::new();
    let mut peak = before;
    // For about three seconds, open the window of every response that begins by one byte;
    // sample the memory over the last rounds.
    for round in 0..14 {
        let mut new = Vec::new();
        for f in peer.frames(Duration::from_millis(200)) {
            assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY");
            if f.ty == HEADERS && begun.insert(f.stream) {
                new.push(f.stream);
            }
        }
        for stream in new {
            peer.send(&window_update(stream, 1));
        }
        assert!(!peer.closed, "the connection ended");
        if round >= 10 {
            peak = peak.max(zion.memory_mib());
        }
    }
    let growth = peak.saturating_sub(before);
    eprintln!(
        "memory: {before} MiB before, {peak} MiB; {} of {STREAMS} responses began with \
         one-byte windows",
        begun.len()
    );
    assert!(
        begun.len() <= STATIC_FILES_PER_CONN,
        "{} responses began: a response handed to the HTTP/2 library gave its slot back while \
         its bytes still waited for the client",
        begun.len()
    );
    assert_eq!(
        begun.len(),
        STATIC_FILES_PER_CONN,
        "{} responses began: the connection may hold {STATIC_FILES_PER_CONN} at once",
        begun.len()
    );
    assert!(
        growth < growth_limit_mib,
        "one connection opening its windows by one byte grew the server by {growth} MiB \
         ({before} -> {peak})"
    );
    drop(peer);
}

/// A client that keeps its windows closed, answering the server's PINGs: each stalled stream
/// is reset with `RST_STREAM(CANCEL)` once its response has waited `send_stall_secs` for
/// the client, its file is closed, and the connection goes on serving.
#[test]
fn a_stream_whose_client_takes_nothing_is_reset_and_frees_its_file() {
    const STALL_SECS: u64 = 2;
    let Some(zion) = Zion::start(
        &format!("send_stall_secs = {STALL_SECS}"),
        &[("big.bin", BIG_BYTES)],
    ) else {
        return;
    };
    let Some(before) = zion.open_fds_to("big.bin") else {
        common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
        return;
    };
    let requests: Vec<u8> = (0..STATIC_FILES_PER_CONN)
        .flat_map(|i| get(stream_id(i), "big.bin"))
        .collect();
    let mut peer = Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &requests);
    let begun = peer.wait_for_responses(STATIC_FILES_PER_CONN, Duration::from_secs(20));
    let started = Instant::now();
    let held = zion.open_fds_to("big.bin").unwrap_or(0);

    // Every stream is reset, with CANCEL, after the deadline and not long after it.
    let mut reset = std::collections::BTreeMap::new();
    while reset.len() < begun.len() && started.elapsed() < Duration::from_secs(STALL_SECS + 8) {
        for f in peer.frames(Duration::from_millis(100)) {
            assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY: the deadline is per stream");
            if f.ty == RST_STREAM {
                let code = u32::from_be_bytes(f.payload[..4].try_into().unwrap());
                reset.insert(f.stream, (code, started.elapsed()));
            }
        }
        assert!(!peer.closed, "the connection ended");
    }
    eprintln!("open fds to the file while stalled: {held}; resets: {reset:?}");
    assert_eq!(
        reset.len(),
        begun.len(),
        "{} of {} stalled streams were reset within {} s",
        reset.len(),
        begun.len(),
        STALL_SECS + 8
    );
    for (stream, (code, at)) in &reset {
        assert_eq!(
            *code, CANCEL,
            "stream {stream} reset with error code {code}"
        );
        assert!(
            *at >= Duration::from_millis(STALL_SECS * 1000 - 500),
            "stream {stream} was reset after {at:?}, before its {STALL_SECS} s deadline"
        );
    }

    // ... and its file with it.
    let until = Instant::now() + Duration::from_secs(5);
    let mut now = held;
    while now > before && Instant::now() < until {
        peer.frames(Duration::from_millis(100));
        now = zion.open_fds_to("big.bin").unwrap_or(now);
    }
    assert!(
        held > before,
        "the stalled responses held no descriptor ({before} -> {held})"
    );
    assert_eq!(
        now, before,
        "{now} descriptors to the file stayed open after every stream holding one was reset"
    );

    // The connection is still served: a new request is answered.
    let next = stream_id(STATIC_FILES_PER_CONN);
    peer.send(&get(next, "big.bin"));
    let more = peer.wait_for_responses(1, Duration::from_secs(5));
    assert_eq!(more, vec![next]);
    drop(peer);

    // Each reset is counted.
    let page = String::from_utf8(fetch(zion.https, "/metrics", &[])).unwrap();
    let counted = page
        .lines()
        .find_map(|l| l.strip_prefix("zion_streams_stalled_total "))
        .and_then(|v| v.trim().parse::<usize>().ok());
    assert_eq!(
        counted,
        Some(STATIC_FILES_PER_CONN),
        "zion_streams_stalled_total after {STATIC_FILES_PER_CONN} resets"
    );
}

/// The plain listener speaks HTTP/2 as well (h2c, with prior knowledge), and its streams get
/// the same deadline. Static routes are not served there, but `/_zion/snapshot.json` is, to an
/// internal address, and has a body: a client that keeps its windows closed has that stream
/// reset with `CANCEL` after `send_stall_secs`, as on the TLS listener.
#[test]
fn a_stream_on_the_plain_listener_whose_client_takes_nothing_is_reset_too() {
    const STALL_SECS: u64 = 2;
    let Some(zion) = Zion::start(&format!("send_stall_secs = {STALL_SECS}"), &[]) else {
        return;
    };
    let until = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", zion.http)).is_err() {
        assert!(Instant::now() < until, "the plain listener did not open");
        std::thread::sleep(Duration::from_millis(100));
    }
    let snapshot = request(1, false, "/_zion/snapshot.json", &[]);
    let mut peer = Peer::open_plain(zion.http, &INITIAL_WINDOW_ZERO, &snapshot);
    assert_eq!(peer.wait_for_responses(1, Duration::from_secs(10)), vec![1]);
    let started = Instant::now();
    let mut reset = None;
    while reset.is_none() && started.elapsed() < Duration::from_secs(STALL_SECS + 8) {
        for f in peer.frames(Duration::from_millis(100)) {
            assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY: the deadline is per stream");
            assert!(
                f.ty != DATA || f.payload.is_empty(),
                "zion sent DATA into a closed window"
            );
            if f.ty == RST_STREAM && f.stream == 1 {
                let code = u32::from_be_bytes(f.payload[..4].try_into().unwrap());
                reset = Some((code, started.elapsed()));
            }
        }
        assert!(!peer.closed, "the connection ended");
    }
    eprintln!("h2c on the plain listener: reset {reset:?}");
    let (code, at) = reset.expect("the stalled h2c stream was never reset");
    assert_eq!(code, CANCEL, "reset with error code {code}");
    assert!(
        at >= Duration::from_millis(STALL_SECS * 1000 - 500),
        "reset after {at:?}, before its {STALL_SECS} s deadline"
    );
}

/// A client that reads slowly but steadily: it opens the stream's window one frame at a time,
/// every 400 ms, so the response takes four seconds, twice the deadline. The deadline counts
/// from the last chunk the client took, not from the start of the response: it is never reset.
#[test]
fn a_client_that_reads_slowly_but_steadily_is_never_reset() {
    const STALL_SECS: u64 = 2;
    const SLOW_BYTES: usize = 10 * STREAM_FRAME;
    let Some(zion) = Zion::start(
        &format!("send_stall_secs = {STALL_SECS}"),
        &[("slow.bin", SLOW_BYTES)],
    ) else {
        return;
    };
    // The connection's window wide open, the stream's at 0: the stream's window paces it.
    let mut first = window_update(0, 1 << 30);
    first.extend(get(1, "slow.bin"));
    let mut peer = Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &first);
    let started = Instant::now();
    let mut received = 0usize;
    let mut done = false;
    while !done {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{received} of {SLOW_BYTES} bytes in 30 s"
        );
        peer.send(&window_update(1, STREAM_FRAME as u32));
        for f in peer.frames(Duration::from_millis(400)) {
            assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY");
            assert_ne!(
                f.ty,
                RST_STREAM,
                "the slow reader was reset after {:?}, {received} of {SLOW_BYTES} bytes in",
                started.elapsed()
            );
            if f.ty == DATA && f.stream == 1 {
                received += f.payload.len();
                done |= f.flags & END_STREAM != 0;
            }
        }
        assert!(!peer.closed, "the connection ended");
    }
    let took = started.elapsed();
    eprintln!("{received} bytes in {took:?} at one frame per 400 ms");
    assert_eq!(received, SLOW_BYTES);
    assert!(
        took > Duration::from_secs(STALL_SECS),
        "the response took {took:?}: it does not prove a response may outlast the deadline"
    );
}

/// Eight large responses that hold every file slot of a connection (their client reads none of
/// them yet: a paused video, a download it will read later) do not keep a small file waiting:
/// a page's stylesheets, scripts and images are read whole and take from a budget of their
/// own. When one slot counted both, the small file got no answer until a large one ended.
#[test]
fn a_small_file_is_served_while_eight_large_responses_hold_every_file_slot() {
    const SMALL_BYTES: usize = 20 * 1024;
    let Some(zion) = Zion::start("", &[("big.bin", BIG_BYTES), ("app.css", SMALL_BYTES)]) else {
        return;
    };
    // The connection's window open, every stream's closed until the client opens it.
    let mut first = window_update(0, 1 << 30);
    first.extend((0..STATIC_FILES_PER_CONN).flat_map(|i| get(stream_id(i), "big.bin")));
    let mut peer = Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &first);
    peer.wait_for_responses(STATIC_FILES_PER_CONN, Duration::from_secs(20));

    let small = stream_id(STATIC_FILES_PER_CONN);
    peer.send(&get(small, "app.css"));
    let asked = Instant::now();
    let begun = peer.wait_for_responses(1, Duration::from_secs(5));
    assert_eq!(begun, vec![small], "a large response began");
    peer.send(&window_update(small, SMALL_BYTES as u32));
    let mut received = 0;
    let mut ended = false;
    while !ended {
        assert!(
            asked.elapsed() < Duration::from_secs(5),
            "{received} of {SMALL_BYTES} bytes of the small file in 5 s"
        );
        for f in peer.frames(Duration::from_millis(100)) {
            assert!(f.ty != GOAWAY && f.ty != RST_STREAM, "frame type {}", f.ty);
            if f.ty == DATA && f.stream == small {
                received += f.payload.len();
                ended |= f.flags & END_STREAM != 0;
            }
        }
        assert!(!peer.closed, "the connection ended");
    }
    eprintln!(
        "the small file: {received} bytes in {:?} beside eight stalled large responses",
        asked.elapsed()
    );
    assert_eq!(received, SMALL_BYTES);
    // A ninth large one still waits for a slot.
    let ninth = stream_id(STATIC_FILES_PER_CONN + 1);
    peer.send(&get(ninth, "big.bin"));
    let more = peer.frames(Duration::from_millis(1500));
    assert!(
        !more.iter().any(|f| f.ty == HEADERS && f.stream == ninth),
        "a ninth streamed response began"
    );
}

/// An ordinary client that asks for more files than the connection may hold at once, and
/// reads: the requests beyond the eight wait for a slot and are served in full, none refused.
#[test]
fn requests_beyond_the_eight_wait_for_a_slot_and_are_all_served() {
    const STREAMS: usize = 16;
    let Some(zion) = Zion::start("", &[("big.bin", BIG_BYTES)]) else {
        return;
    };
    // Windows as wide as HTTP/2 allows, so nothing waits on flow control.
    let max_window = [0x00, 0x04, 0x7f, 0xff, 0xff, 0xff];
    let mut first = window_update(0, (1 << 31) - 1 - 65_535);
    first.extend((0..STREAMS).flat_map(|i| get(stream_id(i), "big.bin")));
    let mut peer = Peer::open(zion.https, &max_window, &first);
    let started = Instant::now();
    let mut received = std::collections::BTreeMap::<u32, usize>::new();
    let mut ended = std::collections::BTreeSet::new();
    while ended.len() < STREAMS {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{} of {STREAMS} responses complete in 30 s",
            ended.len()
        );
        for f in peer.frames(Duration::from_millis(100)) {
            assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY");
            assert_ne!(f.ty, RST_STREAM, "stream {} was reset", f.stream);
            if f.ty == DATA {
                *received.entry(f.stream).or_default() += f.payload.len();
            }
            if matches!(f.ty, DATA | HEADERS) && f.flags & END_STREAM != 0 {
                ended.insert(f.stream);
            }
        }
        assert!(!peer.closed, "the connection ended");
    }
    for i in 0..STREAMS {
        assert_eq!(
            received.get(&stream_id(i)).copied().unwrap_or(0),
            BIG_BYTES,
            "stream {}",
            stream_id(i)
        );
    }
}

/// `max_connections` for the tests of the budget for the whole process: its budget is 128 KiB
/// for each connection of the ceiling, 128 MiB, and one client address may hold an eighth of
/// it, 16 MiB: 21 streamed responses at the 768 KiB each is counted as (`static_budget`).
const BUDGET_CONNS: usize = 1024;
/// The streamed responses one address may hold under [`BUDGET_CONNS`].
const SHARE_STREAMED: usize = 21;
/// ... and all addresses together.
const BUDGET_STREAMED: usize = 170;
/// How long a request waits for its address's share or the budget before its `503`
/// (`static_budget::BUDGET_WAIT`).
const BUDGET_WAIT: Duration = Duration::from_secs(10);

/// [`get`] with `x-forwarded-for: <xff>` (an HPACK literal with a new name).
fn get_xff(stream: u32, name: &str, xff: &str) -> Vec<u8> {
    let mut extra = vec![0x00, 15];
    extra.extend_from_slice(b"x-forwarded-for");
    extra.push(xff.len() as u8);
    extra.extend_from_slice(xff.as_bytes());
    get_with(stream, name, &extra)
}

/// What a round of reading from several connections saw.
#[derive(Default)]
struct Seen {
    /// Responses that began with a body to come: `(connection, stream)`.
    begun: std::collections::BTreeSet<(usize, u32)>,
    /// Responses that ended with their `HEADERS` (a `503`, no body), and when.
    refused: std::collections::BTreeMap<(usize, u32), Duration>,
    /// Streams reset by zion, with the error code and when.
    reset: std::collections::BTreeMap<(usize, u32), (u32, Duration)>,
}

impl Seen {
    /// Read from every peer for `wait`, answering their PINGs, and note what began, what was
    /// refused and what was reset (times from `t0`).
    fn read(&mut self, peers: &mut [Peer], wait: Duration, t0: Instant) {
        let until = Instant::now() + wait;
        while Instant::now() < until {
            for (i, peer) in peers.iter_mut().enumerate() {
                for f in peer.frames(Duration::from_millis(20)) {
                    assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY on connection {i}");
                    match f.ty {
                        HEADERS if f.flags & END_STREAM != 0 => {
                            self.refused.insert((i, f.stream), t0.elapsed());
                        }
                        HEADERS => {
                            self.begun.insert((i, f.stream));
                        }
                        RST_STREAM => {
                            let code = u32::from_be_bytes(f.payload[..4].try_into().unwrap());
                            self.reset.insert((i, f.stream), (code, t0.elapsed()));
                        }
                        _ => {}
                    }
                }
                assert!(!peer.closed, "connection {i} ended");
            }
        }
    }
}

/// A counter of zion's `/metrics` page, read from an internal address.
fn metric(port: u16, name: &str) -> Option<u64> {
    let page = String::from_utf8(fetch(port, "/metrics", &[])).unwrap();
    let prefix = format!("{name} ");
    page.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .and_then(|v| v.trim().parse().ok())
}

/// One address, sixteen HTTP/2 connections, eight streams on each for a streamed file, and no
/// window opened: each connection may stream eight, so 128 files were open, and up to 2048
/// connections (an eighth of the ceiling) times the eight files and 4.5 MiB read whole of each
/// was more memory than a 16 GiB host has. The address now holds at most its share of the
/// budget (21 streamed responses here), the other requests wait holding nothing, and are
/// answered `503` after [`BUDGET_WAIT`].
#[test]
fn one_address_holds_at_most_its_share_of_the_budget_over_many_connections() {
    const CONNS: usize = 16;
    let Some(zion) = Zion::start(
        &format!("max_connections = {BUDGET_CONNS}"),
        &[("big.bin", BIG_BYTES)],
    ) else {
        return;
    };
    let Some(fds_before) = zion.open_fds_to("big.bin") else {
        common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
        return;
    };
    let mem_before = zion.memory_mib();
    let requests: Vec<u8> = (0..STATIC_FILES_PER_CONN)
        .flat_map(|i| get(stream_id(i), "big.bin"))
        .collect();
    let t0 = Instant::now();
    let mut peers: Vec<Peer> = (0..CONNS)
        .map(|_| Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &requests))
        .collect();
    let mut seen = Seen::default();
    let (mut fds_peak, mut mem_peak) = (fds_before, mem_before);
    for _ in 0..8 {
        seen.read(&mut peers, Duration::from_millis(300), t0);
        if let Some(n) = zion.open_fds_to("big.bin") {
            fds_peak = fds_peak.max(n);
        }
        mem_peak = mem_peak.max(zion.memory_mib());
    }
    let begun = seen.begun.len();
    // The others are refused once they have waited BUDGET_WAIT, not before.
    while seen.refused.len() < CONNS * STATIC_FILES_PER_CONN - begun
        && t0.elapsed() < BUDGET_WAIT + Duration::from_secs(10)
    {
        seen.read(&mut peers, Duration::from_millis(200), t0);
    }
    let first_refused = seen.refused.values().min().copied();
    eprintln!(
        "one address, {CONNS} connections x {STATIC_FILES_PER_CONN} streams: open fds to the \
         file {fds_before} -> {fds_peak}, memory {mem_before} -> {mem_peak} MiB; {begun} began, \
         {} refused, the first at {first_refused:?}, the last at {:?}",
        seen.refused.len(),
        seen.refused.values().max()
    );
    assert_eq!(
        begun, SHARE_STREAMED,
        "{begun} streamed responses began for one address, whose share is {SHARE_STREAMED}"
    );
    let held = fds_peak.saturating_sub(fds_before);
    assert!(held > 0, "the measurement saw no descriptor to the file");
    assert!(
        held <= SHARE_STREAMED,
        "one address held {held} descriptors to the file over its share of {SHARE_STREAMED}"
    );
    assert_eq!(
        seen.refused.len(),
        CONNS * STATIC_FILES_PER_CONN - begun,
        "every request beyond the share is answered 503 once it has waited"
    );
    let first_refused = first_refused.unwrap();
    assert!(
        first_refused >= BUDGET_WAIT - Duration::from_millis(500),
        "refused after {first_refused:?}, before the {BUDGET_WAIT:?} wait"
    );
    drop(peers);
    let refused = (CONNS * STATIC_FILES_PER_CONN - begun) as u64;
    assert_eq!(
        metric(zion.https, "zion_static_budget_waited_total"),
        Some(refused)
    );
    assert_eq!(
        metric(zion.https, "zion_static_budget_refused_total"),
        Some(refused)
    );
}

/// The same over HTTP/1.1: one response a connection, but up to an eighth of the ceiling's
/// connections for one address, each holding its file open while its client does not read.
#[test]
fn one_address_over_many_http1_connections_holds_at_most_its_share() {
    const CONNS: usize = 30;
    let Some(zion) = Zion::start(
        &format!("max_connections = {BUDGET_CONNS}"),
        &[("huge.bin", HUGE_BYTES)],
    ) else {
        return;
    };
    let Some(before) = zion.open_fds_to("huge.bin") else {
        common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
        return;
    };
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cfg = Arc::new(cfg);
    // Each sends its request and then reads only the first bytes of the answer, so the server
    // has begun it, and nothing more.
    let conns: Vec<_> = (0..CONNS)
        .map(|_| {
            let tcp = TcpStream::connect(("127.0.0.1", zion.https)).unwrap();
            let mut tls = tls_connect(cfg.clone(), tcp);
            tls.write_all(b"GET /files/huge.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            tls.flush().unwrap();
            tls
        })
        .collect();
    let mut peak = before;
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(250));
        if let Some(n) = zion.open_fds_to("huge.bin") {
            peak = peak.max(n);
        }
    }
    let held = peak.saturating_sub(before);
    eprintln!(
        "http/1.1, one address, {CONNS} connections: open fds to the file {before} -> {peak}"
    );
    assert!(held > 0, "no descriptor to the file was open");
    assert_eq!(
        held, SHARE_STREAMED,
        "one address held {held} descriptors to the file over HTTP/1.1; its share is \
         {SHARE_STREAMED}"
    );
    drop(conns);
}

/// Behind a `trusted_proxies` peer one connection carries many clients, so its eight
/// streamed-file slots made unrelated clients wait for each other: a proxy connection gets no
/// connection slots, and each client the proxy names holds its own share. The budget for the
/// whole process still bounds them all.
#[test]
fn behind_a_trusted_proxy_each_client_holds_its_own_share_and_the_budget_bounds_them_all() {
    const CLIENTS: usize = 100;
    let Some(zion) = Zion::start(
        &format!("max_connections = {BUDGET_CONNS}\ntrusted_proxies = [\"127.0.0.1/32\"]"),
        &[("big.bin", BIG_BYTES)],
    ) else {
        return;
    };
    let t0 = Instant::now();
    // 1. One proxy connection, a hundred clients, one streamed file each: all begin.
    let many: Vec<u8> = (0..CLIENTS)
        .flat_map(|i| get_xff(stream_id(i), "big.bin", &format!("10.1.0.{i}")))
        .collect();
    let mut peers = vec![Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &many)];
    let mut seen = Seen::default();
    seen.read(&mut peers, Duration::from_secs(2), t0);
    let one_conn = seen.begun.len();
    // 2. A second proxy connection, 40 requests from one client: its share.
    let same: Vec<u8> = (0..40)
        .flat_map(|i| get_xff(stream_id(i), "big.bin", "10.2.0.1"))
        .collect();
    peers.push(Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &same));
    seen.read(&mut peers, Duration::from_secs(2), t0);
    let one_client = seen.begun.iter().filter(|(c, _)| *c == 1).count();
    // 3. A third, a hundred more clients: the budget runs out.
    let more: Vec<u8> = (0..CLIENTS)
        .flat_map(|i| get_xff(stream_id(i), "big.bin", &format!("10.3.0.{i}")))
        .collect();
    peers.push(Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &more));
    seen.read(&mut peers, Duration::from_secs(2), t0);
    let third = seen.begun.iter().filter(|(c, _)| *c == 2).count();
    eprintln!(
        "behind a trusted proxy: {one_conn} of {CLIENTS} clients began on one connection, \
         {one_client} of 40 requests from one client, {third} of {CLIENTS} more clients; \
         {} in all",
        seen.begun.len()
    );
    assert_eq!(
        one_conn, CLIENTS,
        "a trusted proxy's connection was held to connection slots"
    );
    assert_eq!(
        one_client, SHARE_STREAMED,
        "one client behind the proxy holds its own share"
    );
    assert_eq!(
        seen.begun.len(),
        BUDGET_STREAMED,
        "the budget for the whole process bounds every client"
    );
    assert_eq!(third, BUDGET_STREAMED - CLIENTS - SHARE_STREAMED);
}

/// A batch client (httpx with `asyncio.gather`) that keeps the default 65,535-byte stream
/// windows, opens its connection window wide, asks for 30 files of 200 KiB, and reads no body
/// until every response has begun. Each file is read whole, and on one chunk hyper hands the
/// whole of it to h2 as soon as the window has room for a byte: the stream's task ended with
/// 136 KiB of it unsent and no deadline, and the 23 that fit the connection's 4.5 MiB held it
/// until the connection's hour was up, while the other seven never began. Cut into 64 KiB
/// pieces, the stream waits with a piece in hand and is reset after `send_stall_secs`; the
/// seven then begin.
#[test]
fn small_files_read_whole_are_reset_at_the_deadline_and_free_the_connection() {
    const STALL_SECS: u64 = 2;
    const FILES: usize = 30;
    const FIRST: usize = 23; // 23 x 200 KiB of the 4.5 MiB
    let Some(zion) = Zion::start(
        &format!("send_stall_secs = {STALL_SECS}"),
        &[("page.js", 200 * 1024)],
    ) else {
        return;
    };
    let mut first = window_update(0, 1 << 30);
    first.extend((0..FILES).flat_map(|i| get(stream_id(i), "page.js")));
    let t0 = Instant::now();
    let mut peers = vec![Peer::open(zion.https, &[], &first)];
    let mut seen = Seen::default();
    seen.read(&mut peers, Duration::from_millis(1000), t0);
    let early = seen.begun.len();
    seen.read(
        &mut peers,
        Duration::from_secs(2 * STALL_SECS + 3) - t0.elapsed(),
        t0,
    );
    eprintln!(
        "{early} of {FILES} began at once; {} began by {:?}; resets {:?}",
        seen.begun.len(),
        t0.elapsed(),
        seen.reset.values().collect::<Vec<_>>()
    );
    assert_eq!(early, FIRST, "the connection's whole-read budget");
    assert_eq!(
        seen.begun.len(),
        FILES,
        "the requests waiting behind stalled ones never began"
    );
    assert!(
        seen.reset.len() >= FIRST,
        "{} of the {FIRST} stalled responses were reset",
        seen.reset.len()
    );
    for ((_, stream), (code, at)) in &seen.reset {
        assert_eq!(*code, CANCEL, "stream {stream}");
        assert!(
            *at >= Duration::from_millis(STALL_SECS * 1000 - 500),
            "stream {stream} reset after {at:?}, before its deadline"
        );
    }
}

/// A file small enough to be one piece, to a client that opens its window by one byte and then
/// reads nothing: hyper hands the piece over with room for one byte, and with it the end of the
/// stream, so the stream's task would end with the rest unsent. The end of a static response
/// waits for its last piece to leave, under the deadline: the stream is reset.
#[test]
fn a_small_file_to_a_one_byte_window_is_reset_at_the_deadline() {
    const STALL_SECS: u64 = 2;
    let Some(zion) = Zion::start(
        &format!("send_stall_secs = {STALL_SECS}"),
        &[("icon.svg", 20 * 1024)],
    ) else {
        return;
    };
    let one_byte = [0x00, 0x04, 0x00, 0x00, 0x00, 0x01];
    let mut first = window_update(0, 1 << 30);
    first.extend(get(1, "icon.svg"));
    let t0 = Instant::now();
    let mut peers = vec![Peer::open(zion.https, &one_byte, &first)];
    let mut seen = Seen::default();
    seen.read(&mut peers, Duration::from_secs(STALL_SECS + 3), t0);
    eprintln!("one-byte window: {:?}", seen.reset);
    let (code, at) = *seen
        .reset
        .get(&(0, 1))
        .expect("the stalled response was never reset");
    assert_eq!(code, CANCEL);
    assert!(
        at >= Duration::from_millis(STALL_SECS * 1000 - 500),
        "reset after {at:?}"
    );
}

/// An upstream on a free port that answers every request with `len` bytes, the head and the
/// body in one write, so zion's HTTP/1 client reads the body in chunks as large as its buffer
/// grows to (hundreds of KiB).
fn big_chunk_origin(len: usize) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            std::thread::spawn(move || {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let mut out =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n").into_bytes();
                out.extend(noise(len));
                let _ = conn.write_all(&out);
                std::thread::sleep(Duration::from_secs(60));
            });
        }
    });
    port
}

/// A proxied download read slowly but steadily: 64 KiB every 600 ms, under a 2 s deadline. The
/// upstream's body arrives in chunks of hundreds of KiB, and hyper takes the next chunk only once
/// the one before has nearly left: 600 ms per 64 KiB of a 256 KiB chunk was past the deadline,
/// and the reader was reset though it never stopped. Cut into 64 KiB pieces, the deadline
/// counts per 64 KiB the client takes.
#[test]
fn a_slow_steady_reader_of_large_proxied_chunks_is_never_reset() {
    const STALL_SECS: u64 = 2;
    const LEN: usize = 768 * 1024;
    let origin = big_chunk_origin(LEN);
    let Some(zion) = Zion::start_route(
        &format!("send_stall_secs = {STALL_SECS}"),
        &(format!("\n[upstreams]\norigin = \"http://127.0.0.1:{origin}\"\n")
            + "[[route]]\npath = \"/proxy/{*rest}\"\nupstream = \"origin\"\nmode = \"standard\"\n"),
        &[],
    ) else {
        return;
    };
    let mut first = window_update(0, 1 << 30);
    first.extend(request(1, true, "/proxy/big", &[]));
    let mut peer = Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &first);
    let started = Instant::now();
    let mut received = 0usize;
    let mut done = false;
    while !done {
        assert!(
            started.elapsed() < Duration::from_secs(40),
            "{received} of {LEN} bytes in 40 s"
        );
        peer.send(&window_update(1, STREAM_FRAME as u32));
        for f in peer.frames(Duration::from_millis(600)) {
            assert_ne!(f.ty, GOAWAY, "zion sent GOAWAY");
            assert_ne!(
                f.ty,
                RST_STREAM,
                "the slow reader was reset after {:?}, {received} of {LEN} bytes in",
                started.elapsed()
            );
            if f.ty == DATA && f.stream == 1 {
                received += f.payload.len();
                done |= f.flags & END_STREAM != 0;
            }
            if f.ty == HEADERS && f.stream == 1 {
                done |= f.flags & END_STREAM != 0;
            }
        }
        assert!(!peer.closed, "the connection ended");
    }
    eprintln!(
        "proxied: {received} bytes in {:?} at 64 KiB per 600 ms",
        started.elapsed()
    );
    assert_eq!(received, LEN);
}

/// A route with `precompressed = true` serves through its own path (sidecar negotiation), which
/// takes its slot as the plain one does: one connection that never opens its windows holds at
/// most eight files open.
#[test]
fn a_precompressed_route_holds_at_most_eight_files_open() {
    const STREAMS: usize = 64;
    let Some(zion) = Zion::start_route("", "precompressed = true", &[("big.bin", BIG_BYTES)])
    else {
        return;
    };
    let Some(before) = zion.open_fds_to("big.bin") else {
        common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
        return;
    };
    let requests: Vec<u8> = (0..STREAMS)
        .flat_map(|i| get(stream_id(i), "big.bin"))
        .collect();
    let t0 = Instant::now();
    let mut peers = vec![Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &requests)];
    let mut seen = Seen::default();
    let mut peak = before;
    for _ in 0..6 {
        seen.read(&mut peers, Duration::from_millis(250), t0);
        if let Some(n) = zion.open_fds_to("big.bin") {
            peak = peak.max(n);
        }
    }
    eprintln!(
        "precompressed route: fds {before} -> {peak}, {} responses began",
        seen.begun.len()
    );
    assert_eq!(seen.begun.len(), STATIC_FILES_PER_CONN);
    assert!(peak > before, "no descriptor to the file was seen");
    assert!(
        peak - before <= STATIC_FILES_PER_CONN,
        "{} descriptors open",
        peak - before
    );
}

/// Requests that wait for an address's share behind clients that do not read are served once
/// `send_stall_secs` resets those, when that comes before their wait runs out; and an address
/// whose clients read takes far more responses than its share in turn, none refused.
#[test]
fn waiting_for_the_share_ends_with_the_deadline_of_the_stalled_and_never_for_readers() {
    const STALL_SECS: u64 = 3;
    let Some(zion) = Zion::start(
        &format!("max_connections = {BUDGET_CONNS}\nsend_stall_secs = {STALL_SECS}"),
        &[("big.bin", BIG_BYTES)],
    ) else {
        return;
    };
    // 1. 32 requests on four connections that never open a window: the share begins, the rest
    //    wait; at the deadline the share is reset, and the waiting ones begin in its place.
    let requests: Vec<u8> = (0..STATIC_FILES_PER_CONN)
        .flat_map(|i| get(stream_id(i), "big.bin"))
        .collect();
    let t0 = Instant::now();
    let mut peers: Vec<Peer> = (0..4)
        .map(|_| Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &requests))
        .collect();
    let mut seen = Seen::default();
    seen.read(&mut peers, Duration::from_secs(1), t0);
    let first = seen.begun.len();
    seen.read(&mut peers, Duration::from_secs(STALL_SECS + 2), t0);
    let late = seen.begun.len() - first;
    eprintln!(
        "{first} began at once; {late} more by {:?}, after {} resets at {:?}; {} refused",
        t0.elapsed(),
        seen.reset.len(),
        seen.reset.values().map(|(_, at)| *at).min(),
        seen.refused.len()
    );
    assert_eq!(first, SHARE_STREAMED);
    assert_eq!(late, 4 * STATIC_FILES_PER_CONN - SHARE_STREAMED);
    assert!(seen.refused.is_empty(), "a request was refused");
    drop(peers);

    // 2. Readers: 64 requests for the file on four connections, windows wide open, all from
    //    one address. Each waits at most for a reader to finish.
    let max_window = [0x00, 0x04, 0x7f, 0xff, 0xff, 0xff];
    let mut open = window_update(0, (1 << 31) - 1 - 65_535);
    open.extend((0..16).flat_map(|i| get(stream_id(i), "big.bin")));
    let t1 = Instant::now();
    let mut peers: Vec<Peer> = (0..4)
        .map(|_| Peer::open(zion.https, &max_window, &open))
        .collect();
    let mut ended = std::collections::BTreeSet::new();
    let mut bytes = 0usize;
    while ended.len() < 64 {
        assert!(
            t1.elapsed() < Duration::from_secs(30),
            "{} of 64 read in 30 s",
            ended.len()
        );
        for (i, peer) in peers.iter_mut().enumerate() {
            for f in peer.frames(Duration::from_millis(20)) {
                assert!(f.ty != GOAWAY && f.ty != RST_STREAM, "frame type {}", f.ty);
                if f.ty == HEADERS && f.flags & END_STREAM != 0 {
                    panic!("connection {i} stream {} refused", f.stream);
                }
                if f.ty == DATA {
                    bytes += f.payload.len();
                    if f.flags & END_STREAM != 0 {
                        ended.insert((i, f.stream));
                    }
                }
            }
        }
    }
    eprintln!(
        "64 responses of 2 MiB read in {:?} from one address",
        t1.elapsed()
    );
    assert_eq!(bytes, 64 * BIG_BYTES);
}

/// A TLS client to `localhost` on `tcp`, its handshake finished on the blocking socket, then a
/// 50 ms read timeout set for the reads the tests poll with. rustls reads during the handshake,
/// and under the timeout a server slower than 50 ms (a loaded CI runner) made that read fail
/// with `WouldBlock`.
fn tls_connect(
    cfg: Arc<rustls::ClientConfig>,
    mut tcp: TcpStream,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let mut conn = rustls::ClientConnection::new(
        cfg,
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).unwrap();
    }
    tcp.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    rustls::StreamOwned::new(conn, tcp)
}

/// An HTTP/1.1 client over TLS whose socket receive buffer is 16 KiB, so the server's sends
/// stop as soon as the client stops reading, after it has sent `GET <path>`.
fn h1_get(port: u16, path: &str) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    sock.set_recv_buffer_size(16 * 1024).unwrap();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    sock.connect(&addr.into()).unwrap();
    let tcp: TcpStream = sock.into();
    let mut tls = tls_connect(Arc::new(cfg), tcp);
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    tls.write_all(req.as_bytes()).unwrap();
    tls.flush().unwrap();
    tls
}

/// Read what has arrived on `io` within `wait`: the bytes, and whether the connection ended.
fn h1_read(io: &mut impl Read, wait: Duration, limit: usize) -> (Vec<u8>, bool) {
    let until = Instant::now() + wait;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    while Instant::now() < until && got.len() < limit {
        let want = buf.len().min(limit - got.len());
        match io.read(&mut buf[..want]) {
            Ok(0) => return (got, true),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return (got, true),
        }
    }
    (got, false)
}

/// HTTP/1.1 clients that stop reading a large static file hold their address's share until
/// `send_stall_secs` closes their connections, as HTTP/2 resets their streams: a request from the
/// same address that waits for the share is then served, not answered `503` after its wait.
#[test]
fn http1_connections_that_stop_reading_are_closed_at_the_deadline_and_free_the_share() {
    const STALL_SECS: u64 = 3;
    let Some(zion) = Zion::start(
        &format!("max_connections = {BUDGET_CONNS}\nsend_stall_secs = {STALL_SECS}"),
        &[("huge.bin", HUGE_BYTES)],
    ) else {
        return;
    };
    let Some(before) = zion.open_fds_to("huge.bin") else {
        common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
        return;
    };
    let t0 = Instant::now();
    let mut holders: Vec<_> = (0..SHARE_STREAMED)
        .map(|_| h1_get(zion.https, "/files/huge.bin"))
        .collect();
    std::thread::sleep(Duration::from_millis(1000));
    let held = zion.open_fds_to("huge.bin").unwrap_or(0);
    // One more from the same address: it waits for the share.
    let mut next = h1_get(zion.https, "/files/huge.bin");
    let (head, _) = loop {
        let (got, ended) = h1_read(&mut next, Duration::from_millis(100), 16);
        if !got.is_empty() || ended || t0.elapsed() > Duration::from_secs(20) {
            break (got, ended);
        }
    };
    let answered = t0.elapsed();
    let head = String::from_utf8_lossy(&head).to_string();
    // The holders: their connections were closed (a holder whose kernel took bytes later than the
    // others is closed a deadline after that, so look once every one has had time).
    std::thread::sleep(Duration::from_secs(2 * STALL_SECS + 2).saturating_sub(t0.elapsed()));
    let mut closed = 0;
    for h in &mut holders {
        // What the kernels buffered first, then the end.
        let (_, ended) = h1_read(h, Duration::from_secs(3), usize::MAX);
        closed += usize::from(ended);
    }
    let after = zion.open_fds_to("huge.bin").unwrap_or(0);
    eprintln!(
        "http/1.1: {held} fds held by {SHARE_STREAMED} clients not reading; the next from the \
         address answered {head:?} at {answered:?}; {closed} holders closed; fds {before} -> \
         {after}"
    );
    assert_eq!(
        held - before,
        SHARE_STREAMED,
        "the holders did not hold the share"
    );
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "the waiting request got {head:?}, not the share the closed holders freed"
    );
    assert!(
        answered >= Duration::from_millis(STALL_SECS * 1000 - 500)
            && answered < Duration::from_secs(STALL_SECS + 4),
        "answered at {answered:?}, not at the {STALL_SECS} s deadline"
    );
    assert_eq!(closed, SHARE_STREAMED, "a holder's connection stayed open");
    assert!(
        after - before <= 1,
        "{} descriptors to the file left open",
        after - before
    );
    drop(next);
    assert!(
        metric(zion.https, "zion_streams_stalled_total").unwrap_or(0) >= SHARE_STREAMED as u64,
        "the closes were not counted"
    );
}

/// An HTTP/1.1 client that reads slowly but steadily, 64 KiB every 300 ms through a 16 KiB
/// receive buffer, under a 2 s deadline: the deadline counts from the last bytes the client
/// took, so it is never cut, though the response takes several deadlines.
#[test]
fn a_slow_steady_http1_reader_is_never_cut() {
    const STALL_SECS: u64 = 2;
    let Some(zion) = Zion::start(
        &format!("send_stall_secs = {STALL_SECS}"),
        &[("big.bin", BIG_BYTES)],
    ) else {
        return;
    };
    let mut io = h1_get(zion.https, "/files/big.bin");
    let started = Instant::now();
    let mut got = Vec::new();
    let mut ended = false;
    while !ended && got.len() < BIG_BYTES {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{} bytes in 60 s",
            got.len()
        );
        let (more, end) = h1_read(&mut io, Duration::from_millis(50), STREAM_FRAME);
        got.extend(more);
        ended = end;
        std::thread::sleep(Duration::from_millis(250));
    }
    let took = started.elapsed();
    // The body is what follows the head.
    let body_at = got
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |p| p + 4);
    let mut body = got.len() - body_at;
    while body < BIG_BYTES && !ended {
        let (more, end) = h1_read(&mut io, Duration::from_millis(200), usize::MAX);
        body += more.len();
        ended = end;
    }
    eprintln!("http/1.1 slow reader: {body} body bytes in {took:?}, ended early: {ended}");
    assert_eq!(body, BIG_BYTES, "the slow reader was cut after {took:?}");
    assert!(
        took > Duration::from_secs(2 * STALL_SECS),
        "the response took {took:?}: it does not prove a response may outlast the deadline"
    );
}

/// A proxied download over HTTP/1.1 that its client stops reading: the connection is closed at
/// the deadline (the upstream connection with it), so the client gets a short body.
#[test]
fn a_proxied_http1_download_its_client_stops_reading_is_closed_at_the_deadline() {
    const STALL_SECS: u64 = 2;
    const LEN: usize = 16 * 1024 * 1024;
    let origin = big_chunk_origin(LEN);
    let route = format!("\n[upstreams]\norigin = \"http://127.0.0.1:{origin}\"\n")
        + "[[route]]\npath = \"/proxy/{*rest}\"\nupstream = \"origin\"\nmode = \"standard\"\n";
    let Some(zion) = Zion::start_route(&format!("send_stall_secs = {STALL_SECS}"), &route, &[])
    else {
        return;
    };
    let mut io = h1_get(zion.https, "/proxy/big");
    // Take the head, then nothing for twice the deadline.
    let (head, _) = h1_read(&mut io, Duration::from_millis(1000), 1024);
    std::thread::sleep(Duration::from_secs(2 * STALL_SECS));
    let mut total = head.len();
    let mut ended = false;
    let until = Instant::now() + Duration::from_secs(30);
    while !ended && Instant::now() < until {
        let (more, end) = h1_read(&mut io, Duration::from_millis(200), usize::MAX);
        total += more.len();
        ended = end;
    }
    eprintln!(
        "http/1.1 proxied, not read for {} s: {total} bytes then closed: {ended}",
        2 * STALL_SECS
    );
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    assert!(ended, "the connection was not closed");
    assert!(
        total < LEN,
        "the whole body arrived ({total} bytes): the connection was not closed at the deadline"
    );
}

/// About eight client addresses that fill their shares spend the budget for the whole process:
/// a ninth client then gets what is left, and `503` after its wait, until `send_stall_secs`
/// resets the holders. The addresses are clients named by a trusted proxy: on macOS the
/// loopback aliases 127.0.0.2 and up need root to configure.
#[test]
fn eight_addresses_that_fill_their_shares_spend_the_budget_until_the_deadline() {
    const STALL_SECS: u64 = 15;
    let Some(zion) = Zion::start(
        &format!(
            "max_connections = {BUDGET_CONNS}\nsend_stall_secs = {STALL_SECS}\n\
             trusted_proxies = [\"127.0.0.1/32\"]"
        ),
        &[("big.bin", BIG_BYTES)],
    ) else {
        return;
    };
    let t0 = Instant::now();
    // Eight clients, 21 requests each, over two proxy connections (128 streams at most each).
    let mut peers: Vec<Peer> = (0..2)
        .map(|c| {
            let reqs: Vec<u8> = (0..4 * SHARE_STREAMED)
                .flat_map(|i| {
                    let client = c * 4 + i / SHARE_STREAMED;
                    get_xff(stream_id(i), "big.bin", &format!("10.8.0.{client}"))
                })
                .collect();
            Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &reqs)
        })
        .collect();
    let mut seen = Seen::default();
    seen.read(&mut peers, Duration::from_secs(2), t0);
    let eight = seen.begun.len();
    // A ninth client, five requests.
    let ninth: Vec<u8> = (0..5)
        .flat_map(|i| get_xff(stream_id(i), "big.bin", "10.9.0.1"))
        .collect();
    peers.push(Peer::open(zion.https, &INITIAL_WINDOW_ZERO, &ninth));
    seen.read(&mut peers, Duration::from_secs(1), t0);
    let ninth_begun = seen.begun.iter().filter(|(c, _)| *c == 2).count();
    // Its others are refused after their wait; the holders are reset at the deadline.
    seen.read(
        &mut peers,
        Duration::from_secs(STALL_SECS + 2).saturating_sub(t0.elapsed()),
        t0,
    );
    let refused: Vec<Duration> = seen
        .refused
        .iter()
        .filter(|((c, _), _)| *c == 2)
        .map(|(_, at)| *at)
        .collect();
    let first_reset = seen.reset.values().map(|(_, at)| *at).min();
    // After the resets, the ninth client is served again.
    let again = stream_id(5);
    peers[2].send(&get_xff(again, "big.bin", "10.9.0.1"));
    let asked = t0.elapsed();
    seen.read(&mut peers, Duration::from_secs(2), t0);
    let served_again = seen.begun.contains(&(2, again));
    eprintln!(
        "{eight} began for eight clients; the ninth: {ninth_begun} of 5 began, {} refused at \
         {refused:?}; first reset at {first_reset:?}; asked again at {asked:?}: began {served_again}",
        refused.len(),
        refused = refused,
        first_reset = first_reset,
        asked = asked,
        served_again = served_again,
    );
    assert_eq!(eight, 8 * SHARE_STREAMED);
    assert_eq!(ninth_begun, BUDGET_STREAMED - 8 * SHARE_STREAMED);
    assert_eq!(
        refused.len(),
        5 - ninth_begun,
        "the ninth's others were not refused"
    );
    assert!(refused.iter().all(|at| *at >= BUDGET_WAIT));
    assert!(
        served_again,
        "the ninth client was not served after the holders were reset"
    );
}

/// The same two bounds on HTTP/3. QUIC flow control lets a client withhold credit on a stream
/// as HTTP/2's lets it withhold window, a connection carries 256 request streams, and a client
/// that answers PINGs keeps it up: each request for a streamed file held the file open, with
/// no deadline.
#[cfg(feature = "http3")]
mod http3 {
    use super::*;

    /// Stream credit the client grants: room for the server's control streams (its SETTINGS),
    /// not for the `HEADERS` of a response, so no response gets anywhere.
    const CREDIT: u32 = 64;

    /// The client's half of an HTTP/3 connection to zion's QUIC listener, and the requests it
    /// sent: each finished, none read.
    struct Client {
        _driver: tokio::task::JoinHandle<()>,
        /// h3 closes the connection when the last of these is dropped.
        _send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        requests: Vec<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>>,
        _endpoint: quinn::Endpoint,
    }

    use bytes::Bytes;

    /// Connect to `port` granting `credit` bytes per stream (more as the client reads), keep
    /// the connection alive with PINGs, and send `n` requests for `/files/<name>`.
    async fn connect(port: u16, credit: u32, name: &str, n: usize) -> Client {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(credit.into())
            .keep_alive_interval(Some(Duration::from_secs(1)));
        let mut cfg = quinn::ClientConfig::new(Arc::new(qc));
        cfg.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(cfg);
        let until = Instant::now() + Duration::from_secs(10);
        let conn = loop {
            let attempt = endpoint
                .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
                .unwrap()
                .await;
            match attempt {
                Ok(c) => break c,
                Err(e) => {
                    assert!(Instant::now() < until, "no HTTP/3 listener: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let _driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut requests = Vec::new();
        for _ in 0..n {
            let req = hyper::Request::get(format!("https://localhost/files/{name}"))
                .body(())
                .unwrap();
            let mut stream = send.clone().send_request(req).await.unwrap();
            stream.finish().await.unwrap();
            requests.push(stream);
        }
        Client {
            _driver,
            _send: send,
            requests,
            _endpoint: endpoint,
        }
    }

    /// One QUIC connection, 128 requests for a streamed file, and a client that grants no
    /// credit for their responses: at most eight files are opened, as on HTTP/2.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_h3_connection_that_grants_no_credit_holds_at_most_eight_files_open() {
        const STREAMS: usize = 128;
        let Some(zion) = Zion::start("", &[("big.bin", BIG_BYTES)]) else {
            return;
        };
        let Some(before) = zion.open_fds_to("big.bin") else {
            common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
            return;
        };
        let client = connect(zion.https, CREDIT, "big.bin", STREAMS).await;
        let mut peak = before;
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if let Some(n) = zion.open_fds_to("big.bin") {
                peak = peak.max(n);
            }
        }
        let held = peak.saturating_sub(before);
        eprintln!(
            "h3: open fds to the served file: {before} before, {peak} while {} requests \
             waited for credit on one connection",
            client.requests.len()
        );
        assert!(
            held > 0,
            "no descriptor to the file was open ({before} -> {peak}): not measuring the hold"
        );
        assert!(
            held <= STATIC_FILES_PER_CONN,
            "one HTTP/3 connection that grants no credit held {held} descriptors to the file \
             ({before} -> {peak}), over the {STATIC_FILES_PER_CONN} a connection may hold"
        );
        drop(client);
    }

    /// One address, sixteen QUIC connections (QUIC has no per-address connection cap), eight
    /// requests for a streamed file on each, no credit granted: the address holds at most its
    /// share of the budget, as over HTTP/2.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_address_over_many_h3_connections_holds_at_most_its_share() {
        const CONNS: usize = 16;
        let Some(zion) = Zion::start(
            &format!("max_connections = {BUDGET_CONNS}"),
            &[("big.bin", BIG_BYTES)],
        ) else {
            return;
        };
        let Some(before) = zion.open_fds_to("big.bin") else {
            common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
            return;
        };
        let mem_before = zion.memory_mib();
        let mut clients = Vec::new();
        for _ in 0..CONNS {
            clients.push(connect(zion.https, CREDIT, "big.bin", STATIC_FILES_PER_CONN).await);
        }
        let (mut peak, mut mem_peak) = (before, mem_before);
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if let Some(n) = zion.open_fds_to("big.bin") {
                peak = peak.max(n);
            }
            mem_peak = mem_peak.max(zion.memory_mib());
        }
        let held = peak.saturating_sub(before);
        eprintln!(
            "h3, one address, {CONNS} connections x {STATIC_FILES_PER_CONN} requests: open fds \
             to the file {before} -> {peak}, memory {mem_before} -> {mem_peak} MiB"
        );
        assert!(held > 0, "no descriptor to the file was open");
        assert!(
            held <= SHARE_STREAMED,
            "one address held {held} descriptors to the file over HTTP/3, over its share of \
             {SHARE_STREAMED}"
        );
        assert_eq!(held, SHARE_STREAMED, "the share was not all used");
        drop(clients);
    }

    /// A stream whose client grants no credit is reset with `H3_REQUEST_CANCELLED` once its
    /// response has waited `send_stall_secs`, its file is closed, and the reset is counted.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_h3_stream_is_reset_and_frees_its_file() {
        const STALL_SECS: u64 = 2;
        let Some(zion) = Zion::start(
            &format!("send_stall_secs = {STALL_SECS}"),
            &[("big.bin", BIG_BYTES)],
        ) else {
            return;
        };
        let Some(before) = zion.open_fds_to("big.bin") else {
            common::skip("cannot read the daemon's open descriptors (no lsof, no /proc)");
            return;
        };
        let mut client = connect(zion.https, CREDIT, "big.bin", STATIC_FILES_PER_CONN).await;
        // Read nothing until the deadline has passed: reading is what grants credit.
        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let held = zion.open_fds_to("big.bin").unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(STALL_SECS * 1000 - 1000)).await;
        let before_deadline = zion.open_fds_to("big.bin").unwrap_or(0);
        let mut now = before_deadline;
        while now > before && started.elapsed() < Duration::from_secs(STALL_SECS + 8) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            now = zion.open_fds_to("big.bin").unwrap_or(now);
        }
        let freed_at = started.elapsed();
        let mut outcomes = Vec::new();
        for stream in &mut client.requests {
            let got = tokio::time::timeout(Duration::from_secs(5), stream.recv_response()).await;
            outcomes.push(format!("{:?}", got.map(|r| r.map(|resp| resp.status()))));
        }
        eprintln!(
            "h3: fds {before} -> {held} -> {before_deadline} at {:?} -> {now} at {freed_at:?}; \
             outcomes {outcomes:?}",
            Duration::from_millis(STALL_SECS * 1000 - 500),
            freed_at = freed_at,
        );
        assert!(held > before, "the stalled responses held no descriptor");
        assert_eq!(
            before_deadline, held,
            "descriptors were freed before the {STALL_SECS} s deadline"
        );
        assert_eq!(
            now, before,
            "{now} descriptors stayed open after the deadline"
        );
        for got in &outcomes {
            assert!(
                got.contains("H3_REQUEST_CANCELLED"),
                "a stalled stream was not reset with H3_REQUEST_CANCELLED: {got}"
            );
        }
        let page = String::from_utf8(fetch(zion.https, "/metrics", &[])).unwrap();
        let counted = page
            .lines()
            .find_map(|l| l.strip_prefix("zion_streams_stalled_total "))
            .and_then(|v| v.trim().parse::<usize>().ok());
        assert_eq!(counted, Some(STATIC_FILES_PER_CONN), "resets counted");
    }

    /// A small file read whole, to a client that grants credit for the response's headers and
    /// a little of its body, then reads nothing: reset at the deadline, as on HTTP/2.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_small_file_never_read_over_h3_is_reset_at_the_deadline() {
        const STALL_SECS: u64 = 2;
        let Some(zion) = Zion::start(
            &format!("send_stall_secs = {STALL_SECS}"),
            &[("icon.svg", 20 * 1024)],
        ) else {
            return;
        };
        let mut client = connect(zion.https, 4096, "icon.svg", 1).await;
        let started = Instant::now();
        let stream = &mut client.requests[0];
        let resp = stream.recv_response().await.expect("a response");
        assert_eq!(resp.status(), 200);
        // Take nothing more until the deadline has passed, then see how the body ends.
        tokio::time::sleep(Duration::from_secs(STALL_SECS + 1)).await;
        let outcome;
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.recv_data()).await {
                Ok(Ok(Some(mut chunk))) => {
                    use bytes::Buf;
                    chunk.advance(chunk.remaining());
                }
                Ok(Ok(None)) => {
                    outcome = "the body ended whole".to_string();
                    break;
                }
                Ok(Err(e)) => {
                    outcome = format!("{e:?}");
                    break;
                }
                Err(_) => {
                    outcome = "nothing within 5 s".to_string();
                    break;
                }
            }
        }
        eprintln!("h3 small file: {outcome} after {:?}", started.elapsed());
        assert!(
            outcome.contains("H3_REQUEST_CANCELLED"),
            "the stalled small response was not reset: {outcome}"
        );
    }

    /// A client that reads slowly but steadily: 64 KiB of credit, all of it taken every 400 ms,
    /// so the response takes about four seconds, twice the deadline. It is never reset: the
    /// deadline counts per send of 64 KiB, from the last one the client took.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_h3_reader_is_never_reset() {
        const STALL_SECS: u64 = 2;
        const SLOW_BYTES: usize = 10 * STREAM_FRAME;
        let Some(zion) = Zion::start(
            &format!("send_stall_secs = {STALL_SECS}"),
            &[("slow.bin", SLOW_BYTES)],
        ) else {
            return;
        };
        let mut client = connect(zion.https, STREAM_FRAME as u32, "slow.bin", 1).await;
        let started = Instant::now();
        let stream = &mut client.requests[0];
        let resp = stream.recv_response().await.expect("a response");
        assert_eq!(resp.status(), 200);
        // Every 400 ms take 64 KiB, or what has arrived if that is less; taking it grants
        // the client's credit back.
        let mut received = 0;
        let mut done = false;
        while !done {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let period = received;
            while received - period < STREAM_FRAME {
                let next = tokio::time::timeout(Duration::from_millis(20), stream.recv_data());
                match next.await {
                    Err(_) => break, // nothing more has arrived
                    Ok(Ok(Some(mut chunk))) => {
                        use bytes::Buf;
                        received += chunk.remaining();
                        chunk.advance(chunk.remaining());
                    }
                    Ok(Ok(None)) => {
                        done = true;
                        break;
                    }
                    Ok(Err(e)) => panic!(
                        "the slow reader was cut after {:?}, {received} of {SLOW_BYTES} bytes \
                         in: {e:?}",
                        started.elapsed(),
                        e = e,
                    ),
                }
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "{received} bytes in 30 s"
            );
        }
        let took = started.elapsed();
        eprintln!("h3: {received} bytes in {took:?}, taken every 400 ms");
        assert_eq!(received, SLOW_BYTES);
        assert!(
            took > Duration::from_secs(STALL_SECS),
            "the response took {took:?}: it does not prove a response may outlast the deadline"
        );
    }
}
