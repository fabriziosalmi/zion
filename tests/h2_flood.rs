// SPDX-License-Identifier: Apache-2.0
//! The HTTP/2 control-frame bound (#475), with the real binary and raw frames.
//!
//! A connection that sends `PING`, `SETTINGS`, `WINDOW_UPDATE` or frames of a type the server
//! skips, faster than `[server] h2_control_frames_per_sec` allows, is closed; it used to be
//! served for as long as the client cared to send. The bound holds however the client got to
//! HTTP/2: ALPN `h2`, TLS with no ALPN, or the preface on the plaintext listener. A download
//! acknowledged with as many `WINDOW_UPDATE`s as a conforming client can send is not a flood.
//!
//! Like the drain tests, a missing `openssl` (for a throwaway certificate) skips with a message.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod common;
use common::free_port;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const RST_STREAM: u8 = 0x3;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
/// The limit the tests set: far above what the test client sends when it behaves.
const LIMIT: u32 = 50;
/// The body of the download test.
const BIG: usize = 48 * 1024 * 1024;

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
    /// Start zion with `h2_control_frames_per_sec = limit` (or the default when `None`) and a
    /// static route; `None` when `openssl` is unavailable.
    fn start(limit: Option<u32>) -> Option<Zion> {
        let (http, https) = (free_port(), free_port());
        let dir = std::env::temp_dir().join(format!("zion-h2flood-{}-{http}", std::process::id()));
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
        std::fs::write(dir.join("www/big.bin"), big_body()).unwrap();
        std::fs::write(dir.join("www/small.txt"), "hello\n").unwrap();
        // Larger than the 64 KiB a connection may be sent before its first WINDOW_UPDATE,
        // so a download of it that the client never acknowledges stays in flight.
        std::fs::write(dir.join("www/mid.bin"), &big_body()[..256 * 1024]).unwrap();
        let limit = limit
            .map(|l| format!("h2_control_frames_per_sec = {l}\n"))
            .unwrap_or_default();
        let cfg = dir.join("zion.toml");
        std::fs::write(
            &cfg,
            format!(
                "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n{limit}\
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
            .stderr(std::fs::File::create(dir.join("zion.log")).unwrap())
            .spawn()
            .expect("spawn zion");
        let zion = Zion {
            child,
            http,
            https,
            dir,
        };
        for port in [http, https] {
            let deadline = Instant::now() + Duration::from_secs(20);
            while TcpStream::connect(("127.0.0.1", port)).is_err() {
                assert!(Instant::now() < deadline, "zion did not start listening");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Some(zion)
    }

    /// How many times `needle` is in zion's log, once it is there `want` times (log lines
    /// are written by a thread of their own, a moment after the event), or as seen last.
    fn logged(&self, needle: &str, want: usize) -> usize {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let log = std::fs::read_to_string(self.dir.join("zion.log")).unwrap_or_default();
            let seen = log.matches(needle).count();
            if seen >= want || Instant::now() > deadline {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The value of a `/metrics` line, once `ok` holds for it (the page is rendered at most
    /// once a second), or the last value seen.
    fn metric(&self, line_start: &str, ok: impl Fn(u64) -> bool) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut tls = connect(self.https, Transport::TlsNoAlpn);
            tls.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut page = Vec::new();
            let _ = tls.read_to_end(&mut page);
            let page = String::from_utf8_lossy(&page);
            let seen = page
                .lines()
                .find(|l| l.starts_with(line_start))
                .and_then(|l| l.split_whitespace().last())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("no `{line_start}` in /metrics:\n{page}"));
            if ok(seen) || Instant::now() > deadline {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn closed_for(&self, reason: &str, ok: impl Fn(u64) -> bool) -> u64 {
        self.metric(
            &format!("zion_h2_control_flood_closed_total{{reason=\"{reason}\"}}"),
            ok,
        )
    }
}

/// Deterministic, not compressible to a constant: a wrong or reordered byte shows.
fn big_body() -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut body = Vec::with_capacity(BIG);
    while body.len() < BIG {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        body.extend_from_slice(&x.to_le_bytes());
    }
    body
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

/// How the client reaches HTTP/2. hyper serves it to any connection that opens with the
/// preface, so each of these is a way in, and the bound has to hold on all three.
#[derive(Clone, Copy, Debug)]
enum Transport {
    /// TLS, ALPN `h2`: what every real client does.
    TlsAlpnH2,
    /// TLS that offers no ALPN protocol, then the preface.
    TlsNoAlpn,
    /// The plaintext listener, then the preface ("prior knowledge").
    Plaintext,
}

trait Conn: Read + Write + Send {}
impl<T: Read + Write + Send> Conn for T {}

fn connect_port(zion: &Zion, how: Transport) -> Box<dyn Conn> {
    match how {
        Transport::Plaintext => connect(zion.http, how),
        _ => connect(zion.https, how),
    }
}

fn connect(port: u16, how: Transport) -> Box<dyn Conn> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    tcp.set_nodelay(true).unwrap();
    if matches!(how, Transport::Plaintext) {
        return Box::new(tcp);
    }
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    if matches!(how, Transport::TlsAlpnH2) {
        cfg.alpn_protocols = vec![b"h2".to_vec()];
    }
    let conn = rustls::ClientConnection::new(
        Arc::new(cfg),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    Box::new(rustls::StreamOwned::new(conn, tcp))
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

/// One HTTP/2 frame: (type, flags, stream, payload), or `None` on EOF, reset or read timeout.
fn read_frame(s: &mut dyn Conn) -> Option<(u8, u8, u32, Vec<u8>)> {
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

/// The error code of a `GOAWAY` payload (the four bytes after the last stream id);
/// `u32::MAX` for a payload too short to hold one.
fn goaway_code(payload: &[u8]) -> u32 {
    match payload.get(4..8) {
        Some(code) => u32::from_be_bytes([code[0], code[1], code[2], code[3]]),
        None => u32::MAX,
    }
}

/// What the server sent until it closed the connection (or stopped talking).
#[derive(Debug, Default)]
struct Seen {
    ping_acks: usize,
    settings_acks: usize,
    /// The error code of a `GOAWAY`, if one arrived.
    goaway: Option<u32>,
    /// The connection ended (EOF or reset), as opposed to the read timing out.
    ended: bool,
}

fn drain(conn: &mut dyn Conn, patience: Duration) -> Seen {
    let mut seen = Seen::default();
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        match read_frame(conn) {
            Some((PING, flags, _, _)) if flags & 1 == 1 => seen.ping_acks += 1,
            Some((SETTINGS, flags, _, _)) if flags & 1 == 1 => seen.settings_acks += 1,
            Some((GOAWAY, _, _, p)) => seen.goaway = Some(goaway_code(&p)),
            Some(_) => {}
            None => {
                // EOF, a reset, or the read timeout: only the first two are an end.
                let mut probe = [0u8; 1];
                seen.ended = !matches!(
                    conn.read(&mut probe),
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
                );
                break;
            }
        }
    }
    seen
}

/// The payload of the next PING ack, skipping other frames; `None` if the connection ends.
fn pong(conn: &mut dyn Conn) -> Option<Vec<u8>> {
    loop {
        match read_frame(conn) {
            Some((PING, 1, _, payload)) => return Some(payload),
            Some(_) => {}
            None => return None,
        }
    }
}

/// `GET path` on `stream`, complete (HPACK: `:method GET`, `:scheme https`, then `:path` and
/// `:authority` as literals).
fn get(stream: u32, path: &str) -> Vec<u8> {
    let mut hpack = vec![0x82, 0x87, 0x44, path.len() as u8];
    hpack.extend_from_slice(path.as_bytes());
    hpack.extend_from_slice(&[0x41, 9]);
    hpack.extend_from_slice(b"localhost");
    frame(HEADERS, 0x5, stream, &hpack)
}

/// Write `bytes` as fast as the connection takes them; `false` when the server stopped
/// taking them (it closed the connection under the client).
fn pour(conn: &mut dyn Conn, bytes: &[u8]) -> bool {
    for chunk in bytes.chunks(64 * 1024) {
        if conn.write_all(chunk).is_err() {
            return false;
        }
    }
    conn.flush().is_ok()
}

/// One more control frame than the limit, in one write, and then silence: with nothing left
/// unread on the socket the `GOAWAY` reaches the client instead of a reset, so what it says
/// can be checked. Over the three ways into HTTP/2.
#[test]
fn a_connection_over_the_limit_is_told_enhance_your_calm_and_closed() {
    let Some(zion) = Zion::start(Some(LIMIT)) else {
        return;
    };
    for (i, how) in [
        Transport::TlsAlpnH2,
        Transport::TlsNoAlpn,
        Transport::Plaintext,
    ]
    .into_iter()
    .enumerate()
    {
        if i > 0 {
            // The log line is throttled to one a second: each listener gets its own.
            std::thread::sleep(Duration::from_millis(1100));
        }
        let mut conn = connect_port(&zion, how);
        // SETTINGS is the first control frame; LIMIT PINGs make LIMIT + 1.
        let mut out = PREFACE.to_vec();
        out.extend(frame(SETTINGS, 0, 0, &[]));
        out.extend(frame(PING, 0, 0, &[7; 8]).repeat(LIMIT as usize));
        conn.write_all(&out).unwrap();
        conn.flush().unwrap();
        let seen = drain(&mut *conn, Duration::from_secs(10));
        assert!(seen.ended, "{how:?}: zion closed the connection: {seen:?}");
        assert_eq!(
            seen.goaway,
            Some(0xb),
            "{how:?}: with GOAWAY(ENHANCE_YOUR_CALM): {seen:?}"
        );
        assert!(
            seen.ping_acks < LIMIT as usize,
            "{how:?}: the frames past the limit were not served: {seen:?}"
        );
        let want = i as u64 + 1;
        assert_eq!(
            zion.closed_for("control_frames", |n| n >= want),
            want,
            "{how:?}: counted in zion_h2_control_flood_closed_total"
        );
        // Logged with the client address and the setting that closed it.
        let line = format!(
            "HTTP/2 control-frame flood from 127.0.0.1: connection closed \
             (h2_control_frames_per_sec = {LIMIT})"
        );
        assert_eq!(zion.logged(&line, i + 1), i + 1, "{how:?}: logged");
    }
    assert_eq!(zion.closed_for("window_update", |_| true), 0);
}

/// The floods of the issue, at wire speed: each ends with the connection closed after about
/// LIMIT frames, where it used to be served to the last frame.
#[test]
fn floods_at_wire_speed_are_cut_off() {
    let Some(zion) = Zion::start(Some(LIMIT)) else {
        return;
    };
    // (name, what the client sends first, the frame it floods, the reason counted)
    let floods: [(&str, Vec<u8>, Vec<u8>, &str); 6] = [
        ("PING", vec![], frame(PING, 0, 0, &[7; 8]), "control_frames"),
        (
            "SETTINGS",
            vec![],
            frame(SETTINGS, 0, 0, &[]),
            "control_frames",
        ),
        (
            "WINDOW_UPDATE",
            vec![],
            frame(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1]),
            "window_update",
        ),
        // A type the server does not know and skips: not a way around the limit.
        (
            "unknown type 0xfa",
            vec![],
            frame(0xfa, 0, 0, &[]),
            "control_frames",
        ),
        // PRIORITY for a stream that was never opened.
        (
            "PRIORITY",
            vec![],
            frame(0x2, 0, 3, &[0, 0, 0, 0, 16]),
            "control_frames",
        ),
        // One request, then its stream reset over and over: the first reset cancels a
        // stream the client opened, the others cancel nothing.
        (
            "RST_STREAM of one stream",
            get(1, "/files/small.txt"),
            frame(RST_STREAM, 0, 1, &[0, 0, 0, 8]),
            "control_frames",
        ),
    ];
    let (mut control, mut window) = (0u64, 0u64);
    for (name, first, one, reason) in floods {
        let mut conn = connect_port(&zion, Transport::TlsAlpnH2);
        let mut out = PREFACE.to_vec();
        out.extend(frame(SETTINGS, 0, 0, &[]));
        out.extend(first);
        out.extend(one.repeat(200_000));
        let took_it_all = pour(&mut *conn, &out);
        let seen = drain(&mut *conn, Duration::from_secs(10));
        assert!(
            !took_it_all || seen.ended,
            "{name}: zion stopped reading or closed: {seen:?}"
        );
        assert!(
            seen.ping_acks <= LIMIT as usize && seen.settings_acks <= LIMIT as usize + 1,
            "{name}: at most the limit was served: {seen:?}"
        );
        match reason {
            "control_frames" => control += 1,
            _ => window += 1,
        }
        assert_eq!(
            zion.closed_for("control_frames", |n| n >= control),
            control,
            "{name}"
        );
        assert_eq!(
            zion.closed_for("window_update", |n| n >= window),
            window,
            "{name}"
        );
    }
    // The server is still serving.
    assert!(zion.metric("zion_h2_control_frames_peak", |_| true) > u64::from(LIMIT));
}

/// With no limit configured (the default) nothing changes: every PING of a flood is answered
/// and the connection stays open. The peak gauge reports the rate, which is what an operator
/// reads before choosing a limit.
#[test]
fn by_default_frames_are_counted_and_nothing_is_closed() {
    let Some(zion) = Zion::start(None) else {
        return;
    };
    let mut conn = connect_port(&zion, Transport::TlsAlpnH2);
    let mut out = PREFACE.to_vec();
    out.extend(frame(SETTINGS, 0, 0, &[]));
    out.extend(frame(PING, 0, 0, &[7; 8]).repeat(5_000));
    assert!(pour(&mut *conn, &out));
    let mut acks = 0;
    while acks < 5_000 {
        match read_frame(&mut *conn) {
            Some((PING, 1, _, _)) => acks += 1,
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(acks, 5_000, "every PING was answered");
    // Still open: one more round trip.
    conn.write_all(&frame(PING, 0, 0, &[9; 8])).unwrap();
    conn.flush().unwrap();
    assert_eq!(
        pong(&mut *conn).as_deref(),
        Some(&[9u8; 8][..]),
        "still open"
    );
    assert_eq!(zion.closed_for("control_frames", |_| true), 0);
    assert_eq!(zion.closed_for("window_update", |_| true), 0);
    // Split over two seconds at worst.
    let peak = zion.metric("zion_h2_control_frames_peak", |n| n >= 2_500);
    assert!(peak >= 2_500, "the peak gauge saw the flood: {peak}");
}

/// A download acknowledged the chattiest way a conforming client can: a `WINDOW_UPDATE` for
/// the stream and one for the connection after every DATA frame. 48 MiB in 16 KiB frames is
/// about 6,000 updates, sent as fast as the bytes arrive: many times the 1,000 a second that
/// are free, and allowed because of the bytes they acknowledge. The body arrives whole and
/// the connection stays open. Then `curl --http2`, when there is one.
#[test]
fn a_download_with_a_window_update_per_frame_is_not_a_flood() {
    let Some(zion) = Zion::start(Some(LIMIT)) else {
        return;
    };
    let body = big_body();
    let mut conn = connect_port(&zion, Transport::TlsAlpnH2);
    let mut out = PREFACE.to_vec();
    out.extend(frame(SETTINGS, 0, 0, &[]));
    out.extend(get(1, "/files/big.bin"));
    conn.write_all(&out).unwrap();
    conn.flush().unwrap();

    let (mut got, mut updates, mut status_ok, mut done) =
        (Vec::with_capacity(BIG), 0u32, false, false);
    while !done {
        let Some((ty, flags, stream, payload)) = read_frame(&mut *conn) else {
            break;
        };
        match (ty, stream) {
            (HEADERS, 1) => status_ok = payload.first() == Some(&0x88), // :status 200
            (DATA, 1) => {
                if !payload.is_empty() {
                    let n = (payload.len() as u32).to_be_bytes();
                    let mut ack = frame(WINDOW_UPDATE, 0, 1, &n);
                    ack.extend(frame(WINDOW_UPDATE, 0, 0, &n));
                    conn.write_all(&ack).unwrap();
                    conn.flush().unwrap();
                    updates += 2;
                }
                got.extend_from_slice(&payload);
                done = flags & 1 == 1;
            }
            (SETTINGS, 0) if flags & 1 == 0 => {
                conn.write_all(&frame(SETTINGS, 1, 0, &[])).unwrap();
            }
            (GOAWAY, _) => panic!(
                "zion sent GOAWAY during a download, error code {}",
                goaway_code(&payload)
            ),
            _ => {}
        }
    }
    assert!(status_ok, "200");
    assert_eq!(got.len(), body.len(), "the whole body arrived");
    assert!(got == body, "and it is the file's bytes");
    assert!(
        updates > 5_000,
        "the client did send many updates: {updates}"
    );
    // The connection is still open and serving.
    conn.write_all(&frame(PING, 0, 0, &[9; 8])).unwrap();
    conn.flush().unwrap();
    assert_eq!(
        pong(&mut *conn).as_deref(),
        Some(&[9u8; 8][..]),
        "still open"
    );

    // A real client, when the machine has one that speaks HTTP/2.
    let curl = Command::new("curl")
        .args(["-sk", "--http2", "--max-time", "60", "-o", "/dev/null"])
        .args(["-w", "%{http_version} %{http_code} %{size_download}"])
        .arg(format!("https://127.0.0.1:{}/files/big.bin", zion.https))
        .output();
    match curl {
        Ok(out) if String::from_utf8_lossy(&out.stdout).starts_with("2 ") => {
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                format!("2 200 {BIG}"),
                "curl --http2 downloaded the file"
            );
        }
        _ => eprintln!("NOTE: no curl with HTTP/2 here, the curl download was not run"),
    }
    assert_eq!(zion.closed_for("control_frames", |_| true), 0);
    assert_eq!(zion.closed_for("window_update", |_| true), 0);
}

/// What a browser does when the user leaves a page that is still loading: every stream in
/// flight is cancelled at once. Measured with Chrome, 100 downloads cancelled three times
/// over is 302 `RST_STREAM`s in one second, six times the limit set here, and it is not a
/// flood: each reset cancels a stream the client opened. The connection stays open.
#[test]
fn cancelling_every_stream_in_flight_is_not_a_flood() {
    let Some(zion) = Zion::start(Some(LIMIT)) else {
        return;
    };
    let mut conn = connect_port(&zion, Transport::TlsAlpnH2);
    let mut out = PREFACE.to_vec();
    out.extend(frame(SETTINGS, 0, 0, &[]));
    conn.write_all(&out).unwrap();
    let mut next_stream = 1u32;
    for round in 0..3 {
        // 100 downloads of a file that does not fit the connection's flow-control window
        // (this client never widens it), each let run until its response has begun: a
        // stream reset before the server took it up is h2's Rapid Reset business, not this
        // test's...
        let streams: Vec<u32> = (0..100).map(|i| next_stream + 2 * i).collect();
        next_stream += 200;
        let opened: Vec<u8> = streams
            .iter()
            .flat_map(|id| get(*id, "/files/mid.bin"))
            .collect();
        conn.write_all(&opened).unwrap();
        conn.flush().unwrap();
        let mut begun = std::collections::HashSet::new();
        while begun.len() < streams.len() {
            match read_frame(&mut *conn) {
                Some((HEADERS, _, id, _)) => {
                    begun.insert(id);
                }
                Some((GOAWAY, _, _, p)) => {
                    panic!("round {round}: GOAWAY, error code {}", goaway_code(&p))
                }
                Some(_) => {}
                None => panic!(
                    "round {round}: the connection ended, {} responses begun",
                    begun.len()
                ),
            }
        }
        // ... and all cancelled in one write (error code 8, CANCEL).
        let cancelled: Vec<u8> = streams
            .iter()
            .flat_map(|id| frame(RST_STREAM, 0, *id, &[0, 0, 0, 8]))
            .collect();
        conn.write_all(&cancelled).unwrap();
        conn.flush().unwrap();
    }
    conn.write_all(&frame(PING, 0, 0, &[9; 8])).unwrap();
    conn.flush().unwrap();
    assert_eq!(
        pong(&mut *conn).as_deref(),
        Some(&[9u8; 8][..]),
        "still open after 300 cancellations"
    );
    assert_eq!(zion.closed_for("control_frames", |_| true), 0);
    assert_eq!(zion.closed_for("window_update", |_| true), 0);
}

/// #663: a client that negotiated `h2` in the TLS handshake and then does not open with the
/// HTTP/2 preface was answered `HTTP/1.1 400 Bad Request`, in text (hyper chooses the
/// protocol from the first bytes, whatever ALPN said). h2spec http2/3.5 reads that as a frame
/// that never ends. It is now told in HTTP/2 and closed, and the three ways of speaking
/// HTTP/1.1 or HTTP/2 that negotiate nothing work as before.
#[test]
fn h2_negotiated_and_no_preface_is_goaway_protocol_error_not_an_http1_answer() {
    let Some(zion) = Zion::start(Some(LIMIT)) else {
        return;
    };
    let openings: [&[u8]; 3] = [
        b"INVALID CONNECTION PREFACE\r\n\r\n", // what h2spec sends
        b"GET /files/small.txt HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\rX",
    ];
    for opening in openings {
        let what = String::from_utf8_lossy(opening);
        let mut conn = connect(zion.https, Transport::TlsAlpnH2);
        conn.write_all(opening).unwrap();
        conn.flush().unwrap();
        // The server's preface, an empty SETTINGS that is not an ack ...
        let (ty, flags, stream, payload) = read_frame(&mut *conn).expect("a first frame");
        assert_eq!(
            (ty, flags, stream, payload.len()),
            (SETTINGS, 0, 0, 0),
            "{what:?}"
        );
        // ... then GOAWAY: last stream id 0, error code 1 (PROTOCOL_ERROR) ...
        let (ty, _, stream, payload) = read_frame(&mut *conn).expect("a second frame");
        assert_eq!((ty, stream), (GOAWAY, 0), "{what:?}");
        assert_eq!(payload, [0, 0, 0, 0, 0, 0, 0, 1], "{what:?}");
        // ... and the end of the TLS connection, said (close_notify), with nothing after:
        // a connection cut without it is an error for this client, as it is for h2spec.
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest)
            .unwrap_or_else(|e| panic!("{what:?}: the connection did not end cleanly: {e}"));
        assert!(
            rest.is_empty(),
            "{what:?}: {} bytes after GOAWAY",
            rest.len()
        );
    }
    assert!(zion.logged("did not send the HTTP/2 preface", 1) >= 1);

    // Controls. The same client with the preface is served HTTP/2 ...
    let mut conn = connect(zion.https, Transport::TlsAlpnH2);
    let mut hello = PREFACE.to_vec();
    hello.extend(frame(SETTINGS, 0, 0, &[]));
    hello.extend(frame(PING, 0, 0, &[5; 8]));
    conn.write_all(&hello).unwrap();
    conn.flush().unwrap();
    assert_eq!(pong(&mut *conn).as_deref(), Some(&[5u8; 8][..]));
    // ... HTTP/1.1 where nothing was negotiated is HTTP/1.1, on TLS and on the plaintext port ...
    for how in [Transport::TlsNoAlpn, Transport::Plaintext] {
        let mut conn = connect_port(&zion, how);
        conn.write_all(
            b"GET /files/small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut answer = Vec::new();
        let _ = conn.read_to_end(&mut answer);
        assert!(
            answer.starts_with(b"HTTP/1.1 "),
            "{how:?}: {:?}",
            String::from_utf8_lossy(&answer[..answer.len().min(40)])
        );
    }
    // ... and garbage where nothing was negotiated still gets hyper's HTTP/1.1 answer.
    let mut conn = connect(zion.https, Transport::TlsNoAlpn);
    conn.write_all(b"INVALID CONNECTION PREFACE\r\n\r\n")
        .unwrap();
    let mut answer = Vec::new();
    let _ = conn.read_to_end(&mut answer);
    assert!(answer.starts_with(b"HTTP/1.1 400"));
}
