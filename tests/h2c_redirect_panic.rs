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
//! The same raw-frame client also pins that an h2c request whose `host` field disagrees with
//! its `:authority`, or whose authority has a port that is not a port or a host that is not a
//! host name, gets a 400: the HTTP/2 decoding hands zion both fields as sent, and zion refuses
//! a request that does not name one host before anything routes by it. An `:authority` the
//! `http` crate cannot parse never reaches zion: h2 resets that stream itself.
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

/// A complete `GET /` on `stream` with an `:authority` of `authority` and, when given, a `host`
/// field of `host`. HPACK: `:method GET` (0x82), `:scheme http` (0x86), `:path /` (0x84), then
/// `:authority` and `host` as literals with incremental indexing on static name indexes 1 and 38
/// (0x40 | index).
fn get_with_host(stream: u32, authority: &[u8], host: Option<&[u8]>) -> Vec<u8> {
    get_with_fields(stream, Some(authority), host)
}

/// An `:authority` and a `host` field, each sent only when given.
type AuthorityAndHost<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

/// [`get_with_host`] with the `:authority` optional too: without it, h2 hands zion an
/// origin-form target and the `host` field.
fn get_with_fields(stream: u32, authority: Option<&[u8]>, host: Option<&[u8]>) -> Vec<u8> {
    let mut hpack = vec![0x82, 0x86, 0x84];
    for (index, value) in [(1u8, authority), (38, host)] {
        let Some(value) = value else { continue };
        assert!(value.len() < 127, "one-byte HPACK length");
        hpack.extend_from_slice(&[0x40 | index, value.len() as u8]);
        hpack.extend_from_slice(value);
    }
    frame(HEADERS, 0x5, stream, &hpack) // END_STREAM | END_HEADERS
}

/// An h2c request whose `host` field names another authority than its `:authority` gets a 400
/// (RFC 9113 §8.3.1 makes it malformed), and one that names the same authority in both is
/// answered as usual. This is the HTTP/2 path end to end: h2 hands zion both fields, and the
/// check the HTTPS pipeline runs as a gate before routing refuses the disagreement on :80 too
/// (where the ACME fallback routes by `:authority` and forwards `host`).
#[test]
fn an_h2c_request_whose_host_disagrees_with_its_authority_is_a_400() {
    let Some(zion) = Zion::start() else {
        return;
    };
    let same = speak_h2c(
        zion.http,
        &get_with_host(1, b"localhost", Some(b"localhost")),
    );
    assert!(
        matches!(same.as_slice(), [(1, Some(first))] if *first != STATUS_400),
        "control: the same authority in :authority and host is answered (a 301), got {same:?}"
    );
    let other = speak_h2c(
        zion.http,
        &get_with_host(1, b"localhost", Some(b"evil.example")),
    );
    assert_eq!(
        other,
        vec![(1, Some(STATUS_400))],
        "a host field that disagrees with :authority gets one response, a 400"
    );
}

/// An h2c request whose `:authority` or `host` has a port that is not a port gets a 400: routing
/// would key the whole text and an upstream would read the host before the `:`. An empty port is
/// the scheme's default (RFC 3986 §6.2.3), so `localhost:` is answered as `localhost`.
#[test]
fn an_h2c_request_whose_authority_port_is_not_a_port_is_a_400() {
    let Some(zion) = Zion::start() else {
        return;
    };
    let empty: &[(&[u8], Option<&[u8]>)] =
        &[(b"localhost:", None), (b"localhost", Some(b"localhost:"))];
    for (authority, host) in empty {
        let got = speak_h2c(zion.http, &get_with_host(1, authority, *host));
        assert!(
            matches!(got.as_slice(), [(1, Some(first))] if *first != STATUS_400),
            "an empty port is the default one and is answered (a 301): :authority {:?}, host \
             {:?}, got {got:?}",
            String::from_utf8_lossy(authority),
            host.map(String::from_utf8_lossy)
        );
    }
    let not_a_port: &[(&[u8], Option<&[u8]>)] = &[
        (b"localhost:x", None),
        (b"localhost:x", Some(b"localhost")),
        (b"localhost", Some(b"localhost:x")),
        (b"localhost", Some(b"localhost:+80")),
    ];
    for (authority, host) in not_a_port {
        assert_eq!(
            speak_h2c(zion.http, &get_with_host(1, authority, *host)),
            vec![(1, Some(STATUS_400))],
            ":authority {:?}, host {:?}",
            String::from_utf8_lossy(authority),
            host.map(String::from_utf8_lossy)
        );
    }
}

/// Send `hpack_request` as one h2c request on stream 1 and return the error code of the
/// `RST_STREAM` that ends it, or `None` when a response or the end of the connection comes
/// first.
fn h2c_reset_code(port: u16, hpack_request: &[u8]) -> Option<u32> {
    let mut conn = connect(port);
    let mut out = PREFACE.to_vec();
    out.extend(frame(SETTINGS, 0, 0, &[]));
    out.extend_from_slice(hpack_request);
    conn.write_all(&out).unwrap();
    conn.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match read_frame(&mut conn)? {
            (RST_STREAM, _, 1, code) => {
                let code: [u8; 4] = code.as_slice().try_into().ok()?;
                return Some(u32::from_be_bytes(code));
            }
            (HEADERS, _, 1, _) | (GOAWAY, _, _, _) => return None,
            _ => {}
        }
    }
    None
}

/// h2's `PROTOCOL_ERROR` (RFC 9113 §7).
const PROTOCOL_ERROR: u32 = 0x1;

/// An h2c request whose `:authority` or `host` names a host that is not a host name (a `,`, a
/// `;`, a tab) gets a 400: routing would key the whole text, while an upstream that reads
/// `X-Forwarded-Host` as a list reads the host before the `,`. The `http` crate takes a `,` or a
/// `;` in an authority, so h2 hands these over; a tab it refuses in `:authority`, but not in a
/// `host` field, which h2 passes on as a header when there is no `:authority`.
#[test]
fn an_h2c_request_whose_authority_host_is_not_a_host_name_is_a_400() {
    let Some(zion) = Zion::start() else {
        return;
    };
    let control = speak_h2c(zion.http, &get_with_fields(1, None, Some(b"localhost")));
    assert!(
        matches!(control.as_slice(), [(1, Some(first))] if *first != STATUS_400),
        "control: a host field without :authority is answered (a 301), got {control:?}"
    );
    let not_a_host_name: &[AuthorityAndHost] = &[
        (Some(b"localhost,x"), None),
        (Some(b"localhost,x"), Some(b"localhost,x")),
        (Some(b"localhost;x"), None),
        (None, Some(b"localhost,x")),
        (None, Some(b"x\tlocalhost")),
    ];
    for (authority, host) in not_a_host_name {
        assert_eq!(
            speak_h2c(zion.http, &get_with_fields(1, *authority, *host)),
            vec![(1, Some(STATUS_400))],
            ":authority {:?}, host {:?}",
            authority.map(String::from_utf8_lossy),
            host.map(String::from_utf8_lossy)
        );
    }
}

/// An `:authority` the `http` crate does not parse as an authority (a second `:` outside
/// brackets, a bare IPv6 literal, a tab) never reaches zion: h2 resets the stream with
/// `PROTOCOL_ERROR`, before any response. The same text in a `host` field reaches zion, which
/// answers it with a 400.
#[test]
fn an_h2c_authority_the_http_crate_cannot_parse_is_reset_by_h2() {
    let Some(zion) = Zion::start() else {
        return;
    };
    for authority in [&b"localhost:1:2"[..], b"::1", b"x\tlocalhost"] {
        assert_eq!(
            h2c_reset_code(zion.http, &get_with_fields(1, Some(authority), None)),
            Some(PROTOCOL_ERROR),
            ":authority {:?}",
            String::from_utf8_lossy(authority)
        );
    }
    for host in [&b"localhost:1:2"[..], b"::1"] {
        assert_eq!(
            speak_h2c(zion.http, &get_with_fields(1, None, Some(host))),
            vec![(1, Some(STATUS_400))],
            "host {:?}",
            String::from_utf8_lossy(host)
        );
    }
}
