// SPDX-License-Identifier: Apache-2.0
//! HTTP/1.1 request-smuggling corpus on the real listener (#697): the real binary, a raw TLS
//! client that sends bytes exactly as written, and an origin that records every byte it receives.
//!
//! zion rebuilds the framing (it parses with hyper, strips `Transfer-Encoding` / `TE` / `Trailer`
//! and always re-serializes HTTP/1.1 upstream), so no on-the-wire framing byte of the client's
//! request can pass through. This corpus proves that end to end for the desync forms behind this
//! year's CVEs: each case tries to smuggle a request for `/smuggled` past zion, and the invariant
//! is that the origin NEVER sees `/smuggled` and zion always returns a final response (no hang, no
//! 5xx). A case that reaches the origin is a real finding and gets its own fix issue.
//!
//! Unix only, and skipped when `openssl` is not installed (it makes the certificate and is the TLS
//! client: `s_client` sends the bytes exactly as written, which no HTTP client library will).
#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// An origin that parses a keep-alive stream of HTTP/1.1 requests, records the head (start-line and
/// header lines) of each one, consumes its body (Content-Length or chunked), and answers `ok`.
/// Recording heads but consuming bodies is the point: bytes that arrive as a request body are NOT
/// recorded, so a `/smuggled` that appears only as body content is not mistaken for a smuggled
/// request, while a genuine second request on the connection is parsed and recorded head and all.
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
                // An idle gap between requests ends the connection (read times out).
                s.set_read_timeout(Some(Duration::from_millis(500))).ok();
                let mut w = match s.try_clone() {
                    Ok(w) => w,
                    Err(_) => return,
                };
                let mut r = BufReader::new(s);
                loop {
                    // Request line.
                    let mut start = String::new();
                    if r.read_line(&mut start).unwrap_or(0) == 0 {
                        break;
                    }
                    let start = start.trim_end().to_string();
                    if start.is_empty() {
                        continue;
                    }
                    // Headers, until the blank line; keep the head and note the body framing.
                    let mut head = start;
                    let mut content_length = 0usize;
                    let mut chunked = false;
                    loop {
                        let mut h = String::new();
                        if r.read_line(&mut h).unwrap_or(0) == 0 {
                            break;
                        }
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        head.push('\n');
                        head.push_str(h);
                        let lower = h.to_ascii_lowercase();
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            content_length = v.trim().parse().unwrap_or(0);
                        } else if lower.starts_with("transfer-encoding:")
                            && lower.contains("chunked")
                        {
                            chunked = true;
                        }
                    }
                    log.lock().unwrap().push(head);
                    // Consume the body so the next request line is at a request boundary.
                    if chunked {
                        loop {
                            let mut size_line = String::new();
                            if r.read_line(&mut size_line).unwrap_or(0) == 0 {
                                break;
                            }
                            let hex = size_line.trim().split(';').next().unwrap_or("0");
                            let n = usize::from_str_radix(hex.trim(), 16).unwrap_or(0);
                            if n == 0 {
                                let mut trailer = String::new();
                                let _ = r.read_line(&mut trailer); // final CRLF / trailers
                                break;
                            }
                            let mut body = vec![0u8; n];
                            if r.read_exact(&mut body).is_err() {
                                break;
                            }
                            let mut crlf = String::new();
                            let _ = r.read_line(&mut crlf); // CRLF after the chunk data
                        }
                    } else if content_length > 0 {
                        let mut body = vec![0u8; content_length];
                        let _ = r.read_exact(&mut body);
                    }
                    if w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    (port, seen)
}

/// Send `raw` over TLS (ALPN http/1.1) and return the status line of zion's answer (empty on
/// timeout, which would mean zion hung).
fn send_raw(port: u16, raw: &[u8]) -> String {
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-quiet",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-alpn",
            "http/1.1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl s_client");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(raw).unwrap();
    // stdin stays open until the answer is read: closing it makes s_client leave before the reply.
    let (tx, rx) = std::sync::mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(out).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx.recv_timeout(Duration::from_secs(10)).unwrap_or_default();
    let _ = stdin; // keep stdin alive until here
    let _ = child.kill();
    let _ = child.wait();
    line.trim().to_string()
}

fn start(dir: &Path, origin_port: u16) -> (Proc, u16) {
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    let https_port = free_port();
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\n\
             [upstreams]\nbackend = \"http://127.0.0.1:{origin_port}\"\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\nmode = \"standard\"\n",
            free_port(),
            cert.to_string_lossy(),
            key.to_string_lossy()
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
    let z = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https_port)).is_err() {
        assert!(Instant::now() < deadline, "zion never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    (z, https_port)
}

/// Every request start-line the origin has parsed, across all connections, one per line.
fn origin_bytes(seen: &Arc<Mutex<Vec<String>>>) -> String {
    seen.lock().unwrap().join("\n")
}

/// Wait until some parsed start-line contains `needle`, up to `within`; whether it did.
fn origin_saw(seen: &Arc<Mutex<Vec<String>>>, needle: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if origin_bytes(seen).contains(needle) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn no_desync_form_smuggles_a_request_past_zion() {
    let dir = std::env::temp_dir().join(format!(
        "zion-http1-smuggle-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
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
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-keyout",
        &dir.join("k.pem").to_string_lossy(),
        "-out",
        &dir.join("c.pem").to_string_lossy(),
    ]);
    if !made {
        eprintln!("SKIP: openssl could not make a certificate");
        return;
    }
    let (origin_port, seen) = origin();
    let (_z, port) = start(&dir, origin_port);

    // Control: a well-formed request is served, proving the route and origin work.
    let ok = send_raw(
        port,
        b"GET /p HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    );
    assert!(ok.starts_with("HTTP/1.1 200"), "control not served: {ok:?}");
    assert!(
        origin_saw(&seen, "GET /p ", Duration::from_secs(5)),
        "control never reached the origin"
    );

    // Forms 1-5 each hide a second request for `GET /smuggled` behind a desync trick. zion may
    // refuse (4xx) or re-frame, but it must never answer with a 5xx or hang, and the hard invariant
    // checked after the loop is that `/smuggled` never reaches the origin as a request.
    let smuggle_cases: &[(&str, &[u8])] = &[
        (
            // 1. bare LF as the chunk-size line ending (Go CVE-2025-22871 family)
            "bare-LF chunk line",
            b"POST /p HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              0\n\r\nGET /smuggled HTTP/1.1\r\nHost: a.example\r\n\r\n",
        ),
        (
            // 2a. a bare CR inside a chunk extension, trying to end the chunk-size line early
            "CR inside a chunk extension",
            b"POST /p HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              1;a=b\rGET /smuggled HTTP/1.1\r\nZ\r\n0\r\n\r\n",
        ),
        (
            // 2b. a bare LF inside a chunk extension
            "LF inside a chunk extension",
            b"POST /p HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              1;a=b\nGET /smuggled HTTP/1.1\r\nZ\r\n0\r\n\r\n",
        ),
        (
            // 2c. a bare CR inside a chunk-extension quoted string
            "CR inside a chunk-extension quoted string",
            b"POST /p HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              1;a=\"b\rGET /smuggled HTTP/1.1\"\r\nZ\r\n0\r\n\r\n",
        ),
        (
            // 2d. a bare LF inside a chunk-extension quoted string
            "LF inside a chunk-extension quoted string",
            b"POST /p HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              1;a=\"b\nGET /smuggled HTTP/1.1\"\r\nZ\r\n0\r\n\r\n",
        ),
        (
            // 3. Content-Length together with Transfer-Encoding (classic CL.TE)
            "Content-Length + Transfer-Encoding",
            b"POST /p HTTP/1.1\r\nHost: a.example\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a.example\r\n\r\n",
        ),
        (
            // 4. two Transfer-Encoding headers
            "two Transfer-Encoding headers",
            b"POST /p HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nConnection: close\r\n\r\n\
              0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a.example\r\n\r\n",
        ),
        (
            // 5. Transfer-Encoding on HTTP/1.0, where TE has no meaning and may be read to EOF
            "Transfer-Encoding on HTTP/1.0",
            b"POST /p HTTP/1.0\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a.example\r\n\r\n",
        ),
    ];

    for (name, raw) in smuggle_cases {
        let line = send_raw(port, raw);
        eprintln!("case {name:?}: zion answered {line:?}");
        assert!(
            !line.is_empty(),
            "case {name:?}: zion did not answer (hung)"
        );
        assert!(
            !line.contains(" 5"),
            "case {name:?}: zion returned a server error: {line:?}"
        );
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !origin_saw(&seen, "/smuggled", Duration::from_millis(1)),
        "a desync form smuggled /smuggled to the origin:\n{}",
        origin_bytes(&seen)
    );

    // 6. obs-fold (a header value continued on a folded line) is forbidden by RFC 9110; the parser
    // refuses it and the origin never sees the request.
    let line = send_raw(
        port,
        b"GET /fold6 HTTP/1.1\r\nHost: a.example\r\nX-Fold: a\r\n b\r\nConnection: close\r\n\r\n",
    );
    assert!(
        line.starts_with("HTTP/1.1 400"),
        "obs-fold must be refused: {line:?}"
    );
    assert!(
        !origin_saw(&seen, "/fold6 ", Duration::from_millis(300)),
        "an obs-folded request reached the origin:\n{}",
        origin_bytes(&seen)
    );

    // 7. Expect: 100-continue on a bodyless OPTIONS must not hang or attribute a phantom body; the
    // request is forwarded once and answered.
    let line = send_raw(
        port,
        b"OPTIONS /opt7 HTTP/1.1\r\nHost: a.example\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
    );
    assert!(
        !line.is_empty() && !line.contains(" 5"),
        "Expect/OPTIONS hung or errored: {line:?}"
    );
    assert!(
        origin_saw(&seen, "OPTIONS /opt7 ", Duration::from_secs(5)),
        "Expect/OPTIONS was never forwarded:\n{}",
        origin_bytes(&seen)
    );

    // 8. an absolute-form target that names a foreign authority is re-framed to origin-form; the
    // foreign authority never reaches the upstream, and the path is forwarded faithfully.
    let line = send_raw(
        port,
        b"GET http://evil.example/abs8 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    );
    assert!(
        !line.is_empty() && !line.contains(" 5"),
        "absolute-form errored: {line:?}"
    );
    assert!(
        origin_saw(&seen, "GET /abs8 ", Duration::from_secs(5)),
        "absolute-form path was not re-framed to origin-form upstream:\n{}",
        origin_bytes(&seen)
    );
    let upstream = origin_bytes(&seen);
    assert!(
        !upstream.contains("evil.example"),
        "the absolute-form authority leaked to the upstream:\n{upstream}"
    );
    assert!(
        !upstream.to_ascii_lowercase().contains("http://"),
        "a non-origin-form target reached the upstream:\n{upstream}"
    );

    // 8b. asterisk-form (`OPTIONS *`) matches no route and is refused, never forwarded.
    let line = send_raw(
        port,
        b"OPTIONS * HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    );
    assert!(
        line.starts_with("HTTP/1.1 4"),
        "OPTIONS * must be refused, not served: {line:?}"
    );
    assert!(
        !origin_bytes(&seen).contains("OPTIONS *"),
        "an asterisk-form target reached the upstream:\n{}",
        origin_bytes(&seen)
    );

    // 8c. authority-form (`CONNECT`) is outside the method whitelist: 405, never forwarded.
    let line = send_raw(
        port,
        b"CONNECT evil.example:443 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    );
    assert!(
        line.starts_with("HTTP/1.1 405"),
        "CONNECT must be refused with 405: {line:?}"
    );
    assert!(
        !origin_bytes(&seen).contains("CONNECT"),
        "a CONNECT reached the upstream:\n{}",
        origin_bytes(&seen)
    );

    let _ = fs::remove_dir_all(dir);
}
