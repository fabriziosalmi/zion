// SPDX-License-Identifier: Apache-2.0
//! HTTP/HTTPS conformance matrix on the real listener (#741): the real binary, a raw TLS client
//! that sends bytes exactly as written, and an origin that records the head of every request it
//! receives. Where the smuggling corpus (#697) proves the *negative* (no desync form reaches the
//! upstream), this is the *positive* matrix: for each request shape, what zion does (forward,
//! refuse, re-frame). Each case states its expectation before it runs, and the suite prints an
//! outcome table so the HTTP contract is visible and cannot drift from behaviour.
//!
//! Slice 1 (#741): HTTP/1.1 methods, body framing, and hop-by-hop header stripping on a proxy
//! route. Later slices add request-target forms, encoding/compression, conditional/range, HTTP/2.
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

fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// An origin that parses a keep-alive stream of HTTP/1.1 requests, records the head (start-line and
/// header lines) of each, consumes its body (Content-Length or chunked) so the next request starts
/// at a boundary, and answers `ok`.
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
                s.set_read_timeout(Some(Duration::from_millis(500))).ok();
                let mut w = match s.try_clone() {
                    Ok(w) => w,
                    Err(_) => return,
                };
                let mut r = BufReader::new(s);
                loop {
                    let mut start = String::new();
                    if r.read_line(&mut start).unwrap_or(0) == 0 {
                        break;
                    }
                    let start = start.trim_end().to_string();
                    if start.is_empty() {
                        continue;
                    }
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
                                let _ = r.read_line(&mut trailer);
                                break;
                            }
                            let mut body = vec![0u8; n];
                            if r.read_exact(&mut body).is_err() {
                                break;
                            }
                            let mut crlf = String::new();
                            let _ = r.read_line(&mut crlf);
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

/// zion's response to `raw`: the status line and the full header block, read until the blank line.
/// An empty status means zion hung (a timeout), which is itself a failure for the caller to assert.
struct Resp {
    status: String,
    /// The response header block (status line + headers), lowercased by callers as needed. Kept for
    /// the slices that assert on response headers (encoding, conditional); unused lines are fine.
    #[allow(dead_code)]
    head: String,
}

fn send(port: u16, raw: &[u8]) -> Resp {
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
    let (tx, rx) = std::sync::mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        // Read the response head: lines until the first blank line.
        let mut r = BufReader::new(out);
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let trimmed = line.trim_end().to_string();
            if trimmed.is_empty() {
                break;
            }
            lines.push(trimmed);
        }
        let _ = tx.send(lines);
    });
    let lines = rx.recv_timeout(Duration::from_secs(10)).unwrap_or_default();
    let _ = stdin;
    let _ = child.kill();
    let _ = child.wait();
    let status = lines.first().cloned().unwrap_or_default();
    Resp {
        status,
        head: lines.join("\n"),
    }
}

/// The 3-digit status code zion returned (0 if it hung / sent no status line).
fn code(resp: &Resp) -> u16 {
    resp.status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn start(dir: &Path, origin_port: u16) -> (Proc, u16) {
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=localhost",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "openssl cert generation failed"
    );
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

/// Did the origin receive a request whose start-line begins with `method ` and targets `/marker`?
/// Waits briefly for the proxied request to arrive.
fn origin_saw_method(seen: &Arc<Mutex<Vec<String>>>, method: &str, marker: &str) -> bool {
    let needle_start = format!("{method} /{marker}");
    let deadline = Instant::now() + Duration::from_millis(800);
    loop {
        if seen.lock().unwrap().iter().any(|h| {
            h.lines()
                .next()
                .is_some_and(|l| l.starts_with(&needle_start))
        }) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn http1_methods_framing_and_hop_by_hop_on_a_proxy_route() {
    if !have_openssl() {
        eprintln!("skipping http_conformance: openssl not installed");
        return;
    }
    let dir = tempdir();
    let (origin_port, seen) = origin();
    let (_zion, port) = start(&dir, origin_port);

    // A header line that must reach the origin, to confirm a case forwarded at all.
    let host = "Host: localhost\r\n";

    let mut matrix: Vec<(String, String)> = Vec::new();
    let mut record = |case: &str, outcome: String| matrix.push((case.to_string(), outcome));

    // ---- Methods ----
    // Expectation: the standard methods are forwarded to the origin unchanged; zion returns the
    // origin's 200. A body-less method carries no body.
    for m in ["GET", "HEAD", "DELETE", "OPTIONS"] {
        let marker = format!("m-{}", m.to_ascii_lowercase());
        let raw = format!("{m} /{marker} HTTP/1.1\r\n{host}Connection: close\r\n\r\n");
        let resp = send(port, raw.as_bytes());
        let c = code(&resp);
        let saw = origin_saw_method(&seen, m, &marker);
        // Contract: a safe/standard method is forwarded unchanged and zion returns the origin's 200.
        assert_eq!(
            c, 200,
            "{m}: expected zion to forward and return 200, got {c}"
        );
        assert!(saw, "{m}: did not reach the origin");
        record(m, format!("zion {c}, origin forwarded"));
    }

    // Body-bearing methods with a Content-Length body.
    for m in ["POST", "PUT", "PATCH"] {
        let marker = format!("m-{}", m.to_ascii_lowercase());
        let raw = format!(
            "{m} /{marker} HTTP/1.1\r\n{host}Content-Length: 5\r\nConnection: close\r\n\r\nhello"
        );
        let resp = send(port, raw.as_bytes());
        let c = code(&resp);
        let saw = origin_saw_method(&seen, m, &marker);
        assert_eq!(
            c, 200,
            "{m}: expected zion to forward and return 200, got {c}"
        );
        assert!(saw, "{m}: did not reach the origin");
        record(m, format!("zion {c}, origin forwarded"));
    }

    // Uncommon / unknown methods. Measured contract: zion refuses TRACE and an unknown method with
    // 405 BEFORE any origin round-trip (TRACE is a reflection risk; an unknown verb is not routed).
    // Pinned here so forwarding one again becomes a deliberate, visible change.
    for m in ["TRACE", "FROB"] {
        let marker = format!("m-{}", m.to_ascii_lowercase());
        let raw = format!("{m} /{marker} HTTP/1.1\r\n{host}Connection: close\r\n\r\n");
        let resp = send(port, raw.as_bytes());
        let c = code(&resp);
        let saw = origin_saw_method(&seen, m, &marker);
        assert_eq!(c, 405, "{m}: expected zion to refuse with 405, got {c}");
        assert!(
            !saw,
            "{m}: reached the origin but should have been refused at the edge"
        );
        record(m, format!("zion {c}, refused before origin"));
    }

    // ---- Framing: a chunked request body is re-framed by zion ----
    // Expectation (measured, not assumed): zion parses the chunked body and re-serializes it
    // upstream through its own HTTP client. The client's raw framing bytes never pass through (that
    // is the #697 invariant), but the upstream request is legitimately re-framed: hyper may send it
    // chunked again or with a Content-Length. We assert the strong invariant (forwarded once, final
    // response, no 5xx) and RECORD which upstream framing zion chose, as documentation.
    {
        let before = seen.lock().unwrap().len();
        let raw = format!(
            "POST /fr-chunked HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        );
        let resp = send(port, raw.as_bytes());
        let c = code(&resp);
        assert!(c != 0 && c < 500, "chunked: zion hung or 5xx ({c})");
        let saw = origin_saw_method(&seen, "POST", "fr-chunked");
        let recorded = {
            let g = seen.lock().unwrap();
            g.iter()
                .skip(before)
                .find(|h| {
                    h.lines()
                        .next()
                        .is_some_and(|l| l.starts_with("POST /fr-chunked"))
                })
                .cloned()
                .unwrap_or_default()
                .to_ascii_lowercase()
        };
        let upstream_framing = if recorded.contains("transfer-encoding") {
            "re-chunked"
        } else if recorded.contains("content-length") {
            "content-length"
        } else {
            "none"
        };
        record(
            "POST chunked body",
            format!(
                "zion {c}, origin {}, upstream framing: {upstream_framing}",
                if saw { "forwarded" } else { "not reached" }
            ),
        );
        assert!(saw, "a chunked POST was not forwarded to the origin");
    }

    // ---- Framing: a Content-Length request body is forwarded intact ----
    {
        let before = seen.lock().unwrap().len();
        let raw = format!(
            "POST /fr-cl HTTP/1.1\r\n{host}Content-Length: 5\r\nConnection: close\r\n\r\nhello"
        );
        let resp = send(port, raw.as_bytes());
        let c = code(&resp);
        assert!(c != 0 && c < 500, "content-length: zion hung or 5xx ({c})");
        let saw = origin_saw_method(&seen, "POST", "fr-cl");
        let recorded = {
            let g = seen.lock().unwrap();
            g.iter()
                .skip(before)
                .find(|h| {
                    h.lines()
                        .next()
                        .is_some_and(|l| l.starts_with("POST /fr-cl"))
                })
                .cloned()
                .unwrap_or_default()
                .to_ascii_lowercase()
        };
        let upstream_framing = if recorded.contains("content-length") {
            "content-length"
        } else if recorded.contains("transfer-encoding") {
            "re-chunked"
        } else {
            "none"
        };
        record(
            "POST content-length body",
            format!(
                "zion {c}, origin {}, upstream framing: {upstream_framing}",
                if saw { "forwarded" } else { "not reached" }
            ),
        );
        assert!(saw, "a Content-Length POST was not forwarded to the origin");
    }

    // ---- Hop-by-hop header stripping ----
    // Expectation: Connection, Keep-Alive, Upgrade and the headers named by Connection are not
    // forwarded to the origin.
    {
        let before = seen.lock().unwrap().len();
        let raw = format!(
            "GET /hbh HTTP/1.1\r\n{host}Connection: keep-alive, x-conn-token\r\nKeep-Alive: timeout=5\r\nUpgrade: h2c\r\nX-Conn-Token: secret\r\nX-Keep: keep-me\r\nConnection: close\r\n\r\n"
        );
        // Note: two Connection lines (one closing the socket) is intentional; the first lists tokens.
        let resp = send(port, raw.as_bytes());
        let c = code(&resp);
        assert!(c != 0 && c < 500, "hop-by-hop: zion hung or 5xx ({c})");
        origin_saw_method(&seen, "GET", "hbh");
        // Inspect the head the origin recorded for THIS request (the newest one).
        let recorded = {
            let g = seen.lock().unwrap();
            g.iter()
                .skip(before)
                .find(|h| h.lines().next().is_some_and(|l| l.starts_with("GET /hbh")))
                .cloned()
        };
        let head = recorded.unwrap_or_default().to_ascii_lowercase();
        let forwarded_keepalive = head.contains("keep-alive:");
        let forwarded_upgrade = head.contains("upgrade:");
        let forwarded_conn_token = head.contains("x-conn-token:");
        let forwarded_kept = head.contains("x-keep:");
        record(
            "hop-by-hop strip",
            format!(
                "keep-alive fwd:{forwarded_keepalive} upgrade fwd:{forwarded_upgrade} conn-named fwd:{forwarded_conn_token} (X-Keep fwd:{forwarded_kept})"
            ),
        );
        assert!(!forwarded_keepalive, "Keep-Alive leaked to the origin");
        assert!(!forwarded_upgrade, "Upgrade leaked to the origin");
        assert!(
            !forwarded_conn_token,
            "a header named by Connection (X-Conn-Token) leaked to the origin"
        );
    }

    // ---- Print the slice-1 outcome matrix ----
    eprintln!("\n=== HTTP/1.1 conformance matrix (slice 1: methods, framing, hop-by-hop) ===");
    for (case, outcome) in &matrix {
        eprintln!("  {case:22}  {outcome}");
    }
    eprintln!("=== end matrix ===\n");
}

fn tempdir() -> TempDir {
    let base = std::env::temp_dir().join(format!("zion-conf-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    TempDir(base)
}

struct TempDir(std::path::PathBuf);
impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
