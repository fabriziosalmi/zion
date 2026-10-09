// SPDX-License-Identifier: Apache-2.0
//! HTTP/1.1 request hygiene on the real listener: the real binary, a raw TLS client, an origin
//! that records what it was sent.
//!
//! RFC 9112 §3.2: a server MUST answer 400 to an HTTP/1.1 request that lacks `Host`, has more than
//! one, or has an invalid value (#648). RFC 9110 §7.6.1: an intermediary MUST remove the header
//! fields named in `Connection` before forwarding (#649).
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

/// An origin that answers every request with `ok` and remembers the head of each request it got.
fn origin() -> (u16, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).into_owned());
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            });
        }
    });
    (port, seen)
}

/// Send `raw` over TLS (ALPN http/1.1) and return the status line of the answer.
fn status_line(port: u16, raw: &[u8]) -> String {
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
    let _ = child.kill();
    let _ = child.wait();
    line.trim().to_string()
}

fn start(dir: &Path, origin_port: u16) -> (Proc, u16) {
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    let https_port = free_port();
    let d = dir.to_string_lossy();
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
    let _ = d;
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

#[test]
fn http1_host_and_connection_headers_follow_the_rfcs() {
    let dir = std::env::temp_dir().join(format!(
        "zion-http1-hygiene-{}-{}",
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
        // a self-signed certificate is a CA by default; rustls refuses a CA as a server certificate
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
    // zion's own health prober also asks the origin things: count only the requests under test
    let forwarded = || {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|h| h.starts_with("GET /p "))
            .count()
    };

    // a well-formed request is served (this also proves the origin and the route work)
    let ok = status_line(
        port,
        b"GET /p HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    );
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok:?}");
    assert_eq!(forwarded(), 1);

    // #648: none, two, an invalid one: 400, and the origin is never asked
    for (what, raw) in [
        ("no Host", &b"GET /p HTTP/1.1\r\n\r\n"[..]),
        (
            "two Host",
            b"GET /p HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
        ),
        (
            "invalid Host",
            b"GET /p HTTP/1.1\r\nHost: exa mple.com\r\n\r\n",
        ),
    ] {
        let line = status_line(port, raw);
        assert!(line.starts_with("HTTP/1.1 400"), "{what}: {line:?}");
    }
    assert_eq!(
        forwarded(),
        1,
        "a refused request must not reach the origin"
    );

    // HTTP/1.0 may omit Host
    let line = status_line(port, b"GET /p HTTP/1.0\r\n\r\n");
    assert!(
        line.starts_with("HTTP/1.1 200") || line.starts_with("HTTP/1.0 200"),
        "{line:?}"
    );

    // #649: a header named in Connection is not forwarded; an unnamed one is
    let before = forwarded();
    let line = status_line(
        port,
        b"GET /p HTTP/1.1\r\nHost: a.example\r\nConnection: close, X-Remove-Me\r\n\
          X-Remove-Me: 1\r\nX-Keep-Me: 2\r\n\r\n",
    );
    assert!(line.starts_with("HTTP/1.1 200"), "{line:?}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while forwarded() <= before {
        assert!(
            Instant::now() < deadline,
            "the origin never saw the request"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let head = seen
        .lock()
        .unwrap()
        .iter()
        .rfind(|h| h.starts_with("GET /p "))
        .unwrap()
        .to_ascii_lowercase();
    assert!(!head.contains("x-remove-me"), "forwarded: {head}");
    assert!(head.contains("x-keep-me: 2"), "forwarded: {head}");
    let _ = fs::remove_dir_all(dir);
}
