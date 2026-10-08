// SPDX-License-Identifier: Apache-2.0
//! `zion_upstream_connections_opened_total` counts the TCP connections zion establishes to an
//! upstream (#571), with the real binary: requests one after another reuse a connection, a burst
//! of concurrent ones opens several, and the counter shows the difference.
//!
//! Unix only; skipped when `openssl` or `curl` is not installed.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
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

/// A keep-alive HTTP/1.1 origin: every request is answered after `delay_ms` with a few bytes,
/// on the same connection until the client closes it. Returns its port.
fn origin(delay_ms: u64) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut conn = conn;
                let mut seen = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                        match conn.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => seen.extend_from_slice(&buf[..n]),
                        }
                    }
                    let end = seen.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    seen.drain(..end);
                    std::thread::sleep(Duration::from_millis(delay_ms));
                    let body = b"ok";
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n",
                        body.len()
                    );
                    if conn.write_all(head.as_bytes()).is_err() || conn.write_all(body).is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// The counter as `/metrics` shows it. The page is rendered at most once a second, so it is read
/// after the traffic has stopped for a moment (a stale page would also pass the "reused" check).
fn opened(https: u16) -> u64 {
    std::thread::sleep(Duration::from_millis(1300));
    let out = Command::new("curl")
        .args(["-sk", "--max-time", "10"])
        .arg(format!("https://127.0.0.1:{https}/metrics"))
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("zion_upstream_connections_opened_total "))
        .and_then(|v| v.trim().parse().ok())
        .expect("zion_upstream_connections_opened_total in /metrics")
}

#[test]
fn upstream_connections_are_reused_one_after_another_and_counted_in_a_burst() {
    let has = |tool: &str| Command::new(tool).arg("--version").output().is_ok();
    if !has("curl") || !has("openssl") {
        eprintln!("SKIP: openssl and curl are needed");
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "zion-upstream-conns-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
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
    assert!(made, "openssl could not make a certificate");
    let upstream = origin(150);
    let https = free_port();
    std::fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https}\"\n\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\n\
             [upstreams]\nbackend = \"http://127.0.0.1:{upstream}\"\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n",
            free_port(),
            cert.display(),
            key.display()
        ),
    )
    .unwrap();
    let _z = Proc(
        Command::new(env!("CARGO_BIN_EXE_zion"))
            .env("ZION_CONFIG", dir.join("zion.toml"))
            .env("ZION_BOOT_FAST", "1")
            .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(dir.join("zion.log")).unwrap())
            .spawn()
            .expect("spawn zion"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https)).is_err() {
        assert!(Instant::now() < deadline, "zion never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    let get = |urls: &[String], parallel: bool| {
        let mut cmd = Command::new("curl");
        cmd.args(["-sk", "-o", "/dev/null", "--max-time", "30"]);
        if parallel {
            cmd.args(["-Z", "--parallel-max", "40"]);
        }
        let out = cmd.args(urls).output().expect("curl");
        assert!(out.status.success(), "curl failed: {:?}", out.status);
    };
    let url = |i: usize| format!("https://127.0.0.1:{https}/r/{i}");
    // Wait for the upstream to be marked up, and for the counter to settle.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let out = Command::new("curl")
            .args(["-sk", "-o", "/dev/null", "-w", "%{http_code}"])
            .arg(url(0))
            .output()
            .unwrap();
        if out.stdout == b"200" {
            break;
        }
        assert!(Instant::now() < deadline, "the upstream never answered");
        std::thread::sleep(Duration::from_millis(200));
    }

    // One after another: one connection to the upstream serves them all.
    let before = opened(https);
    get(&(1..=20).map(url).collect::<Vec<_>>(), false);
    let sequential = opened(https) - before;
    assert!(
        sequential <= 1,
        "20 requests one after another opened {sequential} upstream connections"
    );

    // 40 at once: the pool has one idle connection, so the rest each open their own.
    let before = opened(https);
    get(&(100..140).map(url).collect::<Vec<_>>(), true);
    let burst = opened(https) - before;
    assert!(
        burst >= 20,
        "40 concurrent requests opened only {burst} upstream connections"
    );
    let _ = std::fs::remove_dir_all(dir);
}
