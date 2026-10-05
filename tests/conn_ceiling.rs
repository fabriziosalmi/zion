// SPDX-License-Identifier: Apache-2.0
//! `[server] max_connections` (#527), with the real binary: the configured ceiling is the
//! one in force. The connection that would exceed it is refused at accept and counted, the
//! snapshot reports it, and a freed slot is usable again.
//!
//! Like the drain tests, a missing `openssl` (for a throwaway certificate) skips with a
//! message.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

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

/// Start zion with `server` appended to `[server]`; `None` when `openssl` is unavailable.
fn start(server: &str) -> Option<Zion> {
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-ceiling-{}-{http}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
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
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n{server}\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\
             [upstreams]\nbackend = \"http://127.0.0.1:1\"\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n",
            cert.display(),
            key.display()
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
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", http)).is_err() {
        assert!(Instant::now() < deadline, "zion did not start listening");
        std::thread::sleep(Duration::from_millis(100));
    }
    // The probe connections above are gone once zion has seen them close.
    std::thread::sleep(Duration::from_millis(300));
    Some(zion)
}

fn connect(zion: &Zion) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", zion.http)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// One request on `conn`, kept alive; the status line and the body.
fn get(conn: &mut TcpStream, path: &str) -> Option<(String, String)> {
    conn.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .ok()?;
    let (mut got, mut buf) = (Vec::new(), [0u8; 8192]);
    loop {
        let n = conn.read(&mut buf).ok()?;
        if n == 0 {
            return None; // closed without an answer
        }
        got.extend_from_slice(&buf[..n]);
        let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&got[..end]).into_owned();
        let len = head
            .to_ascii_lowercase()
            .lines()
            .find_map(|l| {
                l.strip_prefix("content-length:")
                    .map(str::trim)
                    .map(String::from)
            })
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if got.len() >= end + 4 + len {
            let body = String::from_utf8_lossy(&got[end + 4..end + 4 + len]).into_owned();
            return Some((head.lines().next().unwrap_or("").to_string(), body));
        }
    }
}

/// The snapshot, fetched on `conn`.
fn snapshot(conn: &mut TcpStream) -> serde_json::Value {
    let (status, body) = get(conn, "/_zion/snapshot.json").expect("the snapshot");
    assert!(status.contains("200"), "{status}");
    serde_json::from_str(&body).expect("the snapshot is JSON")
}

#[test]
fn the_configured_ceiling_is_the_one_in_force() {
    const CEILING: usize = 5;
    // The per-IP cap defaults to an eighth of the ceiling, and every connection of this
    // test comes from one address: lift it out of the way so the ceiling is what refuses.
    let Some(zion) = start(&format!(
        "max_connections = {CEILING}\nmax_connections_per_ip = 100"
    )) else {
        return;
    };
    // CEILING connections, each proven open by a request it gets answered.
    let mut held: Vec<TcpStream> = (0..CEILING).map(|_| connect(&zion)).collect();
    for conn in &mut held {
        assert!(
            get(conn, "/healthz").is_some(),
            "a connection within the ceiling is served"
        );
    }
    assert_eq!(
        snapshot(&mut held[0])["platform"]["conn_limit"],
        CEILING,
        "the snapshot reports the configured ceiling"
    );

    // One more: accepted by the kernel, dropped by zion without an answer.
    let mut extra = connect(&zion);
    assert_eq!(
        get(&mut extra, "/healthz"),
        None,
        "the connection over the ceiling is refused"
    );

    // Free a slot: the next connection is served, and the refusal was counted.
    drop(held.pop());
    std::thread::sleep(Duration::from_millis(300));
    let mut again = connect(&zion);
    assert!(
        get(&mut again, "/healthz").is_some(),
        "a freed slot is usable"
    );
    // `/metrics` is on the HTTPS listener: asked with curl, when there is one.
    drop(again);
    std::thread::sleep(Duration::from_millis(300));
    let metrics = Command::new("curl")
        .args(["-sk", "--max-time", "10"])
        .arg(format!("https://127.0.0.1:{}/metrics", zion.https))
        .output();
    match metrics {
        Ok(out) if out.status.success() => {
            let page = String::from_utf8_lossy(&out.stdout);
            let rejected = page
                .lines()
                .find(|l| l.starts_with("zion_connections_rejected_global "))
                .and_then(|l| l.split_whitespace().last())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("no zion_connections_rejected_global in:\n{page}"));
            assert!(rejected >= 1, "the refusal is counted: {rejected}");
        }
        _ => eprintln!("NOTE: no curl here, the rejected-connections counter was not read"),
    }
    let log = std::fs::read_to_string(zion.dir.join("zion.log")).unwrap_or_default();
    assert!(
        log.contains(&format!(
            "connection ceiling {CEILING} (server.max_connections"
        )),
        "the boot log says which ceiling is in force and why:\n{log}"
    );
}

#[test]
fn without_the_setting_the_ceiling_is_derived_from_memory() {
    let Some(zion) = start("") else {
        return;
    };
    let mut conn = connect(&zion);
    let limit = snapshot(&mut conn)["platform"]["conn_limit"]
        .as_u64()
        .expect("conn_limit");
    assert!(
        (1_000..=100_000).contains(&limit),
        "derived from memory, within its clamp: {limit}"
    );
}
