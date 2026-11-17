// SPDX-License-Identifier: Apache-2.0
//! A proxied WebSocket session holds its client's connection slot, with the real binary.
//!
//! After the `101`, hyper hands the socket to the relay and the connection's own task ends. The
//! global permit (`max_connections`) and the per-IP slot (`max_connections_per_ip`) lived in that
//! task, so they were released while the session stayed open (up to `websocket_max_session_secs`,
//! a day by default): one address could hold any number of sessions past both limits. The relay
//! now holds them until the session ends.
//!
//! The sessions are `openssl s_client` processes (a missing `openssl` skips with a message); the
//! connection that should be refused is a plain-HTTP `/healthz` from the same address, which takes
//! the same per-IP slot and global permit before it is answered.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
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

/// An origin that answers a WebSocket upgrade with `101` and then keeps the tunnel open, reading
/// until the other side closes; any other request gets `200`.
fn ws_origin() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                // Anything but an upgrade (zion's health probe) gets a plain 200.
                if !String::from_utf8_lossy(&head)
                    .to_ascii_lowercase()
                    .contains("upgrade: websocket")
                {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    return;
                }
                // The Sec-WebSocket-Accept is the RFC 6455 example value for the key sent below.
                let _ = s.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                      Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                );
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    port
}

/// Start zion with `server` appended to `[server]` and a websocket route to `origin`; `None` when
/// `openssl` is unavailable.
fn start(server: &str, origin: u16) -> Option<Zion> {
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-ws-slots-{}-{http}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
    let made = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args([
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
        ])
        .args(["-subj", "/CN=localhost"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
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
             [upstreams]\nbackend = \"http://127.0.0.1:{origin}\"\n\
             [[route]]\npath = \"/ws/{{*rest}}\"\nupstream = \"backend\"\nmode = \"websocket\"\n",
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
    while TcpStream::connect(("127.0.0.1", http)).is_err()
        || TcpStream::connect(("127.0.0.1", https)).is_err()
    {
        assert!(Instant::now() < deadline, "zion did not start listening");
        std::thread::sleep(Duration::from_millis(100));
    }
    // The probe connections above are gone once zion has seen them close.
    std::thread::sleep(Duration::from_millis(300));
    Some(zion)
}

/// An open WebSocket session through zion: the TLS client process, kept alive with its stdin.
struct Session {
    child: Child,
    _stdin: ChildStdin,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Open a WebSocket session through zion and return it once zion relayed the origin's `101`.
fn open_session(zion: &Zion) -> Session {
    let mut child = Command::new("openssl")
        .args(["s_client", "-quiet", "-alpn", "http/1.1", "-connect"])
        .arg(format!("127.0.0.1:{}", zion.https))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl s_client");
    let mut stdin = child.stdin.take().unwrap();
    // The Sec-WebSocket-Key is the RFC 6455 example vector, not a secret.
    stdin
        .write_all(
            b"GET /ws/x HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", // gitleaks:allow
        )
        .unwrap();
    stdin.flush().unwrap();
    let out = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(out).read_line(&mut line);
        let _ = tx.send(line);
    });
    let status = rx.recv_timeout(Duration::from_secs(10)).unwrap_or_default();
    assert!(
        status.starts_with("HTTP/1.1 101"),
        "the upgrade is relayed: {status:?}"
    );
    Session {
        child,
        _stdin: stdin,
    }
}

/// `GET /healthz` on a new plain-HTTP connection: `true` when it is answered (with any status:
/// the plain listener redirects to HTTPS), `false` when zion closes the connection unanswered
/// (refused at accept).
fn healthz_answered(zion: &Zion) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", zion.http)) else {
        return false;
    };
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    got.starts_with(b"HTTP/1.1 ")
}

/// Wait up to 3 s for `healthz_answered` to become `want`.
fn healthz_becomes(zion: &Zion, want: bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if healthz_answered(zion) == want {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// With `server`, two open sessions fill the limit: a third connection is refused, and closing
/// one session frees its slot.
fn two_sessions_fill(server: &str, what: &str) {
    let origin = ws_origin();
    let Some(zion) = start(server, origin) else {
        return;
    };
    assert!(healthz_answered(&zion), "{what}: served before any session");
    let first = open_session(&zion);
    let _second = open_session(&zion);
    // Past the upgrade the connection task has ended; the sessions are only relays now.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !healthz_answered(&zion),
        "{what}: two open WebSocket sessions hold both slots, so a third connection is refused"
    );
    drop(first);
    assert!(
        healthz_becomes(&zion, true),
        "{what}: a session that ends gives its slot back"
    );
}

#[test]
fn websocket_sessions_count_against_the_per_ip_cap() {
    two_sessions_fill(
        "max_connections = 100\nmax_connections_per_ip = 2",
        "per-IP cap",
    );
}

#[test]
fn websocket_sessions_count_against_the_connection_ceiling() {
    two_sessions_fill(
        "max_connections = 2\nmax_connections_per_ip = 0",
        "global ceiling",
    );
}
