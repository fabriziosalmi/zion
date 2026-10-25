// SPDX-License-Identifier: Apache-2.0
//! `[tls] handshake_timeout_secs` (#719), with the real binary: a connection that completes
//! TCP but never sends its TLS ClientHello is dropped at the configured handshake timeout,
//! not the hardcoded 10 s. An operator under a slow-handshake flood can tighten it to free
//! connection slots sooner.
//!
//! The proof is deterministic, not a wall-clock race: zion logs `tls handshake timed out (Ns)`
//! with the configured N when the timeout fires, so the test boots with `handshake_timeout_secs
//! = 1` and asserts the log names `(1s)` (the configured value, not the 10 s default) and that
//! the stalled socket is then dropped. An earlier version timed the connect-to-drop interval and
//! was flaky on a saturated 2-core CI runner, where a 1 s tokio timer can fire several seconds
//! late; the log line fires exactly when the configured timeout elapses regardless of that slack.
//!
//! A missing `openssl` (for a throwaway certificate) skips with a message.
#![cfg(unix)]

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

struct Zion {
    child: Child,
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

/// Start zion with `tls_extra` appended to `[tls]`; `None` when `openssl` is unavailable.
fn start(tls_extra: &str) -> Option<Zion> {
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-hstimeout-{}-{http}", std::process::id()));
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
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n{tls_extra}\n\
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
    let zion = Zion { child, https, dir };
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", http)).is_err() {
        assert!(Instant::now() < deadline, "zion did not start listening");
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(300));
    Some(zion)
}

/// Poll `log` until it contains `needle`, up to `cap`. Returns whether it appeared. The log is
/// written through an async queue, so we poll rather than read once.
fn log_contains_within(log: &std::path::Path, needle: &str, cap: Duration) -> bool {
    let deadline = Instant::now() + cap;
    loop {
        if std::fs::read_to_string(log)
            .map(|c| c.contains(needle))
            .unwrap_or(false)
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_stalled_handshake_is_dropped_at_the_configured_timeout() {
    let Some(zion) = start("handshake_timeout_secs = 1") else {
        return;
    };
    // Complete TCP, then send no ClientHello: zion awaits the handshake and times out.
    let sock = TcpStream::connect(("127.0.0.1", zion.https)).expect("connect https");

    // The configured timeout is the deterministic proof: zion logs `(1s)`, the value we set,
    // not the 10 s hardcoded default. The 15 s cap is generous so a saturated CI runner that is
    // slow to even accept the connection (its 1 s timer then starts late) still observes the line.
    let log = zion.dir.join("zion.log");
    assert!(
        log_contains_within(
            &log,
            "tls handshake timed out (1s)",
            Duration::from_secs(15)
        ),
        "zion must log the configured 1 s handshake timeout; log so far:\n{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );

    // Having timed out, zion drops the connection: the read returns promptly with EOF (clean
    // close) or a connection error, never WouldBlock-after-the-cap and never live data.
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 16];
    match (&sock).read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("stalled handshake must be dropped, not answered with {n} bytes"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            panic!("zion did not close the stalled connection within 2 s of logging the timeout")
        }
        Err(_) => {} // reset / broken pipe: the peer closed, which is the drop we expect
    }
}
