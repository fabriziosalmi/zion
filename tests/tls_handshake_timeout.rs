// SPDX-License-Identifier: Apache-2.0
//! `[tls] handshake_timeout_secs` (#719), with the real binary: a connection that completes
//! TCP but never sends its TLS ClientHello is dropped after the configured handshake timeout,
//! not the hardcoded 10 s. An operator under a slow-handshake flood can tighten it to free
//! connection slots sooner.
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
    std::thread::sleep(Duration::from_millis(300));
    Some(zion)
}

/// How long zion keeps a TLS connection that never sends its ClientHello. We connect to the
/// HTTPS listener, send nothing, and time until zion closes it (read returns EOF or errors).
fn time_to_drop(https: u16, cap: Duration) -> Duration {
    let s = TcpStream::connect(("127.0.0.1", https)).expect("connect https");
    s.set_read_timeout(Some(cap)).unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 16];
    // No ClientHello is ever sent. zion awaits the handshake and drops us at the timeout;
    // the read then returns Ok(0) (clean EOF) or a reset/timeout error.
    let _ = (&s).read(&mut buf);
    start.elapsed()
}

#[test]
fn a_stalled_handshake_is_dropped_at_the_configured_timeout() {
    let Some(zion) = start("handshake_timeout_secs = 1") else {
        return;
    };
    // With a 1 s timeout the stalled connection is dropped around 1 s, well before the
    // hardcoded 10 s default would. A read cap of 6 s is the referee: if the drop took the
    // old 10 s, the read would hit the cap and report ~6 s.
    let elapsed = time_to_drop(zion.https, Duration::from_secs(6));
    assert!(
        elapsed < Duration::from_secs(4),
        "a 1 s handshake timeout must drop the stalled connection in about 1 s, took {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(700),
        "it should wait roughly the timeout, not reject instantly: took {elapsed:?}"
    );
}
