// SPDX-License-Identifier: Apache-2.0
//! A `ktls` build on a kernel without kernel TLS serves HTTPS on userspace TLS, with the real
//! binary. Before the fix every connection tried the upgrade after its handshake, the upgrade
//! failed (`failed to enable TLS ULP ... os error 2` on a runner without the `tls` module) and
//! zion closed the connection: every HTTPS request got no answer.
//!
//! The runner may well have the module loaded (the CI `ktls` flavor loads it), so the test
//! forces the kernel-without-kTLS case with `ZION_TEST_KTLS_UNSUPPORTED=1`, a debug-build-only
//! override that makes the boot probe read "unsupported" AND makes any upgrade attempt fail, as
//! on such a kernel. The proof is a 200 over HTTPS, the one boot warning, and no per-connection
//! upgrade failure in the log.
//!
//! Linux with `--features ktls` only: the other builds have no kTLS path. A missing `openssl`
//! or `curl` skips with a message.
#![cfg(all(target_os = "linux", feature = "ktls"))]

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

fn have(tool: &str, arg: &str) -> bool {
    Command::new(tool)
        .arg(arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Start zion with kernel TLS forced off; `None` when `openssl` or `curl` is unavailable.
fn start_without_ktls() -> Option<Zion> {
    if !have("curl", "--version") {
        common::skip("curl not available");
        return None;
    }
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-ktls-fb-{}-{http}", std::process::id()));
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
        common::skip("openssl not available");
        return None;
    }
    let cfg = dir.join("zion.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
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
        .env("ZION_TEST_KTLS_UNSUPPORTED", "1")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("zion.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let zion = Zion { child, https, dir };
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https)).is_err() {
        assert!(Instant::now() < deadline, "zion did not start listening");
        std::thread::sleep(Duration::from_millis(100));
    }
    Some(zion)
}

#[test]
fn a_kernel_without_ktls_serves_https_on_userspace_tls() {
    let Some(zion) = start_without_ktls() else {
        return;
    };
    let log = zion.dir.join("zion.log");
    common::wait_for_log(
        &log,
        "HTTPS is served on userspace TLS",
        Duration::from_secs(15),
    );

    // Several connections, each a fresh handshake: before the fix every one was closed.
    for i in 0..3 {
        let out = Command::new("curl")
            .args([
                "-sk",
                "--max-time",
                "5",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
            ])
            .arg(format!("https://127.0.0.1:{}/healthz", zion.https))
            .output()
            .expect("run curl");
        let code = String::from_utf8_lossy(&out.stdout).to_string();
        assert_eq!(
            code,
            "200",
            "request {i} over HTTPS must be answered on userspace TLS; log:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
    }

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !text.contains("kTLS upgrade failed"),
        "no connection may attempt the upgrade on a kernel without kTLS; log:\n{text}"
    );
    assert_eq!(
        text.matches("does NOT advertise kTLS support").count(),
        1,
        "the missing kernel support is reported once, at boot; log:\n{text}"
    );
}
