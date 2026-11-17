// SPDX-License-Identifier: Apache-2.0
//! A `jwks_url` with credentials in it does not reach the log, with the real binary.
//!
//! Config validation already showed the URL without its `user:password@`, but the JWKS refresher
//! logged it as written, on every failed fetch, and reqwest's own error message carried it again.
//! Needs `--features auth` (CI's all-features test job) and `openssl`.
#![cfg(all(unix, feature = "auth"))]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

struct Daemon(Child, std::path::PathBuf);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

#[test]
fn credentials_in_the_jwks_url_are_not_logged() {
    let dir = std::env::temp_dir().join(format!("zion-jwks-log-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    let made = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args([
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
        ])
        .args(["-subj", "/CN=localhost", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !made {
        common::skip("openssl not available");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    // Port 9 (discard) on loopback: nothing answers, so the first fetch fails at once.
    let cfg = dir.join("zion.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{}\"\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\
             [auth_profile.oidc]\njwks_url = \"http://jwks-user:s3cr3t-pass@127.0.0.1:9/jwks\"\n\
             algorithm = \"RS256\"\n\
             [upstreams]\nbackend = \"http://127.0.0.1:1\"\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\nauth_profile = \"oidc\"\n",
            free_port(),
            free_port(),
            cert.display(),
            key.display()
        ),
    )
    .unwrap();
    let log = dir.join("zion.log");
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", &cfg)
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(std::fs::File::create(dir.join("stdout.log")).unwrap())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .expect("spawn zion");
    let _daemon = Daemon(child, dir.clone());
    let read = || {
        std::fs::read_to_string(&log).unwrap_or_default()
            + &std::fs::read_to_string(dir.join("stdout.log")).unwrap_or_default()
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while !read().contains("Failed to fetch JWKS") {
        assert!(
            Instant::now() < deadline,
            "no JWKS fetch failure logged:\n{}",
            read()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = read();
    assert!(
        out.contains("Failed to fetch JWKS from http://127.0.0.1:9/jwks"),
        "the URL is logged without its credentials:\n{out}"
    );
    assert!(
        !out.contains("s3cr3t-pass") && !out.contains("jwks-user"),
        "the JWKS URL's credentials reached the log:\n{out}"
    );
}
