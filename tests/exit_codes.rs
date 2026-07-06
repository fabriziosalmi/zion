//! Operator contract: the daemon's exit code encodes the failure category so
//! a process supervisor (systemd `Restart=`, k8s `restartPolicy`) can branch —
//! a config error (2) must NOT trigger a restart loop, a bind error (4) should.
//!
//! Before `main()` was wired through `ZionError::to_exit_code`, every boot
//! failure collapsed to exit 1. These tests run the real binary and assert the
//! distinct codes, so that regression can't silently return.
//!
//! They exercise only the pre-bind boot stages (config load = step 1, TLS load
//! = step 3), so no ports are bound and the runs are fast and deterministic.
//! `ZION_BOOT_FAST=1` skips the AES self-calibration.

use std::fs;
use std::process::Command;

fn zion() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_zion"));
    c.env("ZION_BOOT_FAST", "1")
        // Keep the panic-hook's last-gasp file off the runner's real path.
        .env(
            "ZION_LAST_GASP_PATH",
            std::env::temp_dir().join("zion-test-lastgasp.jsonl"),
        );
    c
}

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("zion-exit-{}-{}", tag, std::process::id()));
    fs::create_dir_all(&d).expect("mkdir");
    d
}

/// A missing / unreadable config is a Config error → exit 2 (was 1).
#[test]
fn missing_config_exits_2() {
    let status = zion()
        .env("ZION_CONFIG", "/nonexistent/zion-does-not-exist.toml")
        .status()
        .expect("spawn zion");
    assert_eq!(
        status.code(),
        Some(2),
        "unreadable config must exit 2 (config category), got {:?}",
        status.code()
    );
}

/// A schema-valid config whose cert files exist but are not valid PEM passes
/// validation (which only checks existence) then fails TLS material loading →
/// exit 3 (was 1). This proves the categories are DISTINCT, not just non-zero.
#[test]
fn bad_tls_material_exits_3() {
    let dir = unique_dir("tls");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    fs::write(&cert, b"not a real certificate\n").unwrap();
    fs::write(&key, b"not a real key\n").unwrap();
    let cfg = dir.join("zion.toml");
    fs::write(
        &cfg,
        format!(
            r#"
[server]
listen_http = "127.0.0.1:18091"
listen_https = "127.0.0.1:18491"

[tls]
cert_path = "{cert}"
key_path = "{key}"
hot_reload = false

[upstreams]
backend = "http://127.0.0.1:9099"

[[route]]
path = "/{{*rest}}"
upstream = "backend"
"#,
            cert = cert.display(),
            key = key.display(),
        ),
    )
    .unwrap();

    let status = zion()
        .env("ZION_CONFIG", &cfg)
        .status()
        .expect("spawn zion");
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        status.code(),
        Some(3),
        "invalid TLS material must exit 3 (tls category), got {:?}",
        status.code()
    );
}

/// A schema-valid config that references an unknown upstream fails semantic
/// validation → Config → exit 2 (still the config category, distinct from a
/// TLS or bind failure).
#[test]
fn dangling_upstream_exits_2() {
    let dir = unique_dir("cfg");
    let cfg = dir.join("zion.toml");
    fs::write(
        &cfg,
        r#"
[server]
listen_http = "127.0.0.1:18092"
listen_https = "127.0.0.1:18492"

[tls]
cert_path = "/etc/ssl/zion/zion.crt"
key_path = "/etc/ssl/zion/zion.key"

[upstreams]
backend = "http://127.0.0.1:9099"

[[route]]
path = "/{*rest}"
upstream = "ghost"
"#,
    )
    .unwrap();

    let status = zion()
        .env("ZION_CONFIG", &cfg)
        .status()
        .expect("spawn zion");
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        status.code(),
        Some(2),
        "dangling upstream reference must exit 2 (config category), got {:?}",
        status.code()
    );
}
