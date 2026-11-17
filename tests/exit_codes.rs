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
    // Forward-slash the paths: a Windows path (`C:\Users\...`) embedded in a
    // TOML basic string would be an invalid escape and fail config PARSING
    // (exit 2) before ever reaching TLS load (exit 3). Windows file APIs
    // accept forward slashes, so this keeps the test cross-platform.
    let cert_toml = cert.display().to_string().replace('\\', "/");
    let key_toml = key.display().to_string().replace('\\', "/");
    fs::write(
        &cfg,
        format!(
            r#"
[server]
listen_http = "127.0.0.1:18091"
listen_https = "127.0.0.1:18491"

[tls]
cert_path = "{cert_toml}"
key_path = "{key_toml}"
hot_reload = false

[upstreams]
backend = "http://127.0.0.1:9099"

[[route]]
path = "/{{*rest}}"
upstream = "backend"
"#
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

/// A subcommand given a flag it does not know must not run with defaults: `zion init -y
/// --ouput <path>` used to write `./zion.toml` and exit 0 (ZION-API-02). It is a usage error,
/// exit 2, that names the flag, and nothing is written.
#[test]
fn unknown_cli_flag_exits_2_and_writes_nothing() {
    let dir = unique_dir("cli-usage");
    let out = zion()
        .current_dir(&dir)
        .args(["init", "-y", "--no-tls", "--ouput", "elsewhere.toml"])
        .output()
        .expect("spawn zion");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("unknown flag `--ouput`") && stderr.contains("`--output`"),
        "stderr must name the flag and the nearest valid one: {stderr}"
    );
    assert!(
        !dir.join("zion.toml").exists() && !dir.join("elsewhere.toml").exists(),
        "a usage error must not write a config"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// `zion import` keeps exit 2 for "converted, `--strict` found partial/unsupported directives"
/// (ADR-0011): a usage error there is the fatal 1, so a script branching on 2 never takes a
/// typo for a conversion with findings.
#[test]
fn import_usage_error_exits_1_not_the_strict_findings_code() {
    let out = zion()
        .args(["import", "nginx", "-", "--strct"])
        .output()
        .expect("spawn zion");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("unknown flag `--strct`"),
        "stderr: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "nothing may be emitted on a usage error"
    );
}

/// `[tls.acme]` writes the certificate it obtains to `[tls] cert_path` / `key_path`. A certificate
/// directory zion cannot write (here read-only, as `/etc` is under the shipped systemd unit) made
/// every issuance and renewal fail, found only when the bootstrap certificate expired. It is now
/// a config error at boot: exit 2, naming the directory, before any port is bound or any ACME
/// server is contacted. Only with `--features acme` (the CI `all-features` run).
#[cfg(all(unix, feature = "acme"))]
#[test]
fn acme_with_an_unwritable_certificate_directory_exits_2() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir("acme");
    let certs = dir.join("certs");
    fs::create_dir_all(&certs).unwrap();
    let (cert, key) = (certs.join("cert.pem"), certs.join("key.pem"));
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
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !made {
        eprintln!("SKIP: openssl not available");
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    fs::set_permissions(&certs, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::File::create(certs.join("probe")).is_ok() {
        // Running as root: a read-only mode does not stop it, so there is nothing to refuse.
        eprintln!("SKIP: running as root, the directory stays writable");
        let _ = fs::set_permissions(&certs, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let cfg = dir.join("zion.toml");
    fs::write(
        &cfg,
        format!(
            r#"
[server]
listen_http = "127.0.0.1:18094"
listen_https = "127.0.0.1:18494"

[tls]
cert_path = "{}"
key_path = "{}"
hot_reload = false

[tls.acme]
email = "ops@example.invalid"
domains = ["example.invalid"]
directory_url = "https://127.0.0.1:9/directory"
state_dir = "{}"

[upstreams]
backend = "http://127.0.0.1:9099"

[[route]]
path = "/{{*rest}}"
upstream = "backend"
"#,
            cert.display(),
            key.display(),
            dir.join("state").display()
        ),
    )
    .unwrap();

    // Bounded: without the check zion boots and serves, and `output()` would wait forever.
    let log = dir.join("stderr.log");
    let mut child = zion()
        .env("ZION_CONFIG", &cfg)
        .stdout(std::process::Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .expect("spawn zion");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let stderr = fs::read_to_string(&log).unwrap_or_default();
    let _ = fs::set_permissions(&certs, fs::Permissions::from_mode(0o755));
    let _ = fs::remove_dir_all(&dir);
    let status = status.unwrap_or_else(|| panic!("zion booted and kept running:\n{stderr}"));
    assert_eq!(
        status.code(),
        Some(2),
        "an unwritable certificate directory under [tls.acme] must exit 2, got {:?}\n{stderr}",
        status.code()
    );
    assert!(
        stderr.contains("cannot create files in") && stderr.contains("certs"),
        "the error names the directory:\n{stderr}"
    );
}
