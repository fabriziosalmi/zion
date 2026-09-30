//! End-to-end checks of the admin API's write controls, against the real binary:
//! the write token (`[admin] write_token_env`), `persist_push`, and `/admin/revoke`.
//!
//! Unix only, and skipped when `openssl` is not installed (it makes the throwaway
//! certificate the daemon needs to boot). Every port is picked free at run time.
#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "0123456789abcdef0123456789abcdef-write-token";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One HTTP/1.1 request over a fresh connection. Returns (status, body).
fn http(port: u16, method: &str, path: &str, token: Option<&str>, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect admin");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = String::new();
    let _ = s.read_to_string(&mut raw);
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config(dir: &std::path::Path, admin_port: u16, rps: u32, persist: bool) -> String {
    format!(
        r#"[server]
listen_http = "127.0.0.1:{}"
listen_https = "127.0.0.1:{}"
rate_limit_rps = {rps}

[tls]
cert_path = "{d}/c.pem"
key_path = "{d}/k.pem"
hot_reload = false

[upstreams]
backend = "http://127.0.0.1:9"

[[route]]
path = "/{{*rest}}"
upstream = "backend"

[admin]
listen = "127.0.0.1:{admin_port}"
write_token_env = "ZION_TEST_ADMIN_WRITE_TOKEN"
persist_push = {persist}
rate_limit_rps = 1000
"#,
        free_port(),
        free_port(),
        d = dir.display(),
    )
}

fn boot(persist: bool) -> Option<(Daemon, u16, std::path::PathBuf, std::path::PathBuf)> {
    let dir = std::env::temp_dir().join(format!(
        "zion-admin-e2e-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    let ok = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048"])
        .args(["-nodes", "-days", "1", "-subj", "/CN=localhost"])
        .args(["-addext", "subjectAltName=DNS:localhost"])
        .arg("-keyout")
        .arg(dir.join("k.pem"))
        .arg("-out")
        .arg(dir.join("c.pem"))
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: openssl not available");
        return None;
    }
    let admin_port = free_port();
    let cfg = dir.join("zion.toml");
    fs::write(&cfg, config(&dir, admin_port, 0, persist)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", &cfg)
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_TEST_ADMIN_WRITE_TOKEN", TOKEN)
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(dir.join("daemon.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", admin_port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "admin API never came up; daemon said:\n{}",
            fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Some((d, admin_port, dir, cfg))
}

#[test]
fn writes_need_the_token_reads_do_not() {
    let Some((_d, port, dir, _cfg)) = boot(false) else {
        return;
    };
    assert_eq!(
        http(port, "GET", "/admin/config", None, "").0,
        200,
        "read stays open"
    );
    for (label, tok) in [("none", None), ("wrong", Some("nope-nope-nope"))] {
        let (st, _) = http(port, "POST", "/admin/reload", tok, "");
        assert_eq!(st, 401, "{label} token must not reload");
        let (st, _) = http(port, "POST", "/admin/revoke", tok, r#"{"jti":"a"}"#);
        assert_eq!(st, 401, "{label} token must not revoke");
    }
    let (st, body) = http(port, "POST", "/admin/reload", Some(TOKEN), "");
    assert_eq!(st, 200, "{body}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn revoke_validates_its_body() {
    let Some((_d, port, dir, _cfg)) = boot(false) else {
        return;
    };
    let (st, body) = http(
        port,
        "POST",
        "/admin/revoke",
        Some(TOKEN),
        r#"{"jti":"tok-1"}"#,
    );
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"revoked\":true"), "{body}");
    assert_eq!(
        http(port, "POST", "/admin/revoke", Some(TOKEN), "not json").0,
        400
    );
    assert_eq!(
        http(port, "POST", "/admin/revoke", Some(TOKEN), r#"{"jti":""}"#).0,
        400
    );
    assert_eq!(
        http(
            port,
            "POST",
            "/admin/revoke",
            Some(TOKEN),
            r#"{"jti":"x","extra":1}"#
        )
        .0,
        400,
        "unknown fields are refused"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn persist_push_writes_only_what_validated() {
    let Some((_d, port, dir, cfg)) = boot(true) else {
        return;
    };
    let good = config(&dir, port, 7, true);
    let (st, body) = http(port, "POST", "/admin/config", Some(TOKEN), &good);
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        good,
        "an accepted push is written back"
    );

    let before = fs::read_to_string(&cfg).unwrap();
    let (st, _) = http(
        port,
        "POST",
        "/admin/config",
        Some(TOKEN),
        "this is not toml [[[",
    );
    assert_eq!(st, 400);
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        before,
        "a rejected push leaves the file alone"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_push_is_live_only_by_default() {
    let Some((_d, port, dir, cfg)) = boot(false) else {
        return;
    };
    let original = fs::read_to_string(&cfg).unwrap();
    let pushed = config(&dir, port, 9, false);
    assert_eq!(
        http(port, "POST", "/admin/config", Some(TOKEN), &pushed).0,
        200
    );
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        original,
        "persist_push = false leaves zion.toml as it was"
    );
    let _ = fs::remove_dir_all(dir);
}
