//! End-to-end checks of the admin API's write controls, against the real binary:
//! the write token (`[admin] write_token_env`), `persist_push`, and `/admin/revoke`.
//!
//! Unix only, and skipped when `openssl` is not installed (it makes the throwaway
//! certificate the daemon needs to boot). Every port is picked free at run time.
#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

const TOKEN: &str = "0123456789abcdef0123456789abcdef-write-token";

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
    let d = dir.display().to_string();
    [
        "[server]".to_string(),
        format!("listen_http = \"127.0.0.1:{}\"", free_port()),
        format!("listen_https = \"127.0.0.1:{}\"", free_port()),
        "rate_limit_rps = ".to_string() + &rps.to_string(),
        String::new(),
        "[tls]".to_string(),
        format!("cert_path = \"{d}/c.pem\""),
        format!("key_path = \"{d}/k.pem\""),
        "hot_reload = false".to_string(),
        String::new(),
        "[upstreams]".to_string(),
        "backend = \"http://127.0.0.1:9\"".to_string(),
        String::new(),
        "[[route]]".to_string(),
        "path = \"/{*rest}\"".to_string(),
        "upstream = \"backend\"".to_string(),
        String::new(),
        "[admin]".to_string(),
        "listen = \"127.0.0.1:".to_string() + &admin_port.to_string() + "\"",
        "write_token_env = \"ZION_TEST_ADMIN_WRITE_TOKEN\"".to_string(),
        "persist_push = ".to_string() + &persist.to_string(),
        "rate_limit_rps = 1000".to_string(),
        String::new(),
    ]
    .join("\n")
}

/// The same config with another `rate_limit_rps`: listen ports must not change, or a
/// reload is refused on io-uring builds.
fn with_rps(cfg: &str, rps: u32) -> String {
    cfg.replace("rate_limit_rps = 0", &format!("rate_limit_rps = {rps}"))
}

/// Boot the daemon, retrying with fresh ports if one of them was taken by another process in the
/// meantime (the daemon then logs `Address already in use` and runs without its admin API or a
/// listener, and waiting for the admin port could be satisfied by somebody else's daemon).
fn boot(persist: bool) -> Option<(Daemon, u16, std::path::PathBuf, std::path::PathBuf)> {
    boot_with(persist, true)
}

/// [`boot`], optionally WITHOUT `write_token_env` in `[admin]`.
fn boot_with(
    persist: bool,
    write_token: bool,
) -> Option<(Daemon, u16, std::path::PathBuf, std::path::PathBuf)> {
    for attempt in 1..=5 {
        match boot_once(persist, write_token) {
            Boot::NoOpenssl => return None,
            Boot::Up(d, port, dir, cfg) => return Some((d, port, dir, cfg)),
            Boot::PortTaken(log) => {
                eprintln!("boot attempt {attempt}: a port was taken, retrying:\n{log}")
            }
        }
    }
    panic!("the daemon could not get its ports in 5 attempts");
}

enum Boot {
    NoOpenssl,
    Up(Daemon, u16, std::path::PathBuf, std::path::PathBuf),
    PortTaken(String),
}

fn boot_once(persist: bool, write_token: bool) -> Boot {
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
        return Boot::NoOpenssl;
    }
    let admin_port = free_port();
    let cfg = dir.join("zion.toml");
    let mut text = config(&dir, admin_port, 0, persist);
    if !write_token {
        text = text.replace("write_token_env = \"ZION_TEST_ADMIN_WRITE_TOKEN\"\n", "");
    }
    fs::write(&cfg, text).unwrap();
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
    let log = || fs::read_to_string(dir.join("daemon.log")).unwrap_or_default();
    // Up means: it says it is listening (boot finished), and then the admin port answers.
    let deadline = Instant::now() + Duration::from_secs(20);
    while !log().contains("listening HTTPS on") {
        assert!(
            Instant::now() < deadline,
            "the daemon never finished booting; it said:\n{}",
            log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    if log().contains("Address already in use") {
        return Boot::PortTaken(log());
    }
    while TcpStream::connect(("127.0.0.1", admin_port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "admin API never came up; daemon said:\n{}",
            log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Boot::Up(d, admin_port, dir, cfg)
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
    let good = with_rps(&fs::read_to_string(&cfg).unwrap(), 7);
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
    let pushed = with_rps(&original, 9);
    let (status, body) = http(port, "POST", "/admin/config", Some(TOKEN), &pushed);
    assert_eq!(
        status,
        200,
        "push answered {status}: {body}\ndaemon said:\n{}",
        fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
    );
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        original,
        "persist_push = false leaves zion.toml as it was"
    );
    let _ = fs::remove_dir_all(dir);
}

/// The collision these tests used to suffer: `free_port` must never give one port to two callers
/// of the same process, even from parallel threads (the kernel happily reuses a port it just got
/// back). With hundreds of draws from the ephemeral range, plain "bind 0 and drop" repeats one.
#[test]
fn free_port_never_hands_out_the_same_port_twice() {
    let ports: Vec<u16> = std::thread::scope(|s| {
        (0..8)
            .map(|_| s.spawn(|| (0..400).map(|_| free_port()).collect::<Vec<_>>()))
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    let distinct: std::collections::HashSet<_> = ports.iter().collect();
    assert_eq!(distinct.len(), ports.len(), "a port was handed out twice");
}

/// Without a write token configured, network position alone never authorizes a write:
/// reads work, every POST is refused (it used to be accepted from any loopback peer).
#[test]
fn without_a_write_token_writes_are_refused() {
    let Some((_d, port, dir, _cfg)) = boot_with(false, false) else {
        return;
    };
    assert_eq!(
        http(port, "GET", "/admin/config", None, "").0,
        200,
        "reads work"
    );
    for (path, body) in [
        ("/admin/reload", ""),
        ("/admin/revoke", r#"{"jti":"a"}"#),
        ("/admin/config", "[server]\n"),
    ] {
        let (st, resp) = http(port, "POST", path, None, body);
        assert_eq!(st, 403, "{path}: {resp}");
        assert!(
            resp.contains("write_token_env"),
            "{path} says what to set: {resp}"
        );
    }
    let _ = fs::remove_dir_all(dir);
}

/// Run openssl with `args`; true on success.
fn openssl(args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A CA in `dir/<name>-ca.{pem,key}` and a client certificate it signed in
/// `dir/<name>-client.{pem,key}` (v3, clientAuth).
fn ca_and_client(dir: &std::path::Path, name: &str) -> bool {
    let p = |f: &str| {
        dir.join(format!("{name}-{f}"))
            .to_string_lossy()
            .into_owned()
    };
    let ext = dir.join(format!("{name}-ext.cnf"));
    fs::write(
        &ext,
        "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n",
    )
    .unwrap();
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        &format!("/CN={name}-ca"),
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign",
        "-keyout",
        &p("ca.key"),
        "-out",
        &p("ca.pem"),
    ]) && openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        &format!("/CN={name}-client"),
        "-keyout",
        &p("client.key"),
        "-out",
        &p("client.csr"),
    ]) && openssl(&[
        "x509",
        "-req",
        "-in",
        &p("client.csr"),
        "-CA",
        &p("ca.pem"),
        "-CAkey",
        &p("ca.key"),
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        &ext.to_string_lossy(),
        "-out",
        &p("client.pem"),
    ])
}

/// GET /admin/config over TLS with a client certificate; the status, 0 when refused.
fn mtls_get(port: u16, cert: &std::path::Path, key: &std::path::Path) -> u16 {
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-quiet",
            "-connect",
            &format!("127.0.0.1:{port}"),
        ])
        .arg("-cert")
        .arg(cert)
        .arg("-key")
        .arg(key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"GET /admin/config HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// `auth = "mtls"` trusts `admin.client_ca_path` only: a client certificate issued by the
/// data-plane CA (`tls.client_ca_path`) does not open the admin API.
#[test]
fn admin_mtls_trusts_only_the_admin_ca() {
    let dir = std::env::temp_dir().join(format!(
        "zion-admin-mtls-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    let server_ok = openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost",
        "-keyout",
        &dir.join("k.pem").to_string_lossy(),
        "-out",
        &dir.join("c.pem").to_string_lossy(),
    ]);
    if !(server_ok && ca_and_client(&dir, "data") && ca_and_client(&dir, "admin")) {
        eprintln!("SKIP: openssl could not make the test certificates");
        return;
    }
    let d = dir.to_string_lossy();
    let admin_port = free_port();
    let cfg = format!(
        "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{}\"\n\n\
         [tls]\ncert_path = \"{d}/c.pem\"\nkey_path = \"{d}/k.pem\"\nhot_reload = false\n\
         client_auth = \"optional\"\nclient_ca_path = \"{d}/data-ca.pem\"\n\n\
         [upstreams]\nbackend = \"http://127.0.0.1:9\"\n\n\
         [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n\n\
         [admin]\nlisten = \"127.0.0.1:{admin_port}\"\nauth = \"mtls\"\n\
         client_ca_path = \"{d}/admin-ca.pem\"\nrate_limit_rps = 1000\n",
        free_port(),
        free_port()
    );
    fs::write(dir.join("zion.toml"), cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", dir.join("zion.toml"))
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(dir.join("daemon.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let _d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", admin_port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "admin API never came up: {}",
            fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        mtls_get(
            admin_port,
            &dir.join("admin-client.pem"),
            &dir.join("admin-client.key")
        ),
        200,
        "a certificate from the admin CA opens the admin API"
    );
    assert_eq!(
        mtls_get(
            admin_port,
            &dir.join("data-client.pem"),
            &dir.join("data-client.key")
        ),
        0,
        "a data-plane client certificate must not"
    );
    let _ = fs::remove_dir_all(dir);
}
