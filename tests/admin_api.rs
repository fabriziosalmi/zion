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

/// Start the daemon on an existing config and wait for its admin API.
fn start(cfg: &std::path::Path, dir: &std::path::Path, admin_port: u16, log_name: &str) -> Daemon {
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", cfg)
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_TEST_ADMIN_WRITE_TOKEN", TOKEN)
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(dir.join(log_name)).unwrap())
        .spawn()
        .expect("spawn zion");
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", admin_port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "admin API never came up; daemon said:\n{}",
            fs::read_to_string(dir.join(log_name)).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    d
}

/// A revoked token id is still revoked after a restart when `[admin] revocations_path` is
/// set (ZION-AUTH-06). Without it the list was in memory only: a restart made every revoked
/// token valid again until it expired.
#[test]
fn a_revocation_survives_a_restart() {
    let Some((first, port, dir, cfg)) = boot(false) else {
        return;
    };
    drop(first); // only wanted its certificates and config
    let recorded = dir.join("revoked.jsonl");
    let mut text = fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!("revocations_path = \"{}\"\n", recorded.display()));
    fs::write(&cfg, text).unwrap();
    let far = 4_102_444_800u64; // 2100-01-01

    let run1 = start(&cfg, &dir, port, "run1.log");
    let (st, body) = http(
        port,
        "POST",
        "/admin/revoke",
        Some(TOKEN),
        &format!(r#"{{"jti":"stolen-token-id","exp":{far}}}"#),
    );
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"live_entries\":1"), "{body}");
    assert!(
        fs::read_to_string(&recorded)
            .unwrap()
            .contains("stolen-token-id"),
        "recorded before the operator is told it is revoked"
    );
    drop(run1);

    // Restart: the list comes back from the file before anything is served.
    let run2 = start(&cfg, &dir, port, "run2.log");
    let log = fs::read_to_string(dir.join("run2.log")).unwrap();
    assert!(log.contains("1 revoked token id(s) loaded"), "{log}");
    // The in-memory list already holds the first id: a second one makes two.
    let (st, body) = http(
        port,
        "POST",
        "/admin/revoke",
        Some(TOKEN),
        &format!(r#"{{"jti":"another-id","exp":{far}}}"#),
    );
    assert_eq!(st, 200, "{body}");
    assert!(
        body.contains("\"live_entries\":2"),
        "the first id was loaded: {body}"
    );

    // The file can no longer be written (a directory took its place): the revocation is in
    // force, and the operator is told it would not survive a restart.
    fs::remove_file(&recorded).unwrap();
    fs::create_dir(&recorded).unwrap();
    let (st, body) = http(
        port,
        "POST",
        "/admin/revoke",
        Some(TOKEN),
        &format!(r#"{{"jti":"not-durable","exp":{far}}}"#),
    );
    assert_eq!(st, 500, "{body}");
    assert!(body.contains("not recorded on disk"), "{body}");
    drop(run2);

    // A list that cannot be read stops the boot instead of starting with nothing revoked.
    let status = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", &cfg)
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_TEST_ADMIN_WRITE_TOKEN", TOKEN)
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(dir.join("run3.log")).unwrap())
        .status()
        .expect("spawn zion");
    assert_eq!(
        status.code(),
        Some(2),
        "an unreadable revocation list is a config error"
    );
    let log = fs::read_to_string(dir.join("run3.log")).unwrap();
    assert!(log.contains("cannot load the revocation list"), "{log}");
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
    tls_get(port, "/admin/config", cert, key)
}

/// GET `path` over TLS with a client certificate; the status, 0 when the handshake is refused.
fn tls_get(port: u16, path: &str, cert: &std::path::Path, key: &std::path::Path) -> u16 {
    tls_get_body(port, path, cert, key).0
}

/// Like [`tls_get`], with the response body as well.
fn tls_get_body(
    port: u16,
    path: &str,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> (u16, String) {
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
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .ok(); // a refused handshake closes the pipe before the request is written
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, text)
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

/// A CA that can sign CRLs, two client certificates (`good`, `bad`), a CRL that revokes
/// nothing (`crl-empty.pem`), one that revokes `bad` (`crl.pem`) and the same one valid for a
/// second only (`crl-expired.pem`), all in `dir`.
fn pki_with_crl(dir: &std::path::Path) -> bool {
    let d = dir.to_string_lossy();
    let p = |f: &str| dir.join(f).to_string_lossy().into_owned();
    fs::write(
        dir.join("ca.cnf"),
        format!(
            "[ca]\ndefault_ca = CA_default\n[CA_default]\ndatabase = {d}/index.txt\n\
             crlnumber = {d}/crlnumber\nserial = {d}/serial\nnew_certs_dir = {d}\n\
             default_md = sha256\ndefault_crl_days = 1\ndefault_days = 1\npolicy = policy_any\n\
             unique_subject = no\ncopy_extensions = none\n[policy_any]\ncommonName = supplied\n\
             [client_ext]\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature\n\
             extendedKeyUsage = clientAuth\n"
        ),
    )
    .unwrap();
    fs::write(dir.join("index.txt"), "").unwrap();
    fs::write(dir.join("crlnumber"), "1000\n").unwrap();
    fs::write(dir.join("serial"), "01\n").unwrap();
    let ca = |args: &[&str]| {
        let mut all = vec![
            "ca".to_string(),
            "-batch".into(),
            "-config".into(),
            p("ca.cnf"),
            "-cert".into(),
            p("ca.pem"),
            "-keyfile".into(),
            p("ca.key"),
        ];
        all.extend(args.iter().map(|a| a.to_string()));
        openssl(&all.iter().map(String::as_str).collect::<Vec<_>>())
    };
    // The CA must be allowed to sign CRLs, or the verifier refuses the list.
    let ca_ok = openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=crl-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        &p("ca.key"),
        "-out",
        &p("ca.pem"),
    ]);
    let client = |name: &str| {
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            &format!("/CN={name}"),
            "-keyout",
            &p(&format!("{name}.key")),
            "-out",
            &p(&format!("{name}.csr")),
        ]) && ca(&[
            "-in",
            &p(&format!("{name}.csr")),
            "-out",
            &p(&format!("{name}.pem")),
            "-extensions",
            "client_ext",
            "-notext",
        ])
    };
    ca_ok
        && client("good")
        && client("bad")
        && ca(&["-gencrl", "-out", &p("crl-empty.pem")])
        && ca(&["-revoke", &p("bad.pem")])
        && ca(&["-gencrl", "-out", &p("crl.pem")])
        // The same list, but valid for one second only: expired by the time it is used.
        && ca(&["-gencrl", "-crlsec", "1", "-out", &p("crl-expired.pem")])
}

/// A certificate on the CRL is refused at the handshake, on the data plane and on the admin
/// API, and publishing a new CRL takes effect without a restart: before this, a leaked client
/// certificate (an admin one included) stayed valid until it expired or the CA was replaced
/// (ZION-AUTH-02).
#[test]
fn a_revoked_client_certificate_is_refused_and_a_new_crl_needs_no_restart() {
    let dir = std::env::temp_dir().join(format!("zion-crl-{}-{}", std::process::id(), free_port()));
    // The server certificate lives in a directory of its own: the certificate watcher
    // covers that one, and must also cover wherever the CA and the CRL are.
    fs::create_dir_all(dir.join("server")).unwrap();
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
        &dir.join("server/k.pem").to_string_lossy(),
        "-out",
        &dir.join("server/c.pem").to_string_lossy(),
    ]);
    if !(server_ok && pki_with_crl(&dir)) {
        eprintln!("SKIP: openssl could not make the test certificates");
        return;
    }
    // The CRL the daemon reads: it starts with nothing revoked. It lives in a directory of
    // its own, so the reload below proves that directory is watched, not just the
    // certificate's.
    let live = dir.join("published");
    fs::create_dir_all(&live).unwrap();
    fs::copy(dir.join("crl-empty.pem"), live.join("crl.pem")).unwrap();
    let d = dir.to_string_lossy();
    let (https_port, admin_port) = (free_port(), free_port());
    let cfg = format!(
        "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
         [tls]\ncert_path = \"{d}/server/c.pem\"\nkey_path = \"{d}/server/k.pem\"\n\
         client_auth = \"required\"\nclient_ca_path = \"{d}/ca.pem\"\n\
         client_crl_path = \"{d}/published/crl.pem\"\n\n\
         [upstreams]\nbackend = \"http://127.0.0.1:9\"\n\n\
         [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n\n\
         [admin]\nlisten = \"127.0.0.1:{admin_port}\"\nauth = \"mtls\"\n\
         client_ca_path = \"{d}/ca.pem\"\nclient_crl_path = \"{d}/published/crl.pem\"\n\
         rate_limit_rps = 1000\n",
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
    let log = || fs::read_to_string(dir.join("daemon.log")).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", admin_port)).is_err()
        || TcpStream::connect(("127.0.0.1", https_port)).is_err()
    {
        assert!(
            Instant::now() < deadline,
            "the daemon never came up: {}",
            log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let data = |who: &str| {
        tls_get(
            https_port,
            "/healthz",
            &dir.join(format!("{who}.pem")),
            &dir.join(format!("{who}.key")),
        )
    };
    let admin = |who: &str| {
        mtls_get(
            admin_port,
            &dir.join(format!("{who}.pem")),
            &dir.join(format!("{who}.key")),
        )
    };
    // Nothing revoked yet: both certificates open both listeners.
    assert_eq!((data("good"), admin("good")), (200, 200), "{}", log());
    assert_eq!((data("bad"), admin("bad")), (200, 200), "not revoked yet");
    // Publish the CRL that revokes `bad` (write + rename, as a deploy would).
    fs::copy(dir.join("crl.pem"), live.join("crl.tmp")).unwrap();
    fs::rename(live.join("crl.tmp"), live.join("crl.pem")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while (data("bad"), admin("bad")) != (0, 0) {
        assert!(
            Instant::now() < deadline,
            "the revoked certificate still opens a listener (data {}, admin {}): {}",
            data("bad"),
            admin("bad"),
            log()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(
        (data("good"), admin("good")),
        (200, 200),
        "a certificate that is not on the CRL keeps working"
    );
    let _ = fs::remove_dir_all(dir);
}

/// A daemon with the data plane and the admin API both requiring a client certificate and both
/// reading `published/crl.pem`, which starts as `crl-expired.pem`: a list whose `nextUpdate` is
/// in the past. `enforce` sets `client_crl_enforce_next_update` on both.
struct CrlDaemon {
    dir: std::path::PathBuf,
    https_port: u16,
    admin_port: u16,
    _daemon: Daemon,
}

impl CrlDaemon {
    fn boot(enforce: bool) -> Option<Self> {
        let dir = std::env::temp_dir().join(format!(
            "zion-crl-expiry-{}-{}",
            std::process::id(),
            free_port()
        ));
        fs::create_dir_all(dir.join("server")).unwrap();
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
            &dir.join("server/k.pem").to_string_lossy(),
            "-out",
            &dir.join("server/c.pem").to_string_lossy(),
        ]);
        if !(server_ok && pki_with_crl(&dir)) {
            eprintln!("SKIP: openssl could not make the test certificates");
            return None;
        }
        fs::create_dir_all(dir.join("published")).unwrap();
        fs::copy(dir.join("crl-expired.pem"), dir.join("published/crl.pem")).unwrap();
        // `-crlsec 1`: make sure the second is over before anything reads the list.
        std::thread::sleep(Duration::from_millis(2200));
        let d = dir.to_string_lossy();
        let (https_port, admin_port) = (free_port(), free_port());
        let enforce = format!("client_crl_enforce_next_update = {enforce}\n");
        let cfg = format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
             [tls]\ncert_path = \"{d}/server/c.pem\"\nkey_path = \"{d}/server/k.pem\"\n\
             client_auth = \"required\"\nclient_ca_path = \"{d}/ca.pem\"\n\
             client_crl_path = \"{d}/published/crl.pem\"\n{enforce}\n\
             [upstreams]\nbackend = \"http://127.0.0.1:9\"\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n\n\
             [admin]\nlisten = \"127.0.0.1:{admin_port}\"\nauth = \"mtls\"\n\
             client_ca_path = \"{d}/ca.pem\"\nclient_crl_path = \"{d}/published/crl.pem\"\n\
             {enforce}rate_limit_rps = 1000\n",
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
        let me = Self {
            dir,
            https_port,
            admin_port,
            _daemon: Daemon(child),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(("127.0.0.1", admin_port)).is_err()
            || TcpStream::connect(("127.0.0.1", https_port)).is_err()
        {
            assert!(
                Instant::now() < deadline,
                "the daemon never came up: {}",
                me.log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        Some(me)
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.join("daemon.log")).unwrap_or_default()
    }

    /// (data plane, admin API) status for the client certificate `who`; 0 = refused.
    fn statuses(&self, who: &str) -> (u16, u16) {
        let (cert, key) = (
            self.dir.join(format!("{who}.pem")),
            self.dir.join(format!("{who}.key")),
        );
        (
            tls_get(self.https_port, "/healthz", &cert, &key),
            mtls_get(self.admin_port, &cert, &key),
        )
    }

    /// The `nextUpdate` gauge of each listener, `(tls, admin)`, as `/metrics` shows it. The
    /// data plane serves it to `good`, so a refused `good` shows as `None`.
    fn gauges(&self) -> (Option<u64>, Option<u64>) {
        let (_, body) = tls_get_body(
            self.https_port,
            "/metrics",
            &self.dir.join("good.pem"),
            &self.dir.join("good.key"),
        );
        let gauge = |listener: &str| {
            body.lines()
                .find(|l| {
                    l.starts_with(&format!(
                        "zion_tls_client_crl_next_update_timestamp_seconds{{listener=\"{listener}\"}}"
                    ))
                })
                .and_then(|l| l.split_whitespace().last())
                .and_then(|v| v.parse().ok())
        };
        (gauge("tls"), gauge("admin"))
    }

    /// Replace the published CRL, as a deploy would (write, then rename).
    fn publish(&self, file: &str) {
        fs::copy(self.dir.join(file), self.dir.join("published/crl.tmp")).unwrap();
        fs::rename(
            self.dir.join("published/crl.tmp"),
            self.dir.join("published/crl.pem"),
        )
        .unwrap();
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A CRL whose `nextUpdate` has passed keeps being applied by default (#601): the certificate it
/// lists is still refused and the others still admitted, because failing closed would lock every
/// client out, the admin API included, the day whoever publishes the list stops. What changes is
/// that it is no longer silent: a gauge with the `nextUpdate` per listener for the alert, a
/// warning at load, and the gauge follows a reload that replaces the list.
#[test]
fn an_expired_crl_still_applies_and_is_reported() {
    let Some(z) = CrlDaemon::boot(false) else {
        return;
    };
    assert_eq!(z.statuses("good"), (200, 200), "{}", z.log());
    assert_eq!(
        z.statuses("bad"),
        (0, 0),
        "the expired list still refuses what it lists"
    );

    let log = z.log();
    let line = log
        .lines()
        .find(|l| l.contains("published/crl.pem") && l.contains("expired"))
        .unwrap_or_else(|| panic!("no warning about the expired list:\n{log}"));
    assert!(line.contains("WARN"), "{line}");
    assert!(
        line.contains("client_crl_enforce_next_update"),
        "the warning says how to refuse instead: {line}"
    );
    assert!(
        !log.contains("BEGIN X509 CRL"),
        "the list itself is never logged"
    );

    let (tls, admin) = z.gauges();
    let (tls, admin) = (tls.expect("tls gauge"), admin.expect("admin gauge"));
    assert_eq!(tls, admin, "one file, one nextUpdate");
    let now = now_secs();
    assert!(
        tls < now && tls > now - 3600,
        "nextUpdate {tls} should be a few seconds ago ({now})"
    );

    // A list valid for a day replaces it: the gauge follows, still without a restart.
    z.publish("crl.pem");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (tls, admin) = z.gauges();
        if tls.is_some_and(|t| t > now_secs()) && admin.is_some_and(|t| t > now_secs()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the gauge did not follow the reload ({tls:?}, {admin:?}): {}",
            z.log()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(z.statuses("good"), (200, 200));
    assert_eq!(z.statuses("bad"), (0, 0));
    let _ = fs::remove_dir_all(&z.dir);
}

/// With `client_crl_enforce_next_update = true` an out-of-date list refuses every client, the
/// ones it does not list included, until it is replaced: a strict deployment chooses that
/// knowingly.
#[test]
fn an_expired_crl_refuses_every_client_when_asked_to() {
    let Some(z) = CrlDaemon::boot(true) else {
        return;
    };
    assert_eq!(z.statuses("good"), (0, 0), "{}", z.log());
    assert_eq!(z.statuses("bad"), (0, 0));
    assert!(
        z.log()
            .lines()
            .any(|l| l.contains("expired") && l.contains("refused")),
        "the warning says clients are being refused:\n{}",
        z.log()
    );
    z.publish("crl.pem");
    let deadline = Instant::now() + Duration::from_secs(20);
    while z.statuses("good") != (200, 200) {
        assert!(
            Instant::now() < deadline,
            "a fresh list did not bring the good certificate back: {}",
            z.log()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(z.statuses("bad"), (0, 0));
    let _ = fs::remove_dir_all(&z.dir);
}
