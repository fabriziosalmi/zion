// SPDX-License-Identifier: Apache-2.0
//! The spellings of a header name or value that an upstream reads as the same thing get the same
//! answer from zion, against the real binary:
//!
//! - A byte outside ASCII (obs-text, which hyper and h2 accept) elsewhere in a `Cookie` or
//!   `Content-Type` field does not let `deny_cookies` or a virtual-patch `cookies` /
//!   `content_types` rule skip the field, over HTTP/1.1 and HTTP/2.
//! - A cookie name PHP files under a denied name (`XDEBUG.SESSION` is
//!   `$_COOKIE['XDEBUG_SESSION']`, and `XDEBUG%2ESESSION` is too to a PHP that url-decodes
//!   cookie names) is refused like that name. A rule that names an array element
//!   (`name[#post_render][]`) does not refuse the plain `name`.
//! - Whitespace at the start or end of a header value, which h2 keeps and an HTTP/1.1 upstream
//!   drops, does not hide a `content_types` or `headers` value from a rule over HTTP/2 (a
//!   hyper client: curl drops the whitespace itself).
//! - The underscore spelling of a reserved header (`X_Client_Cert_Fingerprint`) or of a
//!   forwarding header zion sets (`X_Real_IP`) never reaches the upstream: an upstream that names
//!   headers the CGI way (RFC 3875; Python's `wsgiref` is one) folds `_` and `-` into one
//!   `HTTP_X_CLIENT_CERT_FINGERPRINT` variable, and would read the client's value as the one zion
//!   attests. Shown against a recording origin and against `wsgiref`.
//!
//! Each case is paired with a control that must already get the answer (the plain ASCII cookie,
//! the dashed header name), so the controls prove the configuration is active and only the
//! spelling makes the difference. The TLS client is `openssl s_client` (it sends the bytes as
//! written) with no client certificate, against `[tls] client_auth = "optional"`; HTTP/2 is
//! `curl --http2`.
//!
//! Unix only, skipped when `openssl` (or, for the `wsgiref` test, `python3`) is not installed.
#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn openssl(args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A scratch directory holding a server certificate and a client CA (so
/// `client_auth = "optional"` can be configured), or None when openssl cannot make them.
fn pki(tag: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "zion-header-spellings-{tag}-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_string_lossy().into_owned();
    let made = openssl(&[
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
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-keyout",
        &p("k.pem"),
        "-out",
        &p("c.pem"),
    ]) && openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=test-client-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        &p("ca.key"),
        "-out",
        &p("ca.pem"),
    ]);
    if made {
        Some(dir)
    } else {
        let _ = fs::remove_dir_all(&dir);
        None
    }
}

const RULES: &str = r#"
[[rule]]
id = "vp-cookie"
cve = "CVE-2099-0001"
action = "deny"
cookies = ["wp_evil"]

[[rule]]
id = "vp-multipart"
cve = "CVE-2099-0002"
action = "deny"
methods = ["POST"]
path_glob = "/upload*"
content_types = ["multipart/form-data"]

[[rule]]
id = "vp-header"
cve = "CVE-2099-0003"
action = "deny"
[[rule.headers]]
name = "x-mode"
equals = "debug"

[[rule]]
id = "vp-element"
cve = "CVE-2099-0004"
action = "deny"
[[rule.query]]
name = "name[#post_render][]"
"#;

/// Boot zion in front of `origin_port` with `deny_cookies`, the virtual-patch [`RULES`] and
/// optional mTLS; returns the HTTPS port.
fn start(dir: &Path, origin_port: u16) -> (Proc, u16) {
    let https_port = free_port();
    let p = |f: &str| dir.join(f).to_string_lossy().into_owned();
    fs::write(dir.join("virtual-patch.toml"), RULES).unwrap();
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\
             deny_cookies = [\"CacheWarmer\", \"XDEBUG_SESSION\"]\n\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\
             client_auth = \"optional\"\nclient_ca_path = \"{}\"\n\n\
             [virtual_patch]\nrules_file = \"{}\"\n\n\
             [upstreams]\nbackend = \"http://127.0.0.1:{origin_port}\"\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\nmode = \"standard\"\n",
            free_port(),
            p("c.pem"),
            p("k.pem"),
            p("ca.pem"),
            p("virtual-patch.toml"),
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", dir.join("zion.toml"))
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(dir.join("daemon.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let z = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https_port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "zion never listened:\n{}",
            fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(300));
    (z, https_port)
}

/// An origin that answers every request with `ok` and remembers the raw head of each one.
fn origin() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                // drain a Content-Length body so zion is never cut off mid-write
                let lower = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let len = lower
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                let _ = s.read_exact(&mut body);
                log.lock().unwrap().push(head);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            });
        }
    });
    (port, seen)
}

/// The head the origin received for a request to `path`, escaped, or None after a short wait.
fn forwarded(seen: &Mutex<Vec<Vec<u8>>>, path: &str) -> Option<String> {
    let want = format!(" {path} ").into_bytes();
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let hit = seen
            .lock()
            .unwrap()
            .iter()
            .find(|h| {
                let line_end = h.iter().position(|&b| b == b'\r').unwrap_or(h.len());
                h[..line_end]
                    .windows(want.len())
                    .any(|w| w == want.as_slice())
            })
            .map(|h| h.escape_ascii().to_string());
        if hit.is_some() || Instant::now() > deadline {
            return hit;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Send `raw` over TLS (ALPN http/1.1, no client certificate) and return the whole answer.
fn exchange(port: u16, raw: &[u8]) -> String {
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-quiet",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-alpn",
            "http/1.1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl s_client");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(raw).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.read_to_end(&mut buf);
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
    });
    let answer = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(a) => a,
        Err(_) => {
            let _ = child.kill();
            rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default()
        }
    };
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    answer
}

/// The status line of the answer to `raw`.
fn status_line(port: u16, raw: &[u8]) -> String {
    exchange(port, raw)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// `GET path` over HTTP/2 with curl, one extra header given as raw bytes. Returns
/// `"<status> h<version>"`, or an empty string when curl is missing.
fn h2_status(port: u16, path: &str, header: &[u8]) -> String {
    let out = Command::new("curl")
        .args([
            "-sk",
            "--http2",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} h%{http_version}",
            "--max-time",
            "8",
            "-H",
        ])
        .arg(OsStr::from_bytes(header))
        .arg(format!("https://127.0.0.1:{port}{path}"))
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

/// `(path, raw request, the status line it must get)`, each sent and checked; returns what got
/// another answer, with what the origin saw.
fn check_all(port: u16, seen: &Mutex<Vec<Vec<u8>>>, cases: &[(&str, &[u8], &str)]) -> Vec<String> {
    let mut wrong = Vec::new();
    for (path, raw, want) in cases {
        let line = status_line(port, raw);
        if !line.starts_with(want) {
            wrong.push(format!(
                "{path}: expected {want:?}, got {line:?}; origin saw: {}",
                forwarded(seen, path).unwrap_or_else(|| "<nothing>".into())
            ));
        }
    }
    wrong
}

#[test]
fn a_high_byte_in_the_field_does_not_let_a_denied_cookie_or_content_type_through() {
    let Some(dir) = pki("obs-text") else {
        common::skip("openssl could not make the certificates");
        return;
    };
    let (origin_port, seen) = origin();
    let (_z, port) = start(&dir, origin_port);

    // The route works.
    let ok = status_line(
        port,
        b"GET /ok HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    );
    assert!(ok.starts_with("HTTP/1.1 200"), "baseline: {ok:?}");

    // Controls: the pure-ASCII form of each attack is refused (the configuration is active).
    let controls: [(&str, &[u8], &str); 3] = [
        (
            "/c1",
            b"GET /c1 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: a=1; CacheWarmer=O:8:\"stdClass\":0:{}\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/c2",
            b"GET /c2 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: a=1; wp_evil=1\r\n\r\n",
            "HTTP/1.1 403",
        ),
        (
            "/upload-c3",
            b"POST /upload-c3 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Content-Type: multipart/form-data; boundary=B\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 403",
        ),
    ];
    let wrong = check_all(port, &seen, &controls);
    assert!(wrong.is_empty(), "controls: {wrong:#?}");

    // The same requests with one byte >= 0x80 earlier in the same field.
    let attacks: [(&str, &[u8], &str); 3] = [
        (
            "/b1",
            b"GET /b1 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: a=\x80; CacheWarmer=O:8:\"stdClass\":0:{}\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/b2",
            b"GET /b2 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: a=\x80; wp_evil=1\r\n\r\n",
            "HTTP/1.1 403",
        ),
        (
            "/upload-b3",
            b"POST /upload-b3 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Content-Type: multipart/form-data; x=\xff; boundary=B\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 403",
        ),
    ];
    let mut bypassed = check_all(port, &seen, &attacks);

    // HTTP/2 (curl), one cookie field: control then the high-byte variant.
    let h2_control = h2_status(port, "/h2c", b"cookie: a=1; CacheWarmer=x");
    if h2_control.is_empty() || !h2_control.ends_with("h2") {
        common::skip(&format!(
            "the HTTP/2 case needs curl with HTTP/2; curl answered {h2_control:?}"
        ));
    } else {
        assert!(h2_control.starts_with("400"), "h2 control: {h2_control:?}");
        let h2_attack = h2_status(port, "/h2b", b"cookie: a=\x80; CacheWarmer=x");
        if !h2_attack.starts_with("400") {
            bypassed.push(format!(
                "/h2b (HTTP/2): expected \"400 h2\", got {h2_attack:?}; origin saw: {}",
                forwarded(&seen, "/h2b").unwrap_or_else(|| "<nothing>".into())
            ));
        }
    }

    let _ = fs::remove_dir_all(&dir);
    assert!(
        bypassed.is_empty(),
        "{} of the high-byte requests got past the control that refused their ASCII form:\n  {}",
        bypassed.len(),
        bypassed.join("\n  ")
    );
}

#[test]
fn a_cookie_name_php_reads_as_a_denied_one_is_refused() {
    let Some(dir) = pki("php-cookie") else {
        common::skip("openssl could not make the certificates");
        return;
    };
    let (origin_port, seen) = origin();
    let (_z, port) = start(&dir, origin_port);

    let controls: [(&str, &[u8], &str); 3] = [
        (
            "/d0",
            b"GET /d0 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: XDEBUG_SESSION=1\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/v0",
            b"GET /v0 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: wp_evil=1\r\n\r\n",
            "HTTP/1.1 403",
        ),
        // A cookie PHP keeps apart from the denied one is forwarded.
        (
            "/n0",
            b"GET /n0 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: XDEBUG-SESSION=1; wp-evil=1\r\n\r\n",
            "HTTP/1.1 200",
        ),
    ];
    let wrong = check_all(port, &seen, &controls);
    assert!(wrong.is_empty(), "controls: {wrong:#?}");

    // `$_COOKIE['XDEBUG_SESSION']` and `$_COOKIE['wp_evil']` to PHP.
    let attacks: [(&str, &[u8], &str); 5] = [
        (
            "/d1",
            b"GET /d1 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: XDEBUG.SESSION=1\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/d2",
            b"GET /d2 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: a=1; XDEBUG SESSION=1\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/d3",
            b"GET /d3 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: XDEBUG[SESSION=1\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/v1",
            b"GET /v1 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: wp.evil=1\r\n\r\n",
            "HTTP/1.1 403",
        ),
        (
            "/v2",
            b"GET /v2 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: wp_evil[x]=1\r\n\r\n",
            "HTTP/1.1 403",
        ),
    ];
    let mut bypassed = check_all(port, &seen, &attacks);

    // `$_COOKIE['CacheWarmer']`, `$_COOKIE['XDEBUG_SESSION']` and `$_COOKIE['wp_evil']` to a PHP
    // before 7.2.34, 7.3.23 and 7.4.11 (the lab's WordPress image runs PHP 7.0), which
    // url-decoded a cookie name before it made it a key.
    let decoded: [(&str, &[u8], &str); 6] = [
        (
            "/o1",
            b"GET /o1 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: %20CacheWarmer=O:8:\"stdClass\":0:{}\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/o2",
            b"GET /o2 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: a=1; CacheWarmer%00x=O:8:\"stdClass\":0:{}\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/o3",
            b"GET /o3 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: XDEBUG%2ESESSION=1\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/o4",
            b"GET /o4 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: XDEBUG+SESSION=1\r\n\r\n",
            "HTTP/1.1 400",
        ),
        (
            "/o5",
            b"GET /o5 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: wp%5Fevil=1\r\n\r\n",
            "HTTP/1.1 403",
        ),
        (
            "/o6",
            b"GET /o6 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
              Cookie: a=1; wp+evil=1\r\n\r\n",
            "HTTP/1.1 403",
        ),
    ];
    bypassed.extend(check_all(port, &seen, &decoded));
    // A name that decodes to something else is forwarded.
    let kept: [(&str, &[u8], &str); 1] = [(
        "/o0",
        b"GET /o0 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
          Cookie: XDEBUG%2DSESSION=1; CacheWarmerX%00=1; wp_evil+=1\r\n\r\n",
        "HTTP/1.1 200",
    )];
    let wrong = check_all(port, &seen, &kept);
    let _ = fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert!(
        bypassed.is_empty(),
        "{} of the cookie names PHP reads as a denied one got through:\n  {}",
        bypassed.len(),
        bypassed.join("\n  ")
    );
}

/// A rule that names an array element (`name[#post_render][]`) blocks that element, and leaves a
/// request that only carries the plain `name` alone.
#[test]
fn a_rule_naming_an_array_element_does_not_block_the_plain_name() {
    let Some(dir) = pki("php-element") else {
        common::skip("openssl could not make the certificates");
        return;
    };
    let (origin_port, _seen) = origin();
    let (_z, port) = start(&dir, origin_port);
    let cases: [(&str, &[u8], &str); 5] = [
        (
            "/e1",
            b"GET /e1?name[%23post_render][]=passthru HTTP/1.1\r\nHost: a.example\r\n\
              Connection: close\r\n\r\n",
            "HTTP/1.1 403",
        ),
        (
            "/e2",
            b"GET /e2?+name[%23post_render][]=passthru HTTP/1.1\r\nHost: a.example\r\n\
              Connection: close\r\n\r\n",
            "HTTP/1.1 403",
        ),
        (
            "/e3",
            b"GET /e3?name=bob HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200",
        ),
        (
            "/e4",
            b"GET /e4?name[]=bob HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200",
        ),
        (
            "/e5",
            b"GET /e5?name[x]=bob&name.y=1 HTTP/1.1\r\nHost: a.example\r\n\
              Connection: close\r\n\r\n",
            "HTTP/1.1 200",
        ),
    ];
    // `forwarded` matches the request line on " {path} ", which a query string hides.
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(path, raw, want)| {
            let line = status_line(port, raw);
            (!line.starts_with(want)).then(|| format!("{path}: expected {want:?}, got {line:?}"))
        })
        .collect();
    let _ = fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// `method path` over HTTP/2 (TLS, ALPN `h2`, no client certificate) with one header whose value
/// is sent exactly as given, and the status code. curl cannot be used here: it drops the
/// whitespace at the start of a header value, and h2 keeps it.
fn h2_raw_status(port: u16, method: &str, path: &str, name: &str, value: &[u8]) -> u16 {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tls),
        )
        .await
        .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .method(method)
            .uri(format!("https://localhost:{port}{path}"))
            .header(
                name,
                hyper::header::HeaderValue::from_bytes(value).expect("h2 accepts it"),
            )
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(8), send.send_request(req))
            .await
            .expect("an answer within 8 s")
            .expect("an HTTP/2 answer")
            .status()
            .as_u16()
    })
}

/// h2 (and h3) keep whitespace at the start or end of a field value, which an HTTP/1.1 parser
/// drops; zion forwards the value as it came, and the HTTP/1.1 upstream reads
/// `\tmultipart/form-data` as a multipart body. A `content_types` or `headers` rule must match it
/// over HTTP/2 the way it matches the plain value.
#[test]
fn whitespace_around_an_h2_value_does_not_hide_it_from_a_rule() {
    let Some(dir) = pki("h2-ows") else {
        common::skip("openssl could not make the certificates");
        return;
    };
    let (origin_port, seen) = origin();
    let (_z, port) = start(&dir, origin_port);
    let ct = "content-type";
    // Controls: the plain value is refused, and a value no rule names is forwarded.
    let controls = [
        (
            "/upload-w0",
            ct,
            &b"multipart/form-data; boundary=B"[..],
            403,
        ),
        ("/x-w0", "x-mode", b"debug", 403),
        ("/upload-w1", ct, b"\ttext/plain", 200),
        ("/x-w1", "x-mode", b" release", 200),
    ];
    let attacks = [
        (
            "/upload-w2",
            ct,
            &b"\tmultipart/form-data; boundary=B"[..],
            403,
        ),
        ("/upload-w3", ct, b" multipart/form-data; boundary=B", 403),
        ("/x-w2", "x-mode", b"\tdebug", 403),
        ("/x-w3", "x-mode", b"debug ", 403),
    ];
    let run = |cases: &[(&str, &str, &[u8], u16)]| -> Vec<String> {
        cases
            .iter()
            .filter_map(|(path, name, value, want)| {
                let method = if path.starts_with("/upload") {
                    "POST"
                } else {
                    "GET"
                };
                let got = h2_raw_status(port, method, path, name, value);
                (got != *want).then(|| {
                    format!(
                        "{method} {path} {name}: {:?}: expected {want}, got {got}; origin saw: {}",
                        value.escape_ascii().to_string(),
                        forwarded(&seen, path).unwrap_or_else(|| "<nothing>".into())
                    )
                })
            })
            .collect()
    };
    let wrong = run(&controls);
    assert!(wrong.is_empty(), "controls: {wrong:#?}");
    let bypassed = run(&attacks);
    let _ = fs::remove_dir_all(&dir);
    assert!(
        bypassed.is_empty(),
        "{} of the values with whitespace around them got past the rule over HTTP/2:\n  {}",
        bypassed.len(),
        bypassed.join("\n  ")
    );
}

/// The underscore spelling of every reserved header that has a `-` in its name, and of every
/// forwarding header zion sets, in the mixed case a client would send
/// (`x-client-cert-fingerprint` is sent as `X_Client_Cert_Fingerprint`).
fn underscore_spellings() -> Vec<(&'static str, String)> {
    zion::reserved_headers::RESERVED_HEADERS
        .iter()
        .map(|(name, _)| *name)
        .chain(zion::reserved_headers::FORWARDING_HEADERS)
        .filter(|name| name.contains('-'))
        .map(|name| {
            let alias = name
                .split('-')
                .map(|w| {
                    let mut c = w.chars();
                    c.next()
                        .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join("_");
            (name, alias)
        })
        .collect()
}

#[test]
fn no_underscore_spelling_of_a_reserved_or_forwarding_header_reaches_the_upstream() {
    let Some(dir) = pki("underscore") else {
        common::skip("openssl could not make the certificates");
        return;
    };
    let (origin_port, seen) = origin();
    let (_z, port) = start(&dir, origin_port);
    let head_of = |path: &str| -> String {
        let head = forwarded(&seen, path).unwrap_or_else(|| panic!("the origin never saw {path}"));
        head.to_ascii_lowercase()
    };

    // Control: the dashed spelling is scrubbed (the scrub works for the exact name).
    let mut raw = String::from("GET /dash HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n");
    for (name, _) in zion::reserved_headers::RESERVED_HEADERS {
        raw.push_str(&format!("{name}: forged-by-client\r\n"));
    }
    raw.push_str("X-Control: kept\r\n\r\n");
    let line = status_line(port, raw.as_bytes());
    assert!(line.starts_with("HTTP/1.1 200"), "{line:?}");
    let dash = head_of("/dash");
    assert!(dash.contains("x-control: kept"), "{dash}");
    assert!(
        !dash.contains("forged-by-client"),
        "a dashed reserved header reached the origin:\n{dash}"
    );

    // The same headers spelled with `_`, and no dashed copy at all.
    let spellings = underscore_spellings();
    let mut raw =
        String::from("GET /underscore HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n");
    for (_, alias) in &spellings {
        raw.push_str(&format!("{alias}: forged-by-client\r\n"));
    }
    raw.push_str("X_Control: kept\r\n\r\n");
    let line = status_line(port, raw.as_bytes());
    assert!(line.starts_with("HTTP/1.1 200"), "{line:?}");
    let under = head_of("/underscore");
    assert!(
        under.contains("x_control: kept"),
        "an unrelated underscore header must still reach the origin:\n{under}"
    );
    let leaked: Vec<String> = spellings
        .iter()
        .filter(|(_, alias)| {
            under.contains(&format!("{}: forged-by-client", alias.to_ascii_lowercase()))
        })
        .map(|(name, alias)| format!("{alias} ({name})"))
        .collect();
    let _ = fs::remove_dir_all(&dir);
    assert!(
        leaked.is_empty() && !under.contains("forged-by-client"),
        "{} of {} underscore spellings reached the origin: {leaked:#?}\n{under}",
        leaked.len(),
        spellings.len()
    );
}

/// End to end against a real folding upstream (Python's `wsgiref`): a client with no certificate
/// sends `X_Client_Cert_Fingerprint` and `X_Real_IP`, and the WSGI application must read neither
/// as `HTTP_X_CLIENT_CERT_FINGERPRINT` or `HTTP_X_REAL_IP`.
#[test]
fn a_wsgi_upstream_reads_no_forged_value_from_an_underscore_spelling() {
    let has_python = Command::new("python3")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !has_python {
        common::skip("python3 is not installed");
        return;
    }
    let Some(dir) = pki("wsgi") else {
        common::skip("openssl could not make the certificates");
        return;
    };
    let app = "\
import sys
from wsgiref.simple_server import make_server, WSGIRequestHandler
class Quiet(WSGIRequestHandler):
    def log_message(self, *a): pass
def app(environ, start_response):
    fp = environ.get('HTTP_X_CLIENT_CERT_FINGERPRINT', '<absent>')
    ip = environ.get('HTTP_X_REAL_IP', '<absent>')
    body = ('fingerprint=' + fp + '\\nreal_ip=' + ip + '\\n').encode()
    start_response('200 OK', [('Content-Type', 'text/plain'), ('Content-Length', str(len(body)))])
    return [body]
make_server('127.0.0.1', int(sys.argv[1]), app, handler_class=Quiet).serve_forever()
";
    let origin_port = free_port();
    let _py = Proc(
        Command::new("python3")
            .args(["-I", "-c", app, &origin_port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn python3"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", origin_port)).is_err() {
        assert!(Instant::now() < deadline, "wsgiref never listened");
        std::thread::sleep(Duration::from_millis(50));
    }
    let (_z, port) = start(&dir, origin_port);
    let forged = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    // wsgiref answers HTTP/1.0 and zion relays that version: check the status code only.
    let served = |answer: &str| {
        answer
            .lines()
            .next()
            .is_some_and(|l| l.starts_with("HTTP/1.") && l.contains(" 200 "))
    };

    // Control: the dashed spelling is scrubbed, the application sees no fingerprint and zion's
    // own X-Real-IP.
    let answer = exchange(
        port,
        format!(
            "GET /dash HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
             X-Client-Cert-Fingerprint: {forged}\r\nX-Real-IP: 203.0.113.66\r\n\r\n"
        )
        .as_bytes(),
    );
    assert!(served(&answer), "{answer:?}");
    assert!(answer.contains("fingerprint=<absent>"), "{answer}");
    assert!(answer.contains("real_ip=127.0.0.1\n"), "{answer}");

    // No certificate, the underscore spellings only.
    let answer = exchange(
        port,
        format!(
            "GET /underscore HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
             X_Client_Cert_Fingerprint: {forged}\r\nX_Real_IP: 203.0.113.66\r\n\r\n"
        )
        .as_bytes(),
    );
    let _ = fs::remove_dir_all(&dir);
    assert!(served(&answer), "{answer:?}");
    assert!(
        answer.contains("fingerprint=<absent>") && answer.contains("real_ip=127.0.0.1\n"),
        "a client with no certificate made the WSGI app read a forged value \
         (HTTP_X_CLIENT_CERT_FINGERPRINT or HTTP_X_REAL_IP):\n{answer}"
    );
}
