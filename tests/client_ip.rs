// SPDX-License-Identifier: Apache-2.0
//! The client IP behind a trusted proxy, against the real binary: what the internal-only gates
//! (`/metrics`, `/_zion/snapshot.json`, `POST /_zion/cache/purge`, `internal_only` routes) and
//! the upstream's `X-Real-IP` see.
//!
//! The test client connects from 127.0.0.1, listed in `trusted_proxies`, and plays the trusted
//! proxy: it forwards what a client wrote and adds the client it saw, 203.0.113.9 (public, so
//! never internal). Each of these used to let the client choose its own address:
//!
//! - an `X-Forwarded-For` split over two field lines (HAProxy `option forwardfor`): only the
//!   first line, the client's, was read;
//! - a byte that is not ASCII anywhere in the header: the whole header was dropped and the
//!   client resolved to the proxy itself, internal under the default rule;
//! - a proxy hop written as `ip:port`, `[ipv6]:port` or `unknown`: skipped, so the walk went on
//!   into the client's entries;
//! - a dual-stack `[::]` listener: an IPv4 peer arrived as `::ffff:127.0.0.1`, which no IPv4
//!   `trusted_proxies` entry matched.
//!
//! Controls: with no `X-Forwarded-For` the trusted loopback peer is itself the client, internal,
//! and gets `/metrics`; a single readable line resolves to 203.0.113.9.
//!
//! Unix only; `openssl` makes the certificate and is the TLS client (`s_client` sends the
//! bytes exactly as written), so the test is skipped without it.
#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

/// The client the trusted proxy saw: public, so never internal.
const REAL: &str = "203.0.113.9";

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

type Seen = Arc<Mutex<Vec<String>>>;

/// A keep-alive origin that records the head of every request (bytes that are not UTF-8
/// shown lossily) and answers `ok`.
fn origin() -> (u16, Seen) {
    let seen = Seen::default();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                let Ok(mut w) = s.try_clone() else { return };
                let mut r = BufReader::new(s);
                loop {
                    let mut head = String::new();
                    let mut content_length = 0usize;
                    loop {
                        let mut raw = Vec::new();
                        if r.read_until(b'\n', &mut raw).unwrap_or(0) == 0 {
                            return;
                        }
                        let line = String::from_utf8_lossy(&raw);
                        let line = line.trim_end();
                        if line.is_empty() {
                            if head.is_empty() {
                                continue;
                            }
                            break;
                        }
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                        head.push_str(line);
                        head.push('\n');
                    }
                    if content_length > 0 {
                        let mut body = vec![0u8; content_length];
                        let _ = r.read_exact(&mut body);
                    }
                    log.lock().unwrap().push(head);
                    if w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (port, seen)
}

/// Send `raw` over TLS (ALPN http/1.1) to 127.0.0.1; the status code of the answer (0: no
/// answer in 10 s).
fn send(port: u16, raw: &[u8]) -> u16 {
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
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(out).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx.recv_timeout(Duration::from_secs(10)).unwrap_or_default();
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// A self-signed certificate in `dir` (`c.pem` / `k.pem`); false without openssl.
fn certificate(dir: &Path) -> bool {
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout",
        &dir.join("k.pem").to_string_lossy(),
        "-out",
        &dir.join("c.pem").to_string_lossy(),
    ])
}

/// A running zion and its two ports (both reached at 127.0.0.1).
struct Zion {
    _proc: Proc,
    https: u16,
    http: u16,
}

/// Boot zion with HTTPS on `listen` (`127.0.0.1` or `[::]`) and plain HTTP on `127.0.0.1`,
/// `127.0.0.1` as the trusted proxy, an `internal_only` route under `/internal/` and a
/// catch-all to the origin.
fn start(dir: &Path, listen: &str, origin_port: u16) -> Zion {
    let (https, http) = (free_port(), free_port());
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"{listen}:{https}\"\n\
             trusted_proxies = [\"127.0.0.1/32\"]\n\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\n\
             [upstream.backend]\nurl = \"http://127.0.0.1:{origin_port}\"\n\n\
             [[route]]\npath = \"/internal/{{*rest}}\"\nupstream = \"backend\"\ninternal_only = true\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n",
            dir.join("c.pem").to_string_lossy(),
            dir.join("k.pem").to_string_lossy()
        ),
    )
    .unwrap();
    let log = dir.join(format!("daemon-{https}.log"));
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", dir.join("zion.toml"))
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .expect("spawn zion");
    let mut z = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https)).is_err()
        || TcpStream::connect(("127.0.0.1", http)).is_err()
    {
        let exited = z.0.try_wait().ok().flatten().is_some();
        assert!(
            !exited && Instant::now() < deadline,
            "zion (HTTPS on {listen}:{https}) did not come up:\n{}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Zion {
        _proc: z,
        https,
        http,
    }
}

/// Whether this host has a dual-stack `[::]` socket that takes IPv4 connections, checked
/// without zion (a platform without IPv6, or with v6only on, cannot run the dual-stack test).
fn dual_stack_available() -> bool {
    let Ok(l) = TcpListener::bind("[::]:0") else {
        return false;
    };
    let port = l.local_addr().unwrap().port();
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .is_ok()
}

/// Send `raw` in plaintext to 127.0.0.1; the status code of the answer (0: none in 10 s).
fn send_plain(port: u16, raw: &[u8]) -> u16 {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return 0;
    };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    if s.write_all(raw).is_err() {
        return 0;
    }
    let mut line = String::new();
    let _ = BufReader::new(s).read_line(&mut line);
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// A request with one `X-Forwarded-For` field line per entry of `xff`, in order, as bytes.
fn request(method: &str, path: &str, xff: &[&[u8]]) -> Vec<u8> {
    let mut s = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n")
        .into_bytes();
    for v in xff {
        s.extend_from_slice(b"X-Forwarded-For: ");
        s.extend_from_slice(v);
        s.extend_from_slice(b"\r\n");
    }
    if method == "POST" {
        s.extend_from_slice(b"Content-Length: 0\r\n");
    }
    s.extend_from_slice(b"\r\n");
    s
}

/// The values of header `name` in the head the origin recorded for `GET <path> `.
fn origin_header(seen: &Seen, path: &str, name: &str) -> Option<Vec<String>> {
    let start = format!("GET {path} ");
    let prefix = format!("{}:", name.to_ascii_lowercase());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(head) = seen.lock().unwrap().iter().find(|h| h.starts_with(&start)) {
            return Some(
                head.lines()
                    .filter(|l| l.to_ascii_lowercase().starts_with(&prefix))
                    .map(|l| l[prefix.len()..].trim().to_string())
                    .collect(),
            );
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zion-client-ip-{tag}-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn behind_a_trusted_proxy_the_client_cannot_choose_its_address() {
    let dir = temp_dir("v4");
    if !certificate(&dir) {
        common::skip("openssl could not make a certificate");
        return;
    }
    let (origin_port, seen) = origin();
    let z = start(&dir, "127.0.0.1", origin_port);
    let port = z.https;
    let mut failures = Vec::new();

    // Control: no X-Forwarded-For, the trusted loopback peer is the client, and internal.
    let got = send(port, &request("GET", "/metrics", &[]));
    if got != 200 {
        failures.push(format!(
            "control: GET /metrics with no X-Forwarded-For -> {got}, want 200"
        ));
    }

    // Every row says, through the trusted peer, that the client is REAL: all 403.
    let real = REAL.as_bytes();
    let two_lines: Vec<&[u8]> = vec![b"10.0.0.1", real];
    // what nginx's `$proxy_add_x_forwarded_for` forwards for a client that sent a lone 0xFF
    let obs_text = [&[0xFF][..], format!(", {REAL}").as_bytes()].concat();
    let obs: Vec<&[u8]> = vec![&obs_text];
    let port_hop = format!("10.0.0.1, {REAL}:51234");
    let gates: Vec<(&str, &str, &str, Vec<&[u8]>)> = vec![
        ("control: one line", "GET", "/metrics", vec![real]),
        ("two lines", "GET", "/metrics", two_lines.clone()),
        (
            "two lines",
            "GET",
            "/_zion/snapshot.json",
            two_lines.clone(),
        ),
        (
            "two lines",
            "POST",
            "/_zion/cache/purge",
            vec![b"127.0.0.2", real],
        ),
        ("two lines", "GET", "/internal/a", two_lines.clone()),
        ("0xFF byte", "GET", "/metrics", obs.clone()),
        ("0xFF byte", "GET", "/_zion/snapshot.json", obs.clone()),
        ("0xFF byte", "POST", "/_zion/cache/purge", obs.clone()),
        ("0xFF byte", "GET", "/internal/b", obs.clone()),
        (
            "ip:port hop",
            "GET",
            "/internal/c",
            vec![port_hop.as_bytes()],
        ),
        (
            "unknown hop",
            "GET",
            "/internal/d",
            vec![b"127.0.0.1, unknown"],
        ),
        (
            "[v6]:port hop",
            "GET",
            "/metrics",
            vec![b"127.0.0.1, [2001:db8::1]:443"],
        ),
    ];
    for (row, method, path, xff) in &gates {
        let got = send(port, &request(method, path, xff));
        if got != 403 {
            failures.push(format!("{row}: {method} {path} -> {got}, want 403"));
        }
    }

    // `Connection: X-Forwarded-For` passed on by the proxy: the header is zion's to read, it
    // used to be dropped first and the client became the proxy.
    let mut named = request("GET", "/metrics", &[real]);
    let at = named.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
    named.splice(
        at..at,
        b"Connection: keep-alive, X-Forwarded-For\r\n"
            .iter()
            .copied(),
    );
    let got = send(port, &named);
    if got != 403 {
        failures.push(format!(
            "Connection lists X-Forwarded-For: GET /metrics -> {got}, want 403"
        ));
    }

    // The plain-HTTP listener resolves the client the same way: the snapshot is refused,
    // and an ACME-challenge path it forwards tells the upstream the client, not the proxy.
    let got = send_plain(z.http, &request("GET", "/_zion/snapshot.json", &[]));
    if got != 200 {
        failures.push(format!(
            "control: :80 GET /_zion/snapshot.json with no X-Forwarded-For -> {got}, want 200"
        ));
    }
    let got = send_plain(z.http, &request("GET", "/_zion/snapshot.json", &[real]));
    if got != 403 {
        failures.push(format!(
            ":80 GET /_zion/snapshot.json through the trusted proxy -> {got}, want 403"
        ));
    }
    let acme = "/.well-known/acme-challenge/client-ip";
    let got = send_plain(z.http, &request("GET", acme, &[real]));
    let ip = origin_header(&seen, acme, "x-real-ip");
    if got != 200 || ip.as_deref() != Some(&[REAL.to_string()][..]) {
        failures.push(format!(
            ":80 ACME fallback -> {got}, upstream X-Real-IP {ip:?}, want {REAL}"
        ));
    }

    // What the upstream is told: the address the trusted proxy wrote, or 0.0.0.0 when it
    // wrote something that is not an address; never the client's own entry.
    let real_ip: Vec<(&str, &str, Vec<&[u8]>, &str)> = vec![
        ("two lines", "/r1", two_lines, REAL),
        ("0xFF byte", "/r2", obs, REAL),
        ("ip:port hop", "/r3", vec![port_hop.as_bytes()], REAL),
        (
            "[v6]:port hop",
            "/r4",
            vec![b"10.0.0.1, [2001:db8::1]:443"],
            "2001:db8::1",
        ),
        ("unknown hop", "/r5", vec![b"10.0.0.1, unknown"], "0.0.0.0"),
    ];
    for (row, path, xff, want) in &real_ip {
        let got = send(port, &request("GET", path, xff));
        let ip = origin_header(&seen, path, "x-real-ip");
        if got != 200 || ip.as_deref() != Some(&[want.to_string()][..]) {
            failures.push(format!(
                "{row}: GET {path} -> {got}, upstream X-Real-IP {ip:?}, want {want}"
            ));
        }
    }

    // `xff_mode = "append"` sends one line, the inbound chain then the client: an upstream
    // that reads only the first line still sees zion's entry.
    let _ = send(port, &request("GET", "/r6", &[b"198.51.100.7"]));
    let lines = origin_header(&seen, "/r6", "x-forwarded-for");
    if lines.as_deref() != Some(&["198.51.100.7, 198.51.100.7".to_string()][..]) {
        failures.push(format!(
            "append: upstream X-Forwarded-For lines {lines:?}, want one line \"198.51.100.7, 198.51.100.7\""
        ));
    }

    let _ = fs::remove_dir_all(&dir);
    assert!(
        failures.is_empty(),
        "client IP resolution behind a trusted proxy:\n  {}",
        failures.join("\n  ")
    );
}

/// A dual-stack `[::]` listener reached over IPv4: the peer is 127.0.0.1, not
/// `::ffff:127.0.0.1`, so the IPv4 `trusted_proxies` entry matches and the upstream is told
/// the IPv4 address. Skipped only where the platform has no dual-stack `[::]` socket that
/// takes IPv4 (checked without zion); once it has one, zion must come up on it.
#[test]
fn an_ipv4_peer_of_a_dual_stack_listener_is_matched_as_ipv4() {
    if !dual_stack_available() {
        eprintln!("SKIP: no dual-stack [::] socket that takes IPv4 on this host");
        return;
    }
    let dir = temp_dir("dual");
    if !certificate(&dir) {
        common::skip("openssl could not make a certificate");
        return;
    }
    let (origin_port, seen) = origin();
    let z = start(&dir, "[::]", origin_port);
    let port = z.https;
    let mut failures = Vec::new();
    // control: the loopback peer itself is internal
    let got = send(port, &request("GET", "/metrics", &[]));
    if got != 200 {
        failures.push(format!(
            "control: GET /metrics with no X-Forwarded-For -> {got}, want 200"
        ));
    }
    // the trusted proxy is recognised, so its client REAL is not internal
    let got = send(port, &request("GET", "/metrics", &[REAL.as_bytes()]));
    if got != 403 {
        failures.push(format!(
            "GET /metrics with X-Forwarded-For {REAL} from the trusted 127.0.0.1 -> {got}, want 403"
        ));
    }
    let _ = send(port, &request("GET", "/plain", &[]));
    let ip = origin_header(&seen, "/plain", "x-real-ip");
    if ip.as_deref() != Some(&["127.0.0.1".to_string()][..]) {
        failures.push(format!("upstream X-Real-IP {ip:?}, want 127.0.0.1"));
    }
    let _ = fs::remove_dir_all(&dir);
    assert!(
        failures.is_empty(),
        "IPv4 peer of a [::] listener:\n  {}",
        failures.join("\n  ")
    );
}
