// SPDX-License-Identifier: Apache-2.0
//! A per-user response whose `Cache-Control` is split across two field lines, `max-age=300`
//! then `private`, is not stored in the shared cache: another user gets their own page.
//!
//! nginx emits exactly this layout with `expires 5m;` plus `add_header Cache-Control private;`.
//! RFC 9110 §5.3 makes the two lines one list, `max-age=300, private`. zion used to read the
//! first line only, stored the page and served alice's page to bob as a HIT. The origin here
//! answers with the requesting user's cookie in the body (a personalized page, no `Set-Cookie`,
//! no `Vary`). The control route sends the same directives on one line.
//!
//! Unix only; skipped with a message when `openssl` or `curl` is missing.
#![cfg(unix)]

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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

/// A personalized origin: the body names the user from the request `Cookie`. A path that
/// starts with `/c/split` gets two `Cache-Control` lines, every other path gets one joined
/// line with the same directives. It counts the requests per target.
fn origin(hits: Arc<Mutex<HashMap<String, u32>>>) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let hits = hits.clone();
            std::thread::spawn(move || {
                let mut conn = conn;
                let mut seen = Vec::new();
                let mut buf = [0u8; 2048];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&seen).into_owned();
                let target = text
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let user = text
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("cookie")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_else(|| "anonymous".to_string());
                *hits.lock().unwrap().entry(target.clone()).or_insert(0) += 1;
                let cc = if target.starts_with("/c/split") {
                    "Cache-Control: max-age=300\r\nCache-Control: private\r\n"
                } else {
                    "Cache-Control: max-age=300, private\r\n"
                };
                let body = format!("account page of {user}");
                let _ = write!(
                    conn,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{cc}\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    port
}

/// `(status, x-zion-cache or "", body)` for a GET with the given cookie.
fn get(https: u16, path: &str, cookie: &str) -> (u16, String, String) {
    let dir = std::env::temp_dir();
    let hdr_file = dir.join(format!(
        "zion-split-cc-h-{}-{}",
        std::process::id(),
        free_port()
    ));
    let out = Command::new("curl")
        .args(["-sk", "--max-time", "10", "-D"])
        .arg(&hdr_file)
        .args(["-H", &format!("Cookie: {cookie}")])
        .arg(format!("https://127.0.0.1:{https}{path}"))
        .output()
        .expect("curl");
    let head = fs::read_to_string(&hdr_file).unwrap_or_default();
    let _ = fs::remove_file(&hdr_file);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let cache = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("x-zion-cache")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    (
        status,
        cache,
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn count(hits: &Arc<Mutex<HashMap<String, u32>>>, path: &str) -> u32 {
    hits.lock().unwrap().get(path).copied().unwrap_or(0)
}

#[test]
fn a_private_cache_control_on_a_second_line_keeps_one_users_page_from_another() {
    if Command::new("curl").arg("--version").output().is_err() {
        common::skip("curl not available");
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "zion-split-cc-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    if !openssl(&[
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
        &key.to_string_lossy(),
        "-out",
        &cert.to_string_lossy(),
    ]) {
        common::skip("openssl could not make a certificate");
        return;
    }
    let hits = Arc::new(Mutex::new(HashMap::new()));
    let origin = origin(hits.clone());
    let https = free_port();
    let d = dir.to_string_lossy();
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https}\"\n\n\
             [tls]\ncert_path = \"{d}/c.pem\"\nkey_path = \"{d}/k.pem\"\nhot_reload = false\n\n\
             [upstreams]\no = \"http://127.0.0.1:{origin}\"\n\n\
             [cache_profile.mem]\nmode = \"memory\"\nttl_seconds = 600\n\n\
             [[route]]\npath = \"/c/{{*r}}\"\nupstream = \"o\"\ncache_profile = \"mem\"\n",
            free_port()
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
    let _z = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https)).is_err() {
        assert!(Instant::now() < deadline, "zion never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if get(https, "/c/warm", "sid=warm").0 == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the origin never answered\n{}",
            fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Control: one joined line `max-age=300, private` is never stored.
    let joined = "/c/joined/account?x=r4nd";
    let a = get(https, joined, "sid=alice");
    let b = get(https, joined, "sid=bob");
    eprintln!("joined: alice -> {a:?}");
    eprintln!("joined: bob   -> {b:?}");
    assert_eq!(a.0, 200);
    assert_eq!(
        b.2, "account page of sid=bob",
        "control: bob sees his own page"
    );
    assert_eq!(
        count(&hits, joined),
        2,
        "control: the origin sees both requests"
    );

    // The same directives on two field lines.
    let split = "/c/split/account?x=r4nd";
    let a = get(https, split, "sid=alice");
    let b = get(https, split, "sid=bob");
    eprintln!("split:  alice -> {a:?}");
    eprintln!("split:  bob   -> {b:?}");
    eprintln!("split:  origin requests = {}", count(&hits, split));
    assert_eq!(a.0, 200);
    assert_eq!(a.2, "account page of sid=alice");
    assert!(
        !b.1.eq_ignore_ascii_case("hit") && b.2 == "account page of sid=bob",
        "bob was served alice's `Cache-Control: private` page from the shared cache: {b:?}, \
         origin requests = {}",
        count(&hits, split)
    );
    assert_eq!(count(&hits, split), 2, "the origin sees both requests");
    let _ = fs::remove_dir_all(dir);
}
