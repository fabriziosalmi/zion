// SPDX-License-Identifier: Apache-2.0
//! `[cache_profile.x] mode = "none"` means the profile stores nothing (#636), with the real binary.
//!
//! The key was documented (`"memory"` or `"none"`) and parsed, and nothing read it: a route that
//! pointed at a `none` profile cached exactly like one pointing at a `memory` profile. Here one
//! cacheable origin sits behind three routes: a `memory` profile (the second request is a hit, the
//! origin sees one), a `none` profile, and a `static_cache` route with a `none` profile (the origin
//! sees both requests, and the response carries no `X-Zion-Cache`: it is an uncached route).
//!
//! Unix only; skipped with a message when `openssl` or `curl` is missing.
#![cfg(unix)]

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
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

/// An origin whose every answer is cacheable for a minute; it counts the requests per path.
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
                *hits.lock().unwrap().entry(target).or_insert(0) += 1;
                let body = "payload";
                let _ = write!(
                    conn,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: max-age=60\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    port
}

/// `(status, x-zion-cache header or "")`
fn get(https: u16, path: &str) -> (u16, String) {
    let out = Command::new("curl")
        .args(["-sk", "--max-time", "10", "-D", "-", "-o", "/dev/null"])
        .arg(format!("https://127.0.0.1:{https}{path}"))
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let cache = text
        .lines()
        .find_map(|l| l.strip_prefix("x-zion-cache:"))
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    (status, cache)
}

fn count(hits: &Arc<Mutex<HashMap<String, u32>>>, path: &str) -> u32 {
    hits.lock().unwrap().get(path).copied().unwrap_or(0)
}

#[test]
fn a_none_profile_stores_nothing_and_a_memory_profile_does() {
    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("SKIP: curl not available");
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "zion-cache-mode-{}-{}",
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
        eprintln!("SKIP: openssl could not make a certificate");
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
             [cache_profile.mem]\nmode = \"memory\"\n\n\
             [cache_profile.off]\nmode = \"none\"\n\n\
             [[route]]\npath = \"/m/{{*r}}\"\nupstream = \"o\"\ncache_profile = \"mem\"\n\n\
             [[route]]\npath = \"/n/{{*r}}\"\nupstream = \"o\"\ncache_profile = \"off\"\n\n\
             [[route]]\npath = \"/s/{{*r}}\"\nupstream = \"o\"\nmode = \"static_cache\"\ncache_profile = \"off\"\n",
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
    // The first request may wait for the first health probe: ask until the route answers.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if get(https, "/m/warm").0 == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the origin never answered\n{}",
            fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // memory: the second request is served from the cache.
    assert_eq!(get(https, "/m/x").0, 200);
    let (status, cache) = get(https, "/m/x");
    assert_eq!((status, cache.as_str()), (200, "hit"));
    assert_eq!(
        count(&hits, "/m/x"),
        1,
        "a memory profile stores the answer"
    );

    // none: every request goes to the origin, and nothing says it came from a cache.
    for path in ["/n/x", "/s/x"] {
        for _ in 0..2 {
            let (status, cache) = get(https, path);
            assert_eq!(status, 200, "{path}");
            assert_eq!(cache, "", "{path}: an uncached route sets no X-Zion-Cache");
        }
        assert_eq!(
            count(&hits, path),
            2,
            "{path}: a none profile stores nothing, so the origin sees both requests\n{}",
            fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
        );
    }
    let _ = Path::new(&dir);
    let _ = fs::remove_dir_all(dir);
}
