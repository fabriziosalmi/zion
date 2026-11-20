// SPDX-License-Identifier: Apache-2.0
//! A cache hit carries the origin's response headers, not only the few `CachedMeta` used to keep.
//!
//! An origin that serves user uploads keeps the real `Content-Type` (`image/svg+xml`) and makes
//! the file inert with `Content-Security-Policy: sandbox` and `Content-Disposition: attachment`.
//! Behind a `static_cache` route the first GET (MISS) carries both. The second GET (HIT) used to
//! be rebuilt from status, Content-Type, Content-Encoding, ETag and Last-Modified only, so the
//! browser rendered the SVG inline, scripts included, in the site's origin; `Vary` was dropped
//! too. The hit, a ranged hit (`206`) and a `304` to a conditional request are checked here,
//! and the hit must leave with the same headers as the miss, none twice.
//!
//! The origin also sends what must reach no client, on the miss or on a hit: a field named on
//! its second `Connection` line, its own `Alt-Svc` and a `Proxy-Authentication-Info`.
//!
//! Unix only; skipped with a message when `openssl` or `curl` is missing.
#![cfg(unix)]

use std::collections::{BTreeMap, HashMap};
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

const SVG: &str =
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(document.domain)</script></svg>";

/// What the origin says about its own connection and alternatives, which no client may see.
const ORIGIN_ALT_SVC: &str = "h3=\":9443\"; ma=60";

/// An upload origin: every answer is a cacheable SVG neutralised by its response headers. Its
/// `Cache-Control` is written as zion never writes one (`public, max-age=N`), so that a hit
/// carrying one made up from the entry's lifetime cannot pass for the origin's.
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
                let _ = write!(
                    conn,
                    "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\n\
                     Cache-Control: max-age=60, public\r\n\
                     Content-Security-Policy: sandbox\r\n\
                     Content-Disposition: attachment; filename=\"upload.svg\"\r\n\
                     Vary: Accept-Language\r\n\
                     Link: </a.css>; rel=preload\r\n\
                     Link: </b.js>; rel=preload\r\n\
                     X-Origin-Thing: kept\r\n\
                     Content-Digest: sha-256=:d2hvbGUgZmlsZQ==:\r\n\
                     Alt-Svc: {ORIGIN_ALT_SVC}\r\n\
                     Proxy-Authentication-Info: nextnonce=\"n1\"\r\n\
                     ETag: \"u1\"\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\
                     Connection: X-Backend-Session\r\n\
                     X-Backend-Session: per-connection\r\n\r\n{SVG}",
                    SVG.len()
                );
            });
        }
    });
    port
}

/// `(status, lowercased response header block)` of a GET with `extra` curl arguments.
fn get(https: u16, path: &str, extra: &[&str]) -> (u16, String) {
    let out = Command::new("curl")
        .args(["-sk", "--max-time", "10", "-D", "-", "-o", "/dev/null"])
        .args(extra)
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
    (status, text)
}

/// Every value of header `name` in `block`, in order.
fn all<'a>(block: &'a str, name: &str) -> Vec<&'a str> {
    block
        .lines()
        .filter_map(|l| {
            l.strip_prefix(name)
                .and_then(|r| r.strip_prefix(':'))
                .map(str::trim)
        })
        .collect()
}

fn header<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    all(block, name).first().copied()
}

/// How many times each header name appears in `block`.
fn name_counts(block: &str) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for line in block.lines().skip(1) {
        if let Some((name, _)) = line.split_once(':') {
            *out.entry(name.trim().to_string()).or_insert(0) += 1;
        }
    }
    out
}

fn count(hits: &Arc<Mutex<HashMap<String, u32>>>, path: &str) -> u32 {
    hits.lock().unwrap().get(path).copied().unwrap_or(0)
}

/// What the origin said about its own connection and alternatives: on no answer, whether it
/// came from the origin or from the cache. (`Alt-Svc` may be zion's own, with HTTP/3.)
fn assert_no_origin_hop_headers(block: &str, what: &str) {
    for name in ["x-backend-session", "proxy-authentication-info"] {
        assert_eq!(header(block, name), None, "{what} carries {name}\n{block}");
    }
    let origin_alt_svc = ORIGIN_ALT_SVC.to_ascii_lowercase();
    assert!(
        all(block, "alt-svc").iter().all(|v| *v != origin_alt_svc),
        "{what} carries the origin's Alt-Svc\n{block}"
    );
}

/// The headers the origin set to make the upload inert, and the ones a cache must keep with them.
fn assert_origin_headers(block: &str, what: &str) {
    assert_eq!(
        header(block, "content-security-policy"),
        Some("sandbox"),
        "{what}\n{block}"
    );
    assert!(
        header(block, "content-disposition").is_some_and(|v| v.starts_with("attachment")),
        "{what}\n{block}"
    );
    assert_eq!(
        header(block, "vary"),
        Some("accept-language"),
        "{what}\n{block}"
    );
}

#[test]
fn a_cache_hit_keeps_the_origin_csp_content_disposition_and_vary() {
    if Command::new("curl").arg("--version").output().is_err() {
        common::skip("curl not available");
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "zion-cache-hit-hdrs-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    if !openssl(&[
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
             [upstreams]\nuploads = \"http://127.0.0.1:{origin}\"\n\n\
             [[route]]\npath = \"/media/{{*r}}\"\nupstream = \"uploads\"\nmode = \"static_cache\"\n",
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
        if get(https, "/media/warm", &[]).0 == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the origin never answered\n{}",
            fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // The attacker primes the entry: a MISS, served with the origin's headers.
    let path = "/media/upload.svg";
    let (status, miss) = get(https, path, &[]);
    assert_eq!(status, 200, "{miss}");
    assert_eq!(header(&miss, "x-zion-cache"), Some("miss"), "{miss}");
    assert_origin_headers(&miss, "the miss");
    assert_no_origin_hop_headers(&miss, "the miss");

    // The victim's GET is a HIT from the stored entry.
    let (status, hit) = get(https, path, &[]);
    assert_eq!(status, 200, "{hit}");
    assert_eq!(header(&hit, "x-zion-cache"), Some("hit"), "{hit}");
    eprintln!("--- MISS ---\n{miss}--- HIT ---\n{hit}");
    assert_eq!(count(&hits, path), 1, "the origin saw one request");
    assert_eq!(header(&hit, "content-type"), Some("image/svg+xml"), "{hit}");
    assert_no_origin_hop_headers(&hit, "the hit");

    let dropped: Vec<&str> = [
        "content-security-policy",
        "content-disposition",
        "vary",
        "link",
        "x-origin-thing",
    ]
    .into_iter()
    .filter(|h| header(&hit, h).is_none())
    .collect();
    assert!(
        dropped.is_empty(),
        "a cache HIT dropped the origin's {dropped:?}: the SVG renders inline, scripts and all\n\
         --- MISS ---\n{miss}--- HIT ---\n{hit}"
    );
    // The origin's own Cache-Control, as on the miss, not one made up from the entry.
    assert_eq!(
        all(&hit, "cache-control"),
        all(&miss, "cache-control"),
        "{hit}"
    );
    assert_eq!(
        all(&hit, "link"),
        all(&miss, "link"),
        "both lines, in order"
    );

    // The same header names as the miss, each as many times: a hit only adds `Age` and
    // `Accept-Ranges` (it answers ranges itself).
    let (mut miss_names, mut hit_names) = (name_counts(&miss), name_counts(&hit));
    assert_eq!(hit_names.remove("age"), Some(1), "{hit}");
    assert_eq!(hit_names.remove("accept-ranges"), Some(1), "{hit}");
    miss_names.remove("accept-ranges");
    assert_eq!(
        hit_names, miss_names,
        "a hit leaves with the miss's headers, none twice\n--- MISS ---\n{miss}--- HIT ---\n{hit}"
    );

    // A ranged hit (206) from the same entry carries them too.
    let (status, partial) = get(https, path, &["-r", "0-9"]);
    eprintln!("--- RANGED HIT ---\n{partial}");
    assert_eq!(status, 206, "{partial}");
    assert_eq!(header(&partial, "x-zion-cache"), Some("hit"), "{partial}");
    assert_eq!(
        header(&partial, "content-range"),
        Some(format!("bytes 0-9/{}", SVG.len()).as_str()),
        "{partial}"
    );
    assert_origin_headers(&partial, "the ranged hit");
    assert_eq!(all(&partial, "x-origin-thing"), ["kept"], "{partial}");
    assert_no_origin_hop_headers(&partial, "the ranged hit");
    // The whole file's digest does not describe ten bytes of it (RFC 9530 §2).
    assert_eq!(
        header(&hit, "content-digest"),
        header(&miss, "content-digest")
    );
    assert_eq!(header(&partial, "content-digest"), None, "{partial}");

    // A conditional request that matches gets a 304 from the cache with the headers RFC 9110
    // §15.4.5 lists for it: the validator, Cache-Control and Vary.
    let (status, not_modified) = get(https, path, &["-H", "If-None-Match: \"u1\""]);
    eprintln!("--- 304 ---\n{not_modified}");
    assert_eq!(status, 304, "{not_modified}");
    assert_eq!(
        header(&not_modified, "x-zion-cache"),
        Some("hit"),
        "{not_modified}"
    );
    assert_eq!(
        header(&not_modified, "etag"),
        Some("\"u1\""),
        "{not_modified}"
    );
    assert_eq!(
        header(&not_modified, "cache-control"),
        Some("max-age=60, public"),
        "{not_modified}"
    );
    assert_eq!(
        header(&not_modified, "vary"),
        Some("accept-language"),
        "{not_modified}"
    );

    assert_eq!(
        count(&hits, path),
        1,
        "every answer above came from the cache"
    );
    let _ = fs::remove_dir_all(dir);
}
