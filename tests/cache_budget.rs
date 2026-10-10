// SPDX-License-Identifier: Apache-2.0
//! The response cache's memory budget (#524), with the real binary.
//!
//! The cache was bounded by entry count (10,000 by default) and by object size (50 MiB),
//! not by bytes: a client asking for distinct URLs of a cached route could make it hold
//! entries x object size. `[server] cache_max_memory_mb` bounds the total. Here 600
//! distinct 1 MiB responses are requested through a cache with a 16 MiB budget: the cache
//! stays within it, by its own count and by the memory of the process, and it still serves
//! hits.
//!
//! Unix only; skipped with a message when `openssl` or `curl` is missing.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{free_port, process_memory_mib};

const MIB: usize = 1024 * 1024;
const BUDGET_MIB: u64 = 16;
/// Distinct 1 MiB objects requested. Enough that a cache with no budget and one with a
/// budget end far apart on any allocator (see `MAX_GROWTH_MIB`).
const OBJECTS: usize = 600;
/// What the process may grow by while `OBJECTS` MiB go through a 16 MiB cache.
///
/// Measured (debug build, 2026-10-06), growth after 600 MiB of cacheable responses:
///
/// |                     | Linux (glibc)   | macOS       |
/// |---------------------|-----------------|-------------|
/// | 16 MiB budget       | 94 to 125 MiB   | 88 to 90    |
/// | no budget           | 1,213 to 1,271  | 644 to 652  |
///
/// With the budget the growth does not follow what is offered: 200, 400, 800 and 1,600
/// MiB all end between 96 and 131 MiB on Linux. Most of it is the allocator keeping what
/// the churn freed, and it differs by platform and by run. The bound is therefore set
/// between the two rows with room on both sides (more than twice the highest budgeted
/// run, less than half the lowest unbudgeted one), not next to one platform's number:
/// the first version said 110 MiB after 200 objects, measured on macOS, and failed four
/// runs in ten on Linux.
const MAX_GROWTH_MIB: u64 = 300;

struct Zion {
    child: Child,
    https: u16,
    dir: PathBuf,
}
impl Drop for Zion {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An origin that answers `GET /obj/<n>?mib=<m>` with `m` MiB (1 by default) of bytes that
/// depend on `n` and do not compress, cacheable for ten minutes.
fn origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut conn = conn;
                let (mut seen, mut buf) = (Vec::new(), [0u8; 4096]);
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&seen);
                let target = head.split_whitespace().nth(1).unwrap_or("/");
                let mib: usize = target
                    .split_once("mib=")
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(1);
                // xorshift seeded by the URL: a different, incompressible body per object.
                let mut x = 0x9e37_79b9_7f4a_7c15u64
                    ^ target
                        .bytes()
                        .fold(0u64, |h, b| h.wrapping_mul(131) + u64::from(b));
                let mut body = Vec::with_capacity(mib * MIB + 8);
                while body.len() < mib * MIB {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    body.extend_from_slice(&x.to_le_bytes());
                }
                body.truncate(mib * MIB);
                let _ = conn.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\n\
                         cache-control: public, max-age=600\r\ncontent-length: {}\r\n\
                         connection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = conn.write_all(&body);
            });
        }
    });
    port
}

/// Start zion with a cached route in front of `origin` and `server` appended to `[server]`;
/// `None` when a tool the test needs is missing.
fn start(origin: u16, server: &str) -> Option<Zion> {
    start_with(origin, server, &[])
}

/// [`start`], with more environment variables for zion.
fn start_with(origin: u16, server: &str, env: &[(&str, &str)]) -> Option<Zion> {
    let has = |tool: &str| {
        Command::new(tool)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    };
    if !has("openssl") || !has("curl") {
        eprintln!("SKIP: openssl and curl are needed");
        return None;
    }
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-cache-budget-{}-{http}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
    let made = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        ])
        .args([
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(made, "openssl could not make a certificate");
    let cfg = dir.join("zion.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n{server}\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\
             [upstreams]\norigin = \"http://127.0.0.1:{origin}\"\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"origin\"\nmode = \"static_cache\"\n",
            cert.display(),
            key.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", &cfg)
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .envs(env.iter().copied())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("zion.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let zion = Zion { child, https, dir };
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", https)).is_err() {
        assert!(Instant::now() < deadline, "zion did not start listening");
        std::thread::sleep(Duration::from_millis(100));
    }
    Some(zion)
}

/// `GET path` through zion: (status, `X-Zion-Cache`, bytes of body received).
fn get(zion: &Zion, path: &str) -> (u16, String, usize) {
    let out = Command::new("curl")
        .args(["-sk", "--max-time", "30", "-o", "/dev/null", "-D", "-"])
        .args(["-w", "\nsize=%{size_download}\n"])
        .arg(format!("https://127.0.0.1:{}{path}", zion.https))
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let header = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };
    let size = header("size=").parse().unwrap_or(0);
    (status, header("x-zion-cache:"), size)
}

/// The value of a `/metrics` line (the page is rendered at most once a second: read after
/// the traffic has stopped for a moment).
fn metric(zion: &Zion, name: &str) -> u64 {
    let out = Command::new("curl")
        .args(["-sk", "--max-time", "10"])
        .arg(format!("https://127.0.0.1:{}/metrics", zion.https))
        .output()
        .expect("curl");
    let page = String::from_utf8_lossy(&out.stdout);
    page.lines()
        .find_map(|l| l.strip_prefix(name).filter(|rest| rest.starts_with(' ')))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no `{name}` in /metrics"))
}

/// A cached megabyte costs the process about a megabyte (#590).
///
/// `cache_max_memory_mb` is a budget on what the cache counts (`zion_cache_bytes`). On Linux
/// mimalloc's default of committing its arena eagerly made the process hold 1.7 to 2.1 times
/// that, for bodies of 64 KiB, 300 KiB and 1 MiB alike, so a budget of N MiB held about 2N
/// (glibc's malloc: 1.0 to 1.1; `src/alloc_tuning.rs`). With no budget, 150 distinct 1 MiB
/// responses: the growth must stay under 1.5 times what the cache counts (the bug read 1.8
/// to 1.9 here, macOS 1.1).
#[test]
fn a_cached_megabyte_costs_the_process_about_a_megabyte() {
    const N: usize = 150;
    let origin = origin();
    let Some(zion) = start(origin, "cache_max_memory_mb = 0") else {
        return;
    };
    // The first requests pay for connections, TLS state and the page's own buffers.
    for n in 0..5 {
        assert_eq!(get(&zion, &format!("/obj/warm{n}")).0, 200);
    }
    std::thread::sleep(Duration::from_millis(1200));
    let (before, counted_before) = (
        process_memory_mib(zion.child.id()),
        metric(&zion, "zion_cache_bytes"),
    );
    for n in 0..N {
        let (status, _, size) = get(&zion, &format!("/obj/{n}"));
        assert_eq!((status, size), (200, MIB), "object {n}");
    }
    std::thread::sleep(Duration::from_millis(3000));
    let after = process_memory_mib(zion.child.id());
    let counted = (metric(&zion, "zion_cache_bytes") - counted_before) / MIB as u64;
    let grew = after.saturating_sub(before);
    eprintln!("cached {counted} MiB (as counted); the process grew by {grew} MiB");
    assert!(
        counted >= N as u64,
        "the cache holds what was offered: {counted} MiB"
    );
    assert!(
        grew * 2 < counted * 3,
        "the process grew by {grew} MiB for {counted} MiB the cache counts: more than 1.5 times"
    );
}

/// zion runs with transparent huge pages off for its own process, and an operator can keep them.
///
/// The test above only sees the cost where the machine has `transparent_hugepage/enabled` set
/// to `always`, and then only in a release build (#657: 1.5 to 1.6 instead of 1.1). This one
/// reads the switch itself, which the kernel shows in `/proc/<pid>/status`, so it says the same
/// on every Linux machine.
#[cfg(target_os = "linux")]
#[test]
fn transparent_huge_pages_are_off_for_the_process_unless_asked_for() {
    fn thp_enabled(zion: &Zion) -> Option<String> {
        let status = std::fs::read_to_string(format!("/proc/{}/status", zion.child.id())).ok()?;
        let line = status.lines().find(|l| l.starts_with("THP_enabled:"))?;
        Some(line["THP_enabled:".len()..].trim().to_string())
    }
    let Some(zion) = start(origin(), "") else {
        return;
    };
    // `THP_enabled` is in /proc/<pid>/status from Linux 5.0.
    let Some(by_default) = thp_enabled(&zion) else {
        eprintln!("SKIP: this kernel does not show THP_enabled");
        return;
    };
    assert_eq!(
        by_default, "0",
        "transparent huge pages are on for zion's process"
    );
    drop(zion);
    let zion = start_with(origin(), "", &[("MIMALLOC_ALLOW_THP", "1")]).expect("zion starts");
    assert_eq!(
        thp_enabled(&zion).as_deref(),
        Some("1"),
        "MIMALLOC_ALLOW_THP=1 keeps transparent huge pages"
    );
}

#[test]
fn the_cache_stays_within_its_memory_budget_and_still_serves_hits() {
    let origin = origin();
    let Some(zion) = start(origin, &format!("cache_max_memory_mb = {BUDGET_MIB}")) else {
        return;
    };
    let before = process_memory_mib(zion.child.id());

    // 600 distinct objects of 1 MiB: 600 MiB offered to a 16 MiB cache.
    for n in 0..OBJECTS {
        let (status, cache, size) = get(&zion, &format!("/obj/{n}"));
        assert_eq!((status, size), (200, MIB), "object {n}");
        assert_eq!(cache, "miss", "object {n} is new");
    }
    // The last one stored is still there, and what comes back is the whole object.
    let (status, cache, size) = get(&zion, &format!("/obj/{}", OBJECTS - 1));
    assert_eq!((status, cache.as_str(), size), (200, "hit", MIB));

    std::thread::sleep(Duration::from_millis(1200));
    let (bytes, entries) = (
        metric(&zion, "zion_cache_bytes"),
        metric(&zion, "zion_cache_entries"),
    );
    let budget = BUDGET_MIB * MIB as u64;
    assert!(
        bytes <= budget,
        "the cache holds {bytes} bytes, over its {budget}"
    );
    assert!(
        bytes > budget / 2 && (8..=15).contains(&entries),
        "and it is in use, not emptied: {bytes} bytes in {entries} entries"
    );
    assert_eq!(
        metric(&zion, "zion_cache_budget_skipped_total"),
        0,
        "room was made for every one of them"
    );
    let after = process_memory_mib(zion.child.id());
    eprintln!(
        "memory: {before} MiB before, {after} MiB after {OBJECTS} MiB of cacheable responses"
    );
    assert!(
        after.saturating_sub(before) < MAX_GROWTH_MIB,
        "the process grew by {} MiB ({before} -> {after}) with a {BUDGET_MIB} MiB cache budget \
         and {OBJECTS} MiB offered: it must stay under {MAX_GROWTH_MIB}",
        after.saturating_sub(before)
    );

    // An object larger than the whole budget is served and never stored.
    for _ in 0..2 {
        let (status, cache, size) = get(&zion, "/obj/huge?mib=20");
        assert_eq!((status, cache.as_str(), size), (200, "miss", 20 * MIB));
    }
    std::thread::sleep(Duration::from_millis(1200));
    assert!(metric(&zion, "zion_cache_budget_skipped_total") >= 1);
    assert!(metric(&zion, "zion_cache_bytes") <= budget);
    let log = std::fs::read_to_string(zion.dir.join("zion.log")).unwrap_or_default();
    assert!(
        log.contains(&format!(
            "response cache budget {BUDGET_MIB} MiB (server.cache_max_memory_mb)"
        )),
        "the boot log states the budget:\n{log}"
    );

    // A reload that lowers the budget shrinks the cache as new responses are stored.
    let cfg = zion.dir.join("zion.toml");
    let lowered = std::fs::read_to_string(&cfg).unwrap().replace(
        &format!("cache_max_memory_mb = {BUDGET_MIB}"),
        "cache_max_memory_mb = 4",
    );
    std::fs::write(&cfg, lowered).unwrap();
    let small = 4 * MIB as u64;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut n = 1_000;
    loop {
        for _ in 0..4 {
            n += 1;
            assert_eq!(get(&zion, &format!("/obj/{n}")).0, 200);
        }
        std::thread::sleep(Duration::from_millis(1100));
        let bytes = metric(&zion, "zion_cache_bytes");
        if bytes <= small {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "after the reload to 4 MiB the cache still holds {bytes} bytes"
        );
    }
}
