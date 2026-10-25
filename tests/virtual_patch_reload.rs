// SPDX-License-Identifier: Apache-2.0
//! Virtual-patch rules hot-reload (#698), against the real binary: a rule added to the rules file
//! blocks its request shape after a reload, with no restart; a broken edit keeps the previous
//! rules (fail-safe). The upstream is a dead port, so a request that is NOT blocked comes back 503
//! (it reached the proxy) and a blocked one comes back 403 (the virtual-patch gate) — the two are
//! easy to tell apart.
//!
//! Unix only, and skipped when `openssl` or `curl` is missing.
#![cfg(unix)]

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

struct Zion {
    child: Child,
    https: u16,
    dir: PathBuf,
    rules_path: PathBuf,
}
impl Drop for Zion {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn have(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot zion with a `[virtual_patch]` rules file seeded with `initial_rules`. None if openssl/curl
/// are missing.
fn start(initial_rules: &str) -> Option<Zion> {
    if !have("openssl", &["version"]) || !have("curl", &["--version"]) {
        eprintln!("SKIP: openssl or curl missing");
        return None;
    }
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-vpreload-{}-{http}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
    Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        ])
        .args([
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stderr(Stdio::null())
        .status()
        .ok()?;
    let rules_path = dir.join("virtual-patch.toml");
    std::fs::write(&rules_path, initial_rules).unwrap();
    let cfg = dir.join("zion.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n\
             [virtual_patch]\nrules_file = \"virtual-patch.toml\"\n\
             [upstreams]\nbackend = \"http://127.0.0.1:1\"\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n",
            cert.display(),
            key.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", &cfg)
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("zion.log")).unwrap())
        .spawn()
        .expect("spawn zion");
    let zion = Zion {
        child,
        https,
        dir,
        rules_path,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", http)).is_err() {
        assert!(Instant::now() < deadline, "zion did not start listening");
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(300));
    Some(zion)
}

/// The HTTP status code curl sees for `GET https://.../{path}` (0 on transport failure).
fn code(https: u16, path: &str) -> u32 {
    let out = Command::new("curl")
        .args([
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "8",
        ])
        .arg(format!("https://127.0.0.1:{https}{path}"))
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// A rule that blocks `GET /blocked`.
const BLOCK_RULE: &str = "[[rule]]\nid='t1'\ncve='CVE-2099-0001'\nsource='http://example/adv'\n\
                          action='deny'\nmethods=['GET']\npath_glob='/blocked*'\n";

#[test]
fn a_rule_added_to_the_file_blocks_its_shape_after_a_reload_without_restart() {
    // Start with a rule that matches something else, so the file is valid but /blocked is open.
    let Some(zion) = start(
        "[[rule]]\nid='other'\ncve='CVE-0000-0000'\naction='deny'\npath_glob='/something-else*'\n",
    ) else {
        return;
    };
    let pid_before = zion.child.id();

    // /blocked is open: it reaches the (dead) upstream and comes back 503, not 403.
    assert_eq!(
        code(zion.https, "/blocked"),
        503,
        "before the rule, the shape must not be blocked"
    );

    // Add the blocking rule to the file; the watcher debounces ~2 s.
    std::fs::write(&zion.rules_path, BLOCK_RULE).unwrap();
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if code(zion.https, "/blocked") == 403 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the added rule did not take effect after a reload"
        );
        std::thread::sleep(Duration::from_millis(300));
    }

    // A path the rule does not cover is still open.
    assert_eq!(
        code(zion.https, "/elsewhere"),
        503,
        "the rule must block only its own shape"
    );

    // No restart happened.
    assert_eq!(zion.child.id(), pid_before, "zion must not have restarted");

    // Fail-safe: a broken edit keeps the previous (blocking) rule.
    std::fs::write(&zion.rules_path, "this is not valid toml [[[").unwrap();
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(
        code(zion.https, "/blocked"),
        403,
        "a broken rule file must keep the previous rules, not drop them"
    );

    // Still the same process throughout.
    assert_eq!(zion.child.id(), pid_before, "zion must not have restarted");
}

/// The shipped starter pack blocks each CVE's request shape (a test per rule, #698 "done when").
#[test]
fn the_shipped_pack_blocks_each_cve_shape() {
    let pack = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/virtual-patch.toml"
    ))
    .expect("the shipped pack exists");
    let Some(zion) = start(&pack) else {
        return;
    };

    // (CVE, a path the rule must block). One case per rule in examples/virtual-patch.toml.
    let blocked: &[(&str, &str)] = &[
        ("CVE-2022-22947", "/actuator/gateway/routes/x"),
        ("CVE-2021-22986", "/mgmt/tm/util/bash"),
    ];
    for (cve, path) in blocked {
        assert_eq!(
            code(zion.https, path),
            403,
            "the pack must block {cve} ({path})"
        );
    }

    // A request matching no rule is not blocked (reaches the dead upstream -> 503).
    assert_eq!(
        code(zion.https, "/app/home"),
        503,
        "a benign request must pass the virtual-patch gate"
    );
}
