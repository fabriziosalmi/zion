// SPDX-License-Identifier: Apache-2.0
//! The served certificate's expiry and failed certificate reloads are on `/metrics`, with the
//! real binary and its file watcher.
//!
//! A reload that failed was only an `eprintln!` (zion kept serving the previous certificate), and
//! the expiry was computed every minute but exported nowhere: neither could be alerted on.
#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod common;
use common::free_port;

struct Zion(Child, std::path::PathBuf);
impl Drop for Zion {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// A self-signed pair valid for `days`, written to `cert` / `key`.
fn make_pair(cert: &Path, key: &Path, days: u32) -> bool {
    Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"])
        .args([
            "-days",
            &days.to_string(),
            "-subj",
            "/CN=localhost",
            "-keyout",
        ])
        .arg(key)
        .arg("-out")
        .arg(cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The value of `name` on zion's `/metrics`, if it answered.
fn metric(https: u16, name: &str) -> Option<u64> {
    let out = Command::new("curl")
        .args(["-sk", "--max-time", "5"])
        .arg(format!("https://127.0.0.1:{https}/metrics"))
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name} ")).map(str::to_string))
        .and_then(|v| v.trim().parse().ok())
}

/// Poll `metric` until `ok` holds, for up to 15 s (the watcher debounces for 2 s).
fn wait_metric(https: u16, name: &str, ok: impl Fn(u64) -> bool) -> Option<u64> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let v = metric(https, name);
        if v.is_some_and(&ok) || Instant::now() > deadline {
            return v;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn certificate_expiry_and_failed_reloads_are_on_metrics() {
    const DAY: u64 = 86_400;
    let dir = std::env::temp_dir().join(format!("zion-tls-metrics-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
    let have_curl = Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !have_curl || !make_pair(&cert, &key, 3) {
        eprintln!("SKIP: openssl and curl are needed");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let (http, https) = (free_port(), free_port());
    let cfg = dir.join("zion.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{http}\"\nlisten_https = \"127.0.0.1:{https}\"\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = true\n\
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
    let zion = Zion(child, dir.clone());
    let failures = "zion_tls_reload_failures";
    let expiry = "zion_tls_cert_expiry_timestamp_seconds";

    // At boot: the served certificate's notAfter, about 3 days out; no failure yet.
    let at_boot = wait_metric(https, expiry, |v| v > 0).expect("zion answers /metrics");
    assert!(
        (now() + 2 * DAY..now() + 4 * DAY).contains(&at_boot),
        "expiry {at_boot} is not about 3 days from now"
    );
    assert_eq!(metric(https, failures), Some(0));

    // A certificate file that does not parse: the reload fails, is counted, and the previous
    // certificate (and its expiry) stays.
    std::fs::write(&cert, b"not a certificate\n").unwrap();
    let failed = wait_metric(https, failures, |v| v >= 1);
    assert!(
        failed.is_some_and(|v| v >= 1),
        "the failed reload is counted: {failed:?}"
    );
    assert_eq!(
        metric(https, expiry),
        Some(at_boot),
        "the old cert still serves"
    );

    // A new valid pair, 10 days: once both files are in place the reload succeeds and the
    // gauge follows. (Written aside and renamed in, key first: the watcher may see the
    // mismatched moment, which is one more counted failure, not a wrong expiry.)
    let (new_cert, new_key) = (dir.join("new.crt"), dir.join("new.key"));
    assert!(make_pair(&new_cert, &new_key, 10));
    std::fs::rename(&new_key, &key).unwrap();
    std::fs::rename(&new_cert, &cert).unwrap();
    let renewed = wait_metric(https, expiry, |v| v > at_boot + 5 * DAY).unwrap();
    assert!(
        (now() + 9 * DAY..now() + 11 * DAY).contains(&renewed),
        "expiry {renewed} after the reload is not about 10 days from now"
    );
    drop(zion);
}
