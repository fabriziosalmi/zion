// SPDX-License-Identifier: Apache-2.0
//! A certificate renewal killed between its two renames (#536), with the real binary.
//!
//! A renewal renames the new key into place, then the new certificate, keeping a link to
//! the old key until both are done. Killed in between, it leaves the new key beside the old
//! certificate. Before, the next boot refused that pair and the operator had to rename the
//! backup by hand; now the boot puts the previous key back and says so.
//!
//! Unix only, and skipped when `openssl` is not installed.
#![cfg(unix)]

use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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

/// `<name>.pem` / `<name>.key`: a self-signed certificate for `cn`.
fn self_signed(dir: &Path, name: &str, cn: &str) -> bool {
    Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        ])
        .args(["-subj", &format!("/CN={cn}")])
        // An extension makes it a version 3 certificate; a version 1 one (LibreSSL's default
        // for `req -x509`) is not a certificate rustls accepts.
        .args(["-addext", &format!("subjectAltName=DNS:{cn}")])
        .args([
            "-keyout",
            &dir.join(format!("{name}.key")).to_string_lossy(),
        ])
        .args(["-out", &dir.join(format!("{name}.pem")).to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn workdir(tag: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "zion-cert-recovery-{tag}-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    (self_signed(&dir, "old", "old.example") && self_signed(&dir, "new", "new.example"))
        .then_some(dir)
}

fn command(dir: &Path, https_port: u16, log: &str) -> Command {
    let d = dir.to_string_lossy();
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
             [tls]\ncert_path = \"{d}/cert.pem\"\nkey_path = \"{d}/key.pem\"\nhot_reload = false\n\n\
             [upstream.backend]\nurl = \"http://127.0.0.1:9\"\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n",
            free_port()
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zion"));
    cmd.env("ZION_CONFIG", dir.join("zion.toml"))
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(dir.join(log)).unwrap());
    cmd
}

/// The exit code of a daemon that is expected to refuse to boot. One that boots instead is
/// stopped after a few seconds, so a regression fails the test rather than hanging it.
fn exit_code_when_refusing(mut cmd: Command) -> Option<i32> {
    let mut child = cmd.spawn().expect("spawn zion");
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// The state a renewal killed after its first rename leaves: the new key, the old
/// certificate, and the old key under its backup name.
fn interrupted_renewal(dir: &Path, backup: &str) {
    fs::copy(dir.join("old.pem"), dir.join("cert.pem")).unwrap();
    fs::copy(dir.join("new.key"), dir.join("key.pem")).unwrap();
    fs::copy(dir.join(backup), dir.join("key.pem.zion-bak-4242")).unwrap();
}

/// The common name of the certificate zion presents on `port`.
fn served_cn(port: u16) -> String {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo | openssl s_client -connect 127.0.0.1:{port} 2>/dev/null \
             | openssl x509 -noout -subject 2>/dev/null"
        ))
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn wait_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "zion never listened on {port}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_boot_after_an_interrupted_renewal_restores_the_previous_key() {
    let Some(dir) = workdir("restore") else {
        eprintln!("SKIP: openssl not available");
        return;
    };
    interrupted_renewal(&dir, "old.key");
    let port = free_port();
    let _z = Proc(command(&dir, port, "boot.log").spawn().expect("spawn zion"));
    wait_port(port);

    let log = fs::read_to_string(dir.join("boot.log")).unwrap();
    assert!(
        log.contains("renewal was interrupted") && log.contains("Restored the previous key"),
        "the log says what was done:\n{log}"
    );
    assert!(
        served_cn(port).contains("old.example"),
        "the old certificate is served with its own key"
    );
    assert_eq!(
        fs::read(dir.join("key.pem")).unwrap(),
        fs::read(dir.join("old.key")).unwrap()
    );
    assert_eq!(
        fs::read(dir.join("key.pem.zion-unpaired")).unwrap(),
        fs::read(dir.join("new.key")).unwrap(),
        "the key that was replaced is kept"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_mismatched_pair_with_no_matching_backup_still_refuses_to_boot() {
    let Some(dir) = workdir("refuse") else {
        eprintln!("SKIP: openssl not available");
        return;
    };
    // The "backup" is a key of some other certificate: not this certificate's.
    interrupted_renewal(&dir, "new.key");
    let code = exit_code_when_refusing(command(&dir, free_port(), "refuse.log"));
    let log = fs::read_to_string(dir.join("refuse.log")).unwrap();
    assert_eq!(code, Some(3), "{log}");
    assert!(log.contains("does not match key"), "{log}");
    assert_eq!(
        fs::read(dir.join("key.pem")).unwrap(),
        fs::read(dir.join("new.key")).unwrap(),
        "nothing was changed"
    );
    assert!(dir.join("key.pem.zion-bak-4242").exists());
    assert!(!dir.join("key.pem.zion-unpaired").exists());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_mismatched_pair_without_any_backup_refuses_to_boot_as_before() {
    let Some(dir) = workdir("nobak") else {
        eprintln!("SKIP: openssl not available");
        return;
    };
    interrupted_renewal(&dir, "old.key");
    fs::remove_file(dir.join("key.pem.zion-bak-4242")).unwrap();
    let code = exit_code_when_refusing(command(&dir, free_port(), "nobak.log"));
    assert_eq!(code, Some(3));
    let _ = fs::remove_dir_all(dir);
}

/// Only a pair that does not match is a half-finished renewal. A key that cannot be read at
/// all is something else, and a backup is not put in its place without a reason.
#[test]
fn a_key_that_is_not_a_key_is_not_replaced_from_a_backup() {
    let Some(dir) = workdir("garbage") else {
        eprintln!("SKIP: openssl not available");
        return;
    };
    interrupted_renewal(&dir, "old.key");
    fs::write(dir.join("key.pem"), b"not a key\n").unwrap();
    let code = exit_code_when_refusing(command(&dir, free_port(), "garbage.log"));
    assert_eq!(code, Some(3));
    assert_eq!(fs::read(dir.join("key.pem")).unwrap(), b"not a key\n");
    assert!(dir.join("key.pem.zion-bak-4242").exists());
    let _ = fs::remove_dir_all(dir);
}
