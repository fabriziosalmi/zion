// SPDX-License-Identifier: Apache-2.0
//! The daemon boots with a private key of every kind it is given, and serves the certificate
//! that goes with it (#537: the PEM reader was replaced). Each key is made by `openssl` at run
//! time, so no key is committed; a kind the local `openssl` cannot write is reported and
//! skipped, never silently counted as covered.
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

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A key file `name.key` of the PEM kind `label` (`PRIVATE KEY`, `RSA PRIVATE KEY`,
/// `EC PRIVATE KEY`), or `None` when this `openssl` cannot write it.
fn make_key(dir: &Path, kind: &str) -> Option<(&'static str, PathBuf)> {
    let out = dir.join(format!("{kind}.key"));
    let ok = match kind {
        "rsa-pkcs8" => openssl(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                &format!("{kind}.key"),
            ],
        ),
        "rsa-pkcs1" => {
            openssl(
                dir,
                &[
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                    "tmp-rsa.key",
                ],
            ) && (openssl(
                dir,
                &[
                    "rsa",
                    "-in",
                    "tmp-rsa.key",
                    "-traditional",
                    "-out",
                    &format!("{kind}.key"),
                ],
            ) || openssl(
                dir,
                &["rsa", "-in", "tmp-rsa.key", "-out", &format!("{kind}.key")],
            ))
        }
        "ec-sec1" => openssl(
            dir,
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                &format!("{kind}.key"),
            ],
        ),
        "ec-pkcs8" => {
            openssl(
                dir,
                &[
                    "ecparam",
                    "-name",
                    "prime256v1",
                    "-genkey",
                    "-noout",
                    "-out",
                    "tmp-ec.key",
                ],
            ) && openssl(
                dir,
                &[
                    "pkcs8",
                    "-topk8",
                    "-nocrypt",
                    "-in",
                    "tmp-ec.key",
                    "-out",
                    &format!("{kind}.key"),
                ],
            )
        }
        "ed25519" => openssl(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "ed25519",
                "-out",
                &format!("{kind}.key"),
            ],
        ),
        _ => unreachable!(),
    };
    if !ok {
        return None;
    }
    let want = match kind {
        "rsa-pkcs1" => "BEGIN RSA PRIVATE KEY",
        "ec-sec1" => "BEGIN EC PRIVATE KEY",
        _ => "BEGIN PRIVATE KEY",
    };
    fs::read_to_string(&out)
        .ok()?
        .contains(want)
        .then_some((want, out))
}

fn served_subject(port: u16) -> String {
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

#[test]
fn the_daemon_boots_with_every_kind_of_private_key() {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("SKIP: openssl not available");
        return;
    }
    let mut covered = Vec::new();
    for kind in ["rsa-pkcs8", "rsa-pkcs1", "ec-sec1", "ec-pkcs8", "ed25519"] {
        let dir = std::env::temp_dir().join(format!(
            "zion-pem-{kind}-{}-{}",
            std::process::id(),
            free_port()
        ));
        fs::create_dir_all(&dir).unwrap();
        let Some((label, key)) = make_key(&dir, kind) else {
            eprintln!("SKIP {kind}: this openssl cannot write it");
            continue;
        };
        let cn = format!("{kind}.example");
        let made = openssl(
            &dir,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                &key.to_string_lossy(),
                "-days",
                "1",
                "-subj",
                &format!("/CN={cn}"),
                "-addext",
                &format!("subjectAltName=DNS:{cn}"),
                "-out",
                "cert.pem",
            ],
        );
        assert!(
            made,
            "{kind}: openssl could not make a certificate for its own key"
        );
        let (https_port, d) = (free_port(), dir.to_string_lossy().into_owned());
        fs::write(
            dir.join("zion.toml"),
            format!(
                "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
                 [tls]\ncert_path = \"{d}/cert.pem\"\nkey_path = \"{}\"\nhot_reload = false\n\n\
                 [upstreams]\nbackend = \"http://127.0.0.1:9\"\n\n\
                 [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\n",
                free_port(),
                key.display()
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
        while TcpStream::connect(("127.0.0.1", https_port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "{kind} ({label}): zion never listened: {}",
                fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        let subject = served_subject(https_port);
        assert!(
            subject.contains(&cn),
            "{kind} ({label}): served {subject:?}"
        );
        covered.push(kind);
        let _ = fs::remove_dir_all(&dir);
    }
    assert!(
        covered.len() >= 3,
        "too few key kinds could be made here to say anything: {covered:?}"
    );
    eprintln!("booted with: {covered:?}");
}
