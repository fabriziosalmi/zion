// SPDX-License-Identifier: Apache-2.0
//! `[tls] session_tickets` on the wire: the real binary, and the number of `NewSessionTicket`
//! messages a TLS 1.3 client actually receives after a full handshake.
//!
//! The default is 2 (it was 4: each extra ticket is about 25 µs of server CPU per full
//! handshake, measured), the key raises or lowers it, and 0 sends none.
//!
//! The client is a real rustls client whose session store counts the tickets it is handed (one
//! `insert_tls13_ticket` per `NewSessionTicket`), so no `openssl` version has to print them.
//!
//! Unix only, and skipped when `openssl` is not installed (it makes the certificate).
#![cfg(unix)]

use std::fs;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::NamedGroup;

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

/// A listener that accepts and says nothing: the route needs an upstream to exist, the handshake
/// never reaches it.
fn idle_upstream() -> u16 {
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || for _ in l.incoming() {});
    port
}

fn start(dir: &Path, tickets_line: &str, upstream: u16) -> (Proc, u16) {
    let https_port = free_port();
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
             [tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nhot_reload = false\n{tickets_line}\n\n\
             [upstreams]\nbackend = \"http://127.0.0.1:{upstream}\"\n\n\
             [[route]]\npath = \"/{{*rest}}\"\nupstream = \"backend\"\nmode = \"standard\"\n",
            free_port(),
            dir.join("c.pem").to_string_lossy(),
            dir.join("k.pem").to_string_lossy()
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
        assert!(Instant::now() < deadline, "zion never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    (z, https_port)
}

/// A client session store that only counts the TLS 1.3 tickets it is given.
#[derive(Debug, Default)]
struct CountingStore(AtomicUsize);
impl ClientSessionStore for CountingStore {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}
    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }
    fn set_tls12_session(&self, _: ServerName<'static>, _: Tls12ClientSessionValue) {}
    fn tls12_session(&self, _: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }
    fn remove_tls12_session(&self, _: &ServerName<'static>) {}
    fn insert_tls13_ticket(&self, _: ServerName<'static>, _: Tls13ClientSessionValue) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn take_tls13_ticket(&self, _: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        None
    }
}

/// Complete a TLS 1.3 handshake against `port` and count the tickets the server sends after it.
fn tickets_received(dir: &Path, port: u16) -> usize {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&fs::read(dir.join("c.pem")).unwrap()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let store = Arc::new(CountingStore::default());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.resumption = rustls::client::Resumption::store(store.clone());
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    // The tickets follow the server's Finished; a read timeout is how this loop learns that the
    // server has nothing more to say.
    tcp.set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    loop {
        while conn.wants_write() {
            conn.write_tls(&mut tcp).unwrap();
        }
        match conn.read_tls(&mut tcp) {
            Ok(0) => break,
            Ok(_) => {
                conn.process_new_packets()
                    .expect("a valid TLS 1.3 handshake");
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(e) => panic!("read: {e}"),
        }
    }
    assert!(!conn.is_handshaking(), "the handshake did not complete");
    store.0.load(Ordering::SeqCst)
}

#[test]
fn session_tickets_are_two_by_default_and_the_key_changes_it() {
    let dir = std::env::temp_dir().join(format!(
        "zion-tickets-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
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
        // a self-signed certificate is a CA by default; rustls refuses a CA as a server certificate
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-keyout",
        &dir.join("k.pem").to_string_lossy(),
        "-out",
        &dir.join("c.pem").to_string_lossy(),
    ]);
    if !made {
        eprintln!("SKIP: openssl could not make a certificate");
        return;
    }
    let upstream = idle_upstream();
    let mut seen = Vec::new();
    for (line, want) in [
        ("", 2),                      // the default
        ("session_tickets = 5\n", 5), // raised
        ("session_tickets = 0\n", 0), // none
    ] {
        let (_z, port) = start(&dir, line, upstream);
        let got = tickets_received(&dir, port);
        seen.push((line, got));
        assert_eq!(got, want, "`{}`: {got} tickets on the wire", line.trim());
    }
    eprintln!("tickets on the wire: {seen:?}");
    let _ = fs::remove_dir_all(dir);
}
