//! Shutdown contract: on SIGTERM zion must not sit out the idle timeout of keep-alive
//! connections. An idle connection is closed at once, so a deploy takes as long as the work in
//! flight, not as long as the slowest idle client. Runs the real binary; Unix only (SIGTERM).
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Zion(Child);
impl Drop for Zion {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn an_idle_keep_alive_connection_does_not_delay_shutdown() {
    let (http, https) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("zion-drain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // a throwaway self-signed certificate (the repo tracks no key material); the SAN makes it
    // an X.509 v3 certificate, which rustls requires
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
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("openssl is needed to generate a test certificate");
    assert!(made.status.success(), "openssl failed: {made:?}");
    let cfg = dir.join("zion.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
[server]
listen_http = "127.0.0.1:{http}"
listen_https = "127.0.0.1:{https}"
[tls]
cert_path = "{cert}"
key_path = "{key}"
hot_reload = false
[upstreams]
backend = "http://127.0.0.1:1"
[[route]]
path = "/{{*rest}}"
upstream = "backend"
"#,
            cert = cert.display(),
            key = key.display(),
        )
        .replace('\\', "/"),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_zion"))
        .env("ZION_CONFIG", &cfg)
        .env("ZION_BOOT_FAST", "1")
        .env("ZION_LAST_GASP_PATH", dir.join("gasp.jsonl"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn zion");
    let pid = child.id();
    let mut zion = Zion(child);

    // wait for the listener, then open a keep-alive connection and leave it idle
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut conn = loop {
        match TcpStream::connect(("127.0.0.1", http)) {
            Ok(c) => break c,
            Err(_) => {
                assert!(Instant::now() < deadline, "zion did not start listening");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = conn
        .read(&mut buf)
        .expect("a response on the plain-HTTP listener");
    assert!(n > 0);
    std::thread::sleep(Duration::from_millis(300)); // now idle, kept alive

    let t = Instant::now();
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let exited = loop {
        if let Some(s) = zion.0.try_wait().unwrap() {
            break s;
        }
        assert!(
            t.elapsed() < Duration::from_secs(8),
            "zion was still running {:?} after SIGTERM: the idle connection held the drain",
            t.elapsed()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(exited.success() || exited.code().is_some(), "{exited:?}");
    // the idle connection was closed by zion, not left to time out
    let mut rest = Vec::new();
    let _ = conn.read_to_end(&mut rest);
}
