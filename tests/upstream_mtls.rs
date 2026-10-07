// SPDX-License-Identifier: Apache-2.0
//! mTLS from zion to an upstream (#503), with the real binary and a backend that REQUIRES a
//! client certificate (`openssl s_server -Verify`), behind a private CA.
//!
//! Unix only, and skipped when `openssl` or `curl` is not installed.
#![cfg(unix)]

use std::fs;
use std::net::TcpStream;
use std::path::Path;
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

fn openssl(args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A CA, and certificates it signed: `server` (for `localhost`) and `client`. Plus
/// `stranger`, a client certificate from another CA, and zion's own listener certificate.
fn pki(dir: &Path) -> bool {
    let p = |f: &str| dir.join(f).to_string_lossy().into_owned();
    let self_signed = |name: &str, cn: &str, exts: &[&str]| {
        let mut args = vec![
            "req".to_string(),
            "-x509".into(),
            "-newkey".into(),
            "rsa:2048".into(),
            "-nodes".into(),
            "-days".into(),
            "1".into(),
            "-subj".into(),
            format!("/CN={cn}"),
            "-keyout".into(),
            p(&format!("{name}.key")),
            "-out".into(),
            p(&format!("{name}.pem")),
        ];
        for e in exts {
            args.push("-addext".into());
            args.push(e.to_string());
        }
        openssl(&args.iter().map(String::as_str).collect::<Vec<_>>())
    };
    let signed = |ca: &str, name: &str, cn: &str, ext: &str| {
        fs::write(dir.join(format!("{name}.ext")), ext).unwrap();
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            &format!("/CN={cn}"),
            "-keyout",
            &p(&format!("{name}.key")),
            "-out",
            &p(&format!("{name}.csr")),
        ]) && openssl(&[
            "x509",
            "-req",
            "-in",
            &p(&format!("{name}.csr")),
            "-CA",
            &p(&format!("{ca}.pem")),
            "-CAkey",
            &p(&format!("{ca}.key")),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &p(&format!("{name}.ext")),
            "-out",
            &p(&format!("{name}.pem")),
        ])
    };
    let ca_exts = [
        "basicConstraints=critical,CA:TRUE",
        "keyUsage=critical,keyCertSign",
    ];
    self_signed("zion", "localhost", &["subjectAltName=DNS:localhost"])
        && self_signed("ca", "upstream-test-ca", &ca_exts)
        && self_signed("other-ca", "some-other-ca", &ca_exts)
        && signed(
            "ca",
            "server",
            "localhost",
            "basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n",
        )
        && signed("ca", "client", "zion-first", "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n")
        && signed("ca", "client2", "zion-second", "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n")
        && signed(
            "other-ca",
            "stranger",
            "stranger",
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n",
        )
}

fn wait_port(port: u16, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "{what} never listened on {port}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `curl -sk` against zion; (status, body).
///
/// HTTP/1.1 on purpose (#592). The backend is `openssl s_server -www`, which delimits its
/// page by closing the connection and, on LibreSSL, closes it WITHOUT a TLS `close_notify`
/// (measured: 300 closes of 300). zion cannot tell that from a truncated response, so it
/// ends the stream with an error after the whole body has been sent. Over HTTP/2 that
/// error is a `RST_STREAM(INTERNAL_ERROR)`: curl exits 92 on every request, and in about
/// 2 % of runs the reset reaches curl before it has delivered the response headers, so the
/// status is `0` although zion logged a 200. Over HTTP/1.1 the status line always comes
/// first. The test is about the client certificate zion presents, not about that framing.
///
/// A status of `0` still means curl got none, and used to be silent: curl's exit code and
/// its own error line are printed then, so they sit next to the assertion that fails.
fn get(https_port: u16, path: &str) -> (u16, String) {
    let out = Command::new("curl")
        .args([
            "-skS",
            "--http1.1",
            "--max-time",
            "10",
            "-w",
            "\n%{http_code}",
        ])
        .arg(format!("https://127.0.0.1:{https_port}{path}"))
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", "0"));
    let status = code.trim().parse().unwrap_or(0);
    if status == 0 {
        eprintln!(
            "curl got no HTTP status for GET {path}: exit {:?}, stderr {:?}, stdout {} byte(s)",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
            out.stdout.len()
        );
    }
    (status, body.to_string())
}

/// The request did not reach the backend: `502` when this request's own handshake was
/// refused, `503` when the health probe had already marked the upstream down.
fn refused(status: u16) -> bool {
    status == 502 || status == 503
}

/// The value of `zion_upstream_up` for the backend, once it is `want` (or what it was last).
fn upstream_up(https_port: u16, backend_port: u16, want: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (_, metrics) = get(https_port, "/metrics");
        let seen = metrics
            .lines()
            .find(|l| l.starts_with("zion_upstream_up") && l.contains(&format!(":{backend_port}")))
            .and_then(|l| l.split_whitespace().last())
            .unwrap_or("?")
            .to_string();
        if seen == want || Instant::now() > deadline {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// `openssl s_server` requiring a client certificate, on a port that is free when it starts.
///
/// `free_port()` frees the port before s_server binds it, so another process can take it in
/// between: seen once in 80 runs on a busy machine ("the mTLS backend never listened"). A
/// backend that exited before listening is started again on a new port, up to five times.
fn start_backend(d: &str) -> (Proc, u16) {
    for _ in 0..5 {
        let port = free_port();
        let child = Command::new("openssl")
            .args(["s_server", "-accept", &port.to_string(), "-www"])
            .args(["-cert", &format!("{d}/server.pem")])
            .args(["-key", &format!("{d}/server.key")])
            .args(["-CAfile", &format!("{d}/ca.pem"), "-Verify", "1"])
            // Without this s_server's verify callback logs a bad certificate and carries on.
            .arg("-verify_return_error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("openssl s_server");
        let mut backend = Proc(child);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            // Listening, and still ours: if the bind failed, a stranger answers the connect.
            let exited = backend.0.try_wait().expect("try_wait").is_some();
            if exited {
                break;
            }
            if TcpStream::connect(("127.0.0.1", port)).is_ok()
                && backend.0.try_wait().expect("try_wait").is_none()
            {
                return (backend, port);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    panic!("openssl s_server never listened, in five tries on five ports");
}

fn zion(dir: &Path, upstream: &str, https_port: u16, log: &str) -> Command {
    let d = dir.to_string_lossy();
    fs::write(
        dir.join("zion.toml"),
        format!(
            "[server]\nlisten_http = \"127.0.0.1:{}\"\nlisten_https = \"127.0.0.1:{https_port}\"\n\n\
             [tls]\ncert_path = \"{d}/zion.pem\"\nkey_path = \"{d}/zion.key\"\nhot_reload = false\n\n\
             [upstream.backend]\n{upstream}\n\n\
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

/// An upstream that requires a client certificate answers zion when zion presents the one
/// it was given, refuses it when zion presents none or a stranger's, and its health probe
/// follows: UP with the certificate, DOWN without. A key that is not the certificate's is a
/// config error. Before #503 the settings were accepted and ignored (then refused): zion
/// never presented a certificate.
#[test]
fn zion_presents_its_client_certificate_to_an_upstream_that_requires_one() {
    let has = |tool: &str| {
        Command::new(tool)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    };
    let dir = std::env::temp_dir().join(format!(
        "zion-upstream-mtls-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&dir).unwrap();
    if !has("curl") || !pki(&dir) {
        eprintln!("SKIP: openssl / curl not available");
        return;
    }
    let d = dir.to_string_lossy().into_owned();
    // The backend: TLS, a certificate from the private CA, and a client certificate from
    // that CA is mandatory (-Verify, capital V).
    let (_backend, backend_port) = start_backend(&d);
    let url = format!("url = \"https://localhost:{backend_port}\"\nca_path = \"{d}/ca.pem\"");
    let run = |upstream: &str, log: &str| {
        let https_port = free_port();
        let child = zion(&dir, upstream, https_port, log)
            .spawn()
            .expect("spawn zion");
        let p = Proc(child);
        wait_port(https_port, "zion");
        (p, https_port)
    };

    // 1. With a certificate the CA signed: the request goes through, the backend's page
    // names the certificate it was shown, and the probe says UP.
    for ext in ["pem", "key"] {
        fs::copy(
            dir.join(format!("client.{ext}")),
            dir.join(format!("live.{ext}")),
        )
        .unwrap();
    }
    let (z, port) = run(
        &format!("{url}\nclient_cert_path = \"{d}/live.pem\"\nclient_key_path = \"{d}/live.key\""),
        "with.log",
    );
    let log = || fs::read_to_string(dir.join("with.log")).unwrap();
    let (status, body) = get(port, "/");
    assert_eq!(status, 200, "{body}\n{}", log());
    assert!(
        body.contains("zion-first"),
        "the backend saw zion's certificate: {body}"
    );
    assert_eq!(
        upstream_up(port, backend_port, "1"),
        "1",
        "the probe presents the certificate too"
    );

    // 1b. Rotation: the same paths now hold another certificate, and the config is
    // reloaded. The client that is already built and pooled presents the old one; the
    // client cache is keyed by the files' contents, so the reload makes a new client and
    // the backend sees the new certificate, without a restart.
    for ext in ["pem", "key"] {
        fs::copy(
            dir.join(format!("client2.{ext}")),
            dir.join(format!("live.{ext}")),
        )
        .unwrap();
    }
    let cfg = fs::read_to_string(dir.join("zion.toml")).unwrap();
    fs::write(dir.join("zion.toml"), format!("{cfg}\n# reload\n")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (status, body) = get(port, "/");
        if status == 200 && body.contains("zion-second") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the renewed certificate is not the one presented after a reload \
             (status {status}, still the first: {}): {}",
            body.contains("zion-first"),
            log()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    drop(z);

    // 2. Without a client certificate: the backend refuses the handshake.
    let (z, port) = run(&url, "without.log");
    assert!(refused(get(port, "/").0), "no certificate, no answer");
    assert_eq!(
        upstream_up(port, backend_port, "0"),
        "0",
        "and the probe marks it down"
    );
    drop(z);

    // 3. With a certificate from another CA: refused as well.
    let (z, port) = run(
        &format!("{url}\nclient_cert_path = \"{d}/stranger.pem\"\nclient_key_path = \"{d}/stranger.key\""),
        "stranger.log",
    );
    assert!(
        refused(get(port, "/").0),
        "a certificate the backend's CA did not sign"
    );
    drop(z);

    // 4. Without the private CA zion does not trust the backend at all (public roots only).
    let (z, port) = run(
        &format!(
            "url = \"https://localhost:{backend_port}\"\n\
             client_cert_path = \"{d}/client.pem\"\nclient_key_path = \"{d}/client.key\""
        ),
        "noca.log",
    );
    assert!(
        refused(get(port, "/").0),
        "the backend's certificate is not publicly trusted"
    );
    drop(z);

    // 5. A key that is not the certificate's: refused at boot, exit 2.
    let status = zion(
        &dir,
        &format!(
            "{url}\nclient_cert_path = \"{d}/client.pem\"\nclient_key_path = \"{d}/zion.key\""
        ),
        free_port(),
        "mismatch.log",
    )
    .status()
    .expect("spawn zion");
    let log = fs::read_to_string(dir.join("mismatch.log")).unwrap();
    assert_eq!(status.code(), Some(2), "{log}");
    assert!(
        log.contains("upstream.backend") && log.contains("does not match"),
        "{log}"
    );
    let _ = fs::remove_dir_all(dir);
}
