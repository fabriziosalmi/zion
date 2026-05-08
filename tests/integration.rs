// SPDX-License-Identifier: Apache-2.0
//! Zion Edge Gateway — Integration Tests
//!
//! Validates the full proxy stack end-to-end:
//! - HTTP→HTTPS redirect
//! - TLS termination & proxy pass (GET, POST, PUT, DELETE)
//! - Forwarding headers (X-Forwarded-For, X-Real-IP, X-Forwarded-Proto)
//! - WAF (valid JSON allowed, malformed rejected)
//! - Cache (hit vs miss, Content-Type preservation)
//! - SSE streaming
//! - Large responses
//! - Internal-only routes
//! - Error code forwarding
//! - Host header validation
//!
//! Prerequisites: running Zion on :4433 + test backend on :9090
//! Setup: ZION_CONFIG=tests/zion-test.toml ./target/release/zion
//!        cd benchmarks/backend && go run test-server.go
//!
//! Run:   cargo test --test integration -- --ignored --test-threads=1
//!
//! All tests are #[ignore]d by default so `cargo test` only runs unit tests.

use std::process::Command;
use std::time::Duration;

/// Macro to add the common `#[ignore]` + skip-if-not-running guard.
macro_rules! integration_test {
    ($name:ident, $body:block) => {
        #[test]
        #[ignore]
        fn $name() {
            if !zion_is_running() {
                eprintln!("SKIP: Zion not running on 127.0.0.1:4433");
                return;
            }
            $body
        }
    };
}

/// Simple HTTP client wrapper using curl (avoids adding reqwest dep).
/// Returns (status_code, body, headers).
fn curl(args: &[&str]) -> (u16, String, String) {
    let mut cmd = Command::new("curl");
    cmd.arg("-sk") // silent + insecure (self-signed cert)
        .arg("--max-time")
        .arg("10")
        .arg("-D")
        .arg("/dev/stderr") // headers to stderr
        .args(args);

    let output = cmd.output().expect("curl not found");
    let body = String::from_utf8_lossy(&output.stdout).to_string();
    let headers = String::from_utf8_lossy(&output.stderr).to_string();

    // Extract status code from header line "HTTP/... 200 ..."
    let status = headers
        .lines()
        .find(|l| l.starts_with("HTTP/"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    (status, body, headers)
}

/// Shorthand: GET with Host header
fn get(path: &str) -> (u16, String, String) {
    curl(&[
        "-H",
        "Host: bench.local",
        &format!("https://127.0.0.1:4433{path}"),
    ])
}

/// Shorthand: POST JSON with Host header
fn post_json(path: &str, body: &str) -> (u16, String, String) {
    curl(&[
        "-X",
        "POST",
        "-H",
        "Host: bench.local",
        "-H",
        "Content-Type: application/json",
        "-d",
        body,
        &format!("https://127.0.0.1:4433{path}"),
    ])
}

/// Check if Zion is running on the test port
fn zion_is_running() -> bool {
    std::net::TcpStream::connect_timeout(&"127.0.0.1:4433".parse().unwrap(), Duration::from_secs(2))
        .is_ok()
}

/// Write `bytes` to a tempfile and return its path. Used by the streaming
/// WAF tests (issue #49) to ship MB-scale bodies into curl via `-d @path`
/// — passing them as argv arguments trips `ArgumentListTooLong` (ARG_MAX)
/// on the CI runner.
fn write_tempfile(prefix: &str, bytes: &[u8]) -> std::path::PathBuf {
    use std::io::Write;
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("{prefix}-{nanos}.bin"));
    let mut f = std::fs::File::create(&path).expect("create tempfile");
    f.write_all(bytes).expect("write tempfile");
    f.sync_all().expect("sync tempfile");
    path
}

// ============================================================================
// Tests (all #[ignore]d — run with: cargo test --test integration -- --ignored)
// ============================================================================

// ── Basic Connectivity ──

integration_test!(t01_get_root_returns_200, {
    let (status, body, _) = get("/");
    assert_eq!(status, 200, "GET / should return 200");
    // Both the Go and Rust test backends serve a "Dashboard" HTML stub.
    // The earlier "Zion Test Backend" string was stale (no backend ever
    // emitted it) and only survived because the test was #[ignore]d.
    assert!(
        body.contains("<h1>Dashboard</h1>"),
        "should contain backend dashboard HTML, got: {body}"
    );
});

// ── API Proxy ──

integration_test!(t02_api_get_returns_json, {
    let (status, body, _) = get("/api/v1/data");
    assert_eq!(status, 200);
    assert!(
        body.contains("\"status\":\"ok\""),
        "API should return JSON with status:ok"
    );
});

integration_test!(t03_api_health_check, {
    let (status, body, _) = get("/api/v1/health");
    assert_eq!(status, 200);
    assert!(body.contains("\"status\":\"ok\""));
});

// ── Forwarding Headers ──

integration_test!(t04_forwarding_headers, {
    let (_, body, _) = get("/api/v1/echo");
    assert!(
        body.contains("\"x_forwarded_for\":\"127.0.0.1\""),
        "X-Forwarded-For missing"
    );
    assert!(
        body.contains("\"x_real_ip\":\"127.0.0.1\""),
        "X-Real-IP missing"
    );
    assert!(
        body.contains("\"x_forwarded_proto\":\"https\""),
        "X-Forwarded-Proto missing"
    );
});

// ── WAF ──

integration_test!(t05_waf_valid_json_passes, {
    let (status, _, _) = post_json("/api/v1/users", r#"{"username":"test","email":"t@t.com"}"#);
    assert_eq!(status, 201, "valid JSON POST should pass WAF");
});

integration_test!(t06_waf_malformed_json_rejected, {
    let (status, _, _) = post_json("/api/v1/users", r#"{"broken json"#);
    assert_eq!(status, 400, "malformed JSON should be rejected by WAF");
});

integration_test!(t07_waf_missing_content_type_rejected, {
    let (status, _, _) = curl(&[
        "-X",
        "POST",
        "-H",
        "Host: bench.local",
        "-d",
        r#"{"data":"test"}"#,
        "https://127.0.0.1:4433/api/v1/users",
    ]);
    assert_eq!(status, 400, "POST without Content-Type should be rejected");
});

integration_test!(t08_waf_valid_put_passes, {
    let (status, _, _) = curl(&[
        "-X",
        "PUT",
        "-H",
        "Host: bench.local",
        "-H",
        "Content-Type: application/json",
        "-d",
        r#"{"update":true}"#,
        "https://127.0.0.1:4433/api/v1/users",
    ]);
    assert_eq!(status, 201, "valid PUT should pass WAF");
});

// ── Streaming WAF (issue #49) ─────────────────────────────────────────────
// Routes under /stream/* use `waf_profile = "streamed"` (streaming = true).
// The dispatch path feeds each frame to a StreamingScanner; attack patterns
// in the first chunk deny without reading the rest of the upload.

integration_test!(t08a_stream_waf_clean_post_passes, {
    // Small, clean text/plain body must pass the streaming gate AND the
    // buffered re-validation that runs on the assembled body.
    let (status, _, _) = curl(&[
        "-X",
        "POST",
        "-H",
        "Host: bench.local",
        "-H",
        "Content-Type: text/plain",
        "-d",
        "hello from a normal client; nothing suspicious here",
        "https://127.0.0.1:4433/stream/echo",
    ]);
    assert!(
        matches!(status, 200..=299),
        "clean streaming POST should reach upstream, got {status}"
    );
});

integration_test!(t08b_stream_waf_attack_first_chunk_denies, {
    // Inject a known WAF pattern (`<script>`) at the very start of the body.
    // The streaming scanner must deny on chunk #1 — well before a 10MB
    // upload would finish. We don't measure wall-clock here (CI noise),
    // but the upload completes well under any reasonable buffered
    // baseline because the deny short-circuits the body read.
    //
    // Bodies in the MB range are written to a tempfile and passed via
    // `-d @path` — argv-passing trips ARG_MAX on tighter CI runners.
    let mut payload = String::with_capacity(1_048_576);
    payload.push_str("<script>alert(1)</script>");
    while payload.len() < 1_048_576 {
        payload.push_str("padding ");
    }
    let path = write_tempfile("zion-stream-attack", payload.as_bytes());
    let body_arg = format!("@{}", path.display());
    let (status, _, _) = curl(&[
        "-X",
        "POST",
        "-H",
        "Host: bench.local",
        "-H",
        "Content-Type: text/plain",
        "--data-binary",
        &body_arg,
        "https://127.0.0.1:4433/stream/echo",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status, 400,
        "attack pattern in first chunk must deny on the streaming path"
    );
});

integration_test!(t08c_stream_waf_oversize_body_denies, {
    // Streaming scanner enforces the size cap incrementally. Build a body
    // that exceeds `max_body_mb = 10` and expect deny — buffered path
    // returns 413 (PAYLOAD_TOO_LARGE) via `Limited`; streaming path
    // returns 400 because `StreamVerdict::Deny("body exceeds max size")`
    // is treated as a WAF deny. Both are correct rejections; the test
    // asserts on the 4xx class so either path passes.
    let big = vec![b'A'; 11 * 1024 * 1024];
    let path = write_tempfile("zion-stream-oversize", &big);
    let body_arg = format!("@{}", path.display());
    let (status, _, _) = curl(&[
        "-X",
        "POST",
        "-H",
        "Host: bench.local",
        "-H",
        "Content-Type: text/plain",
        "--data-binary",
        &body_arg,
        "https://127.0.0.1:4433/stream/echo",
    ]);
    let _ = std::fs::remove_file(&path);
    assert!(
        (400..=499).contains(&status),
        "oversize body must be rejected with a 4xx, got {status}"
    );
});

// ── Static Cache ──

integration_test!(t09_static_cache_serves_asset, {
    let (status, body, headers) = get("/_next/static/chunk.js");
    assert_eq!(status, 200);
    assert!(body.contains("chunk.js"), "should serve static asset");
    assert!(
        headers.to_lowercase().contains("immutable"),
        "should have Cache-Control immutable"
    );
});

integration_test!(t10_static_cache_returns_same_content, {
    let (_, body1, _) = get("/_next/static/chunk.js");
    let (_, body2, _) = get("/_next/static/chunk.js");
    assert_eq!(body1, body2, "cached response should match original");
});

// ── SSE Streaming ──

integration_test!(t11_sse_stream_returns_events, {
    let (_, body, _) = curl(&[
        "--max-time",
        "5",
        "-H",
        "Host: bench.local",
        "https://127.0.0.1:4433/api/v1/events/stream",
    ]);
    assert!(body.contains("event: tick"), "SSE should contain events");
    assert!(body.contains("\"seq\":"), "SSE events should have seq data");
});

// ── Query String ──

integration_test!(t12_query_string_preserved, {
    let (_, body, _) = get("/api/v1/echo?foo=bar&page=2");
    assert!(body.contains("foo=bar"), "query string should be preserved");
});

// ── Large Response ──

integration_test!(t13_large_response_512kb, {
    let (status, body, _) = get("/api/v1/large?size=524288");
    assert_eq!(status, 200);
    assert!(
        body.len() >= 500_000,
        "large response should be >= 500KB, got {} bytes",
        body.len()
    );
});

// ── Error Code Forwarding ──

integration_test!(t14_error_codes_forwarded, {
    for code in [200u16, 201, 400, 404, 500, 503] {
        let (status, _, _) = get(&format!("/api/v1/status/{code}"));
        assert_eq!(status, code, "upstream {code} should be forwarded");
    }
});

// ── Edge Cases ──

integration_test!(t15_catch_all_route, {
    let (status, _, _) = get("/random/unknown/path");
    assert_eq!(status, 200, "catch-all route should handle unknown paths");
});

// ── Security Headers ──

integration_test!(t16_security_headers_present, {
    let (_, _, headers) = get("/");
    let h = headers.to_lowercase();
    assert!(h.contains("strict-transport-security"), "HSTS missing");
    assert!(
        h.contains("x-content-type-options"),
        "X-Content-Type-Options missing"
    );
    assert!(h.contains("x-frame-options"), "X-Frame-Options missing");
    assert!(h.contains("referrer-policy"), "Referrer-Policy missing");
    assert!(!h.contains("server:"), "Server header should be stripped");
});

// ── Health Endpoints ──

integration_test!(t17_healthz_returns_200, {
    let (status, body, _) = curl(&["-H", "Host: bench.local", "https://127.0.0.1:4433/healthz"]);
    assert_eq!(status, 200);
    assert!(body.contains("ok"), "/healthz should return ok");
});

integration_test!(t18_readyz_returns_200, {
    let (status, _, _) = curl(&["-H", "Host: bench.local", "https://127.0.0.1:4433/readyz"]);
    assert_eq!(status, 200);
});

// ── HTTP → HTTPS Redirect ──

integration_test!(t19_http_redirects_to_https, {
    let (status, _, headers) = curl(&[
        "-o",
        "/dev/null",
        "-H",
        "Host: bench.local",
        "http://127.0.0.1:8080/",
    ]);
    assert_eq!(status, 301, "HTTP should redirect to HTTPS");
    assert!(
        headers.to_lowercase().contains("location: https://"),
        "should redirect to https://"
    );
});

// ── Unified-port co-existence (issue #53) ──────────────────────────────────
//
// The `bpf-demux` track (issue #53) requires TCP HTTPS and UDP QUIC to
// coexist on the same port without conflict. This is a kernel-level
// invariant — TCP and UDP are independent L4 protocols and the kernel
// demuxes them before port routing — but the test pins the *Zion-side*
// half: the daemon binds both listeners cleanly and TCP requests
// continue to work even when the QUIC listener is also active.
//
// The test is intentionally weak about the QUIC side: a real
// end-to-end QUIC client requires `--features http3` on the binary
// AND an h3-capable curl in the runner, neither of which the
// integration workflow ships today. What the test DOES prove:
//
//   * TCP HTTPS on :4433 works (a real GET reaches upstream).
//   * Probing UDP :4433: when zion was built with `--features http3`,
//     the local-bind probe trips `EADDRINUSE` (the QUIC listener
//     occupies the port). The test logs the observed mode so a CI
//     log shows the operator which path was exercised; the assertion
//     itself is OS-portable and tolerates either outcome.
//
// Closing the QUIC end-to-end gap is tracked as a follow-up: enable
// `--features http3` in `.github/workflows/integration.yml` and use
// an h3-capable client.

integration_test!(t30_unified_port_tcp_works_with_or_without_quic, {
    use std::net::UdpSocket;

    // 1. TCP path: must succeed regardless of the http3 feature.
    let (status, body, _) = get("/api/v1/data");
    assert_eq!(status, 200, "TCP HTTPS path must work on :4433");
    assert!(
        body.contains("\"status\":\"ok\""),
        "API should return 200/ok"
    );

    // 2. UDP probe: try to bind UDP on :4433 ourselves. The two
    //    legitimate outcomes:
    //
    //      a) `EADDRINUSE` — zion's QUIC listener already holds the
    //         port. Confirms TCP+UDP coexistence is observable.
    //      b) `Ok(_)` — no UDP listener. Means the binary under test
    //         was compiled without `--features http3` (current CI
    //         default). The TCP-only assertion above is the
    //         meaningful signal in this mode.
    //
    //    Anything else (PermissionDenied, AddrNotAvailable on the
    //    address itself) is a setup error worth flagging.
    match UdpSocket::bind("127.0.0.1:4433") {
        Ok(sock) => {
            // No QUIC listener observable. Drop the socket immediately
            // so we don't lock the port for the rest of the suite.
            drop(sock);
            eprintln!(
                "t30: UDP :4433 was free — zion compiled without `--features http3`. \
                 TCP-only mode validated."
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!(
                "t30: UDP :4433 reports EADDRINUSE — zion's QUIC listener active. \
                 TCP+UDP unified-port co-existence validated."
            );
        }
        Err(other) => {
            panic!("t30: unexpected UDP-bind error on :4433: {other:?}");
        }
    }
});
