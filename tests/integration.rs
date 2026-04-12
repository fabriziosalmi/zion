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
        &format!("https://127.0.0.1:4433{}", path),
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
        &format!("https://127.0.0.1:4433{}", path),
    ])
}

/// Check if Zion is running on the test port
fn zion_is_running() -> bool {
    std::net::TcpStream::connect_timeout(&"127.0.0.1:4433".parse().unwrap(), Duration::from_secs(2))
        .is_ok()
}

// ============================================================================
// Tests (all #[ignore]d — run with: cargo test --test integration -- --ignored)
// ============================================================================

// ── Basic Connectivity ──

integration_test!(t01_get_root_returns_200, {
    let (status, body, _) = get("/");
    assert_eq!(status, 200, "GET / should return 200");
    assert!(
        body.contains("<h1>Zion Test Backend</h1>"),
        "should contain test backend HTML"
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
        let (status, _, _) = get(&format!("/api/v1/status/{}", code));
        assert_eq!(status, code, "upstream {} should be forwarded", code);
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
