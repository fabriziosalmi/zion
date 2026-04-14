//! Zion benchmark backend — Rust replacement for test-server.go.
//!
//! Pure hyper 1.x, zero-copy pre-generated payloads, no framework overhead.
//! Designed to remove the Go runtime as a bottleneck so benchmarks measure
//! the proxy layer alone.
//!
//! Endpoints mirror the Go backend exactly for compatibility with
//! bench-native.sh and integration tests.

#![allow(clippy::needless_borrow)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::net::SocketAddr;
use std::sync::OnceLock;

// ═══════════════════════════════════════════════════════════════════
// PRE-GENERATED PAYLOADS (zero allocation on hot path)
// ═══════════════════════════════════════════════════════════════════

struct Payloads {
    json_1kb: Bytes,
    json_10kb: Bytes,
    js_4kb: Bytes,
    css_3kb: Bytes,
    html_5kb: Bytes,
    svg_2kb: Bytes,
    png_8kb: Bytes,
    woff2_16kb: Bytes,
    binary_100kb: Bytes,
    health_json: Bytes,
    manifest_json: Bytes,
}

static PAYLOADS: OnceLock<Payloads> = OnceLock::new();

fn payloads() -> &'static Payloads {
    PAYLOADS.get_or_init(|| {
        use rand::Rng;
        let mut rng = rand::rng();

        // 1KB JSON
        let mut items = String::from(r#"{"status":"ok","data":["#);
        for i in 0..10 {
            if i > 0 { items.push(','); }
            items.push_str(&format!(
                r#"{{"id":{},"name":"item-{}","value":{:.2}}}"#,
                i + 1, i + 1, i as f64 * 1.23
            ));
        }
        items.push_str("]}");
        let json_1kb = Bytes::from(items);

        // 10KB JSON
        let mut big = String::from(r#"{"status":"ok","total":100,"data":["#);
        for i in 0..100 {
            if i > 0 { big.push(','); }
            big.push_str(&format!(
                r#"{{"id":{},"name":"item-{}","desc":"{}","val":{}}}"#,
                i, i, "x".repeat(50), i
            ));
        }
        big.push_str("]}");
        let json_10kb = Bytes::from(big);

        // 4KB JS
        let js = format!("/* chunk.js */\n{}", "var x = function() { return 'data'; };\n".repeat(80));
        let js_4kb = Bytes::from(js);

        // 3KB CSS
        let css = format!("/* styles.css */\n{}", "body{margin:0;} .container{display:flex;} .item{padding:1rem;}\n".repeat(40));
        let css_3kb = Bytes::from(css);

        // 5KB HTML
        let rows = "<tr><td>Name</td><td>Value</td><td>Description of item</td></tr>\n".repeat(60);
        let html = format!(
            "<!DOCTYPE html>\n<html><head><title>Zion Dashboard</title></head>\n<body><h1>Dashboard</h1><table>{}</table></body></html>",
            rows
        );
        let html_5kb = Bytes::from(html);

        // 2KB SVG
        let circles = r#"<circle cx="50" cy="50" r="40" fill="blue"/>"#.repeat(20);
        let svg = format!(r#"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">{}</svg>"#, circles);
        let svg_2kb = Bytes::from(svg);

        // 8KB PNG (fake header + random)
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.resize(8192, 0);
        rng.fill(&mut png[8..]);
        let png_8kb = Bytes::from(png);

        // 16KB WOFF2 (fake header + random)
        let mut woff = vec![b'w', b'O', b'F', b'2'];
        woff.resize(16384, 0);
        rng.fill(&mut woff[4..]);
        let woff2_16kb = Bytes::from(woff);

        // 100KB random binary
        let mut bin = vec![0u8; 102400];
        rng.fill(&mut bin[..]);
        let binary_100kb = Bytes::from(bin);

        let health_json = Bytes::from_static(b"{\"status\":\"ok\"}");
        let manifest_json = Bytes::from_static(
            b"{\"name\":\"Zion\",\"version\":\"1.0.0\",\"icons\":[{\"src\":\"/icon.svg\",\"sizes\":\"any\"}]}"
        );

        Payloads {
            json_1kb, json_10kb, js_4kb, css_3kb, html_5kb,
            svg_2kb, png_8kb, woff2_16kb, binary_100kb,
            health_json, manifest_json,
        }
    })
}

// ═══════════════════════════════════════════════════════════════════
// RESPONSE HELPERS (zero-alloc)
// ═══════════════════════════════════════════════════════════════════

type BoxBody = Full<Bytes>;
type Resp = Response<BoxBody>;

#[inline]
fn ok(ct: &'static str, body: Bytes) -> Resp {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", ct)
        .body(Full::new(body))
        .unwrap()
}

#[inline]
fn ok_cached(ct: &'static str, body: Bytes) -> Resp {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", ct)
        .header("Cache-Control", "public, max-age=31536000, immutable")
        .body(Full::new(body))
        .unwrap()
}

#[inline]
fn not_found() -> Resp {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from_static(b"404")))
        .unwrap()
}

// ═══════════════════════════════════════════════════════════════════
// ROUTER (manual match — zero framework overhead)
// ═══════════════════════════════════════════════════════════════════

async fn handle(req: Request<Incoming>) -> Result<Resp, std::convert::Infallible> {
    let p = payloads();
    let path = req.uri().path();

    let resp = match path {
        // ── Dynamic API ──
        "/api/v1/health" => ok("application/json", p.health_json.clone()),
        "/api/v1/data" => ok("application/json", p.json_1kb.clone()),
        "/api/v1/data/large" => ok("application/json", p.json_10kb.clone()),

        "/api/v1/echo" => {
            // Echo back request info as JSON (simplified — no body read for perf)
            let xff = req.headers().get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok()).unwrap_or("");
            let xrip = req.headers().get("X-Real-IP")
                .and_then(|v| v.to_str().ok()).unwrap_or("");
            let body = format!(
                r#"{{"method":"{}","path":"{}","x_forwarded_for":"{}","x_real_ip":"{}"}}"#,
                req.method(), path, xff, xrip
            );
            ok("application/json", Bytes::from(body))
        }

        "/api/v1/users" => {
            Response::builder()
                .status(StatusCode::CREATED)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from_static(b"{\"created\":true}")))
                .unwrap()
        }

        // ── Static files ──
        "/_next/static/chunk.js" | "/_next/static/js/app.js" =>
            ok_cached("application/javascript; charset=utf-8", p.js_4kb.clone()),
        "/_next/static/style.css" | "/_next/static/css/style.css" =>
            ok_cached("text/css; charset=utf-8", p.css_3kb.clone()),
        "/_next/static/icon.svg" =>
            ok_cached("image/svg+xml", p.svg_2kb.clone()),
        "/_next/static/hero.png" | "/_next/static/img/hero.png" =>
            ok_cached("image/png", p.png_8kb.clone()),
        "/_next/static/font.woff2" | "/_next/static/fonts/inter.woff2" =>
            ok_cached("font/woff2", p.woff2_16kb.clone()),
        "/_next/static/manifest.json" =>
            ok_cached("application/json", p.manifest_json.clone()),

        // ── Large binary (configurable size via ?size=N) ──
        "/api/v1/large" | "/_next/static/blob" => {
            let size = req.uri().query()
                .and_then(|q| q.strip_prefix("size="))
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(102400)
                .min(100 * 1024 * 1024);

            let ct = if path.starts_with("/_next") { "application/octet-stream" } else { "application/octet-stream" };
            let cache = if path.starts_with("/_next") {
                Some("public, max-age=31536000, immutable")
            } else {
                None
            };

            // Serve from pre-generated buffer if small enough, otherwise generate
            let body = if size <= p.binary_100kb.len() {
                p.binary_100kb.slice(..size)
            } else {
                Bytes::from(vec![0xAA; size])
            };

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", ct);
            if let Some(cc) = cache {
                builder = builder.header("Cache-Control", cc);
            }
            builder.body(Full::new(body)).unwrap()
        }

        // ── Status code mirror ──
        _ if path.starts_with("/api/v1/status/") => {
            let code = path.rsplit('/').next()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200);
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
            let body = format!(r#"{{"status":{}}}"#, code);
            Response::builder()
                .status(status)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }

        // ── HTML (SSR simulation) — catch-all for / and /page* ──
        "/" | "/page" => ok("text/html; charset=utf-8", p.html_5kb.clone()),

        // ── 404 ──
        _ => {
            // Try matching any /_next/static/* as generic static
            if path.starts_with("/_next/static/") {
                ok_cached("application/octet-stream", p.binary_100kb.slice(..1024))
            } else if path.starts_with("/api/") {
                ok("application/json", p.json_1kb.clone())
            } else {
                ok("text/html; charset=utf-8", p.html_5kb.clone())
            }
        }
    };

    Ok(resp)
}

// ═══════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let addr: SocketAddr = "0.0.0.0:9090".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    eprintln!("rust-bench-backend listening on {}", addr);

    // Pre-initialize payloads
    let _ = payloads();

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => continue,
        };
        let _ = stream.set_nodelay(true);
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let builder = AutoBuilder::new(TokioExecutor::new());
            let _ = builder
                .serve_connection(io, service_fn(handle))
                .await;
        });
    }
}
