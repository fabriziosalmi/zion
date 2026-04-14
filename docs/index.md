---
layout: home
hero:
  name: Zion
  text: Edge Gateway
  tagline: High-performance TLS reverse proxy with built-in WAF. Written in Rust. Single binary. Zero dependencies.
  image:
    src: /logo.svg
    alt: Zion Edge Gateway
  actions:
    - theme: brand
      text: Get Started
      link: /guide/quickstart
    - theme: alt
      text: View Benchmarks
      link: /benchmarks/
    - theme: alt
      text: GitHub
      link: https://github.com/fabriziosalmi/zion

features:
  - icon: "\u26A1"
    title: 235K req/s
    details: Peak throughput on Apple M4 with TLS 1.3 end-to-end. 106K req/s API proxy, 103K with full WAF pipeline active. Zero errors.
  - icon: "\uD83D\uDEE1\uFE0F"
    title: Zero-Regex WAF
    details: 80+ injection patterns (SQLi, XSS, CMDi, SSRF, Log4Shell) scanned in a single O(N) Aho-Corasick pass. SIMD pre-filter skips clean traffic.
  - icon: "\uD83D\uDDC3\uFE0F"
    title: Two-Level Cache
    details: "L1 thread-local (~5ns, O(1) LRU) + L2 shared DashMap (~30ns). Generation-based coherence. Singleflight coalescing prevents thundering herd."
  - icon: "\uD83D\uDD12"
    title: TLS 1.3 + Hot-Reload
    details: rustls + hardware crypto (AES-NI/NEON). Multi-SNI, session tickets, 0-RTT. Certificate hot-reload via ArcSwap with zero downtime.
  - icon: "\uD83C\uDF10"
    title: HTTP/1.1 + H2 + H3
    details: Full protocol support including WebSocket proxy, SSE streaming, HTTP/3 QUIC (feature-gated). ACME auto-renewal for Let's Encrypt.
  - icon: "\uD83D\uDCCA"
    title: Prometheus Native
    details: "/metrics, /healthz, /readyz built-in. Lock-free sharded counters, latency histograms. X-Request-ID + W3C traceparent propagation."
  - icon: "\u2699\uFE0F"
    title: Hardware-Aware
    details: "Auto-detects CPU cores, L1d cache, AES-NI/NEON. Pins workers to cores. TCP_FASTOPEN, SO_REUSEPORT, io_uring multishot accept."
  - icon: "\uD83D\uDCC4"
    title: Single Binary, TOML Config
    details: "No runtime dependencies. ~4MB release binary. Validates config at startup. Graceful shutdown with 30s drain. systemd + Docker ready."
---

<div class="benchmark-highlight">

## Performance at a Glance

<div class="stat-grid">
  <div class="stat-card">
    <div class="number">235K</div>
    <div class="label">req/s HTML (TLS 1.3)</div>
  </div>
  <div class="stat-card">
    <div class="number">211K</div>
    <div class="label">req/s cache hit</div>
  </div>
  <div class="stat-card">
    <div class="number">106K</div>
    <div class="label">req/s API proxy</div>
  </div>
  <div class="stat-card">
    <div class="number">103K</div>
    <div class="label">req/s WAF POST</div>
  </div>
</div>

Native benchmark on Apple M4, 5 runs x 10s, c=100. Rust backend. [Full results &rarr;](/benchmarks/)

</div>

## Why Zion?

|  | nginx | Envoy | Traefik | **Zion** |
|---|:---:|:---:|:---:|:---:|
| Language | C | C++ | Go | **Rust** |
| Memory safety | No | No | GC | **Compile-time** |
| Built-in WAF | No | No | No | **80+ patterns** |
| RAM cache | No | No | No | **L1+L2** |
| TLS hot-reload | Signal | xDS | File watch | **ArcSwap** |
| Config | Custom | YAML/xDS | YAML/API | **TOML** |
| Binary size | ~1.5MB | ~40MB | ~100MB | **~4MB** |
| Request coalescing | No | No | No | **Singleflight** |
| HTTP/3 QUIC | Patch | Yes | Yes | **Feature-gated** |

## Quick Start

```bash
cargo build --release
ZION_CONFIG=zion.toml ./target/release/zion
```

```toml
[server]
listen_https = "0.0.0.0:443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"
key_path = "/etc/ssl/zion/tls.key"

[upstreams]
backend = "http://127.0.0.1:8000"

[[route]]
path = "/api/{*rest}"
upstream = "backend"
waf = true
```

[Full configuration reference &rarr;](/config/)
