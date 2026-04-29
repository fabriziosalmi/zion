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
  - title: 233K req/s
    details: Peak throughput on Apple M4 with TLS 1.3 end-to-end. 107K req/s API proxy, 103K with full WAF pipeline active (CV 0.5%). Zero errors.
  - title: Zero-Regex WAF
    details: Aho-Corasick automaton in a single O(N) pass over the body. Two pattern sets — balanced (default, ~120 high-precision patterns) and aggressive (opt-in, +~70 broad-substring patterns). Per-profile entropy gate (default 6.5 bits/byte, JSON-string-aware).
  - title: Two-Level Cache
    details: "L1 thread-local with O(1) LRU (intrusive doubly-linked list) + L2 shared DashMap. Generation-based coherence. Watch-channel singleflight (race-free even when the fetcher completes between subscribe and await)."
  - title: TLS 1.3 + Hot-Reload
    details: rustls + hardware crypto (AES-NI/NEON). Multi-SNI, session tickets, 0-RTT. Certificate hot-reload via ArcSwap with zero downtime.
  - title: HTTP/1.1 + H2 + H3
    details: Full protocol support including HTTP/2 upstream multiplexing, WebSocket proxy, SSE streaming, HTTP/3 QUIC (feature-gated). ACME auto-renewal.
  - title: Prometheus Native
    details: "/metrics, /healthz, /readyz built-in. Lock-free sharded counters, differential latency histograms. X-Request-ID + W3C traceparent propagation."
  - title: Hardware-Aware
    details: "Auto-detects CPU cores, L1d cache, AES-NI/NEON. Pins workers to cores. TCP_FASTOPEN, TCP_CORK, SO_REUSEPORT, SO_BUSY_POLL, io_uring."
  - title: Single Binary, TOML Config
    details: "No runtime dependencies. ~4MB release binary. Validates config at startup. Graceful shutdown with 30s drain. systemd + Docker ready."
---

<div class="benchmark-highlight">

## Performance at a Glance

<div class="stat-grid">
  <div class="stat-card">
    <div class="number">233K</div>
    <div class="label">req/s HTML (TLS 1.3)</div>
  </div>
  <div class="stat-card">
    <div class="number">210K</div>
    <div class="label">req/s cache hit</div>
  </div>
  <div class="stat-card">
    <div class="number">107K</div>
    <div class="label">req/s API proxy</div>
  </div>
  <div class="stat-card">
    <div class="number">103K</div>
    <div class="label">req/s WAF POST</div>
  </div>
</div>

Native benchmark on Apple M4, 5 runs x 10s, c=100. Rust backend. Tracked per-commit in [bench-history.json](https://github.com/fabriziosalmi/zion/blob/master/benchmarks/bench-history.json). [Full results](/benchmarks/)

</div>

## Why Zion?

|  | nginx | HAProxy | Envoy | Caddy | Traefik | Pingora | **Zion** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Language | C | C | C++ | Go | Go | Rust | **Rust** |
| Memory safety | No | No | No | GC | GC | Yes | **Yes** |
| Built-in WAF | No | No | No | No | No | No | **Aho-Corasick, dual-mode** |
| RAM cache | No | Yes | No | No | No | No | **L1+L2** |
| TLS hot-reload | Signal | Signal | xDS | Auto | File watch | Custom | **ArcSwap** |
| Config format | Custom | Custom | YAML/xDS | JSON/API | YAML/API | Rust code | **TOML** |
| Binary size | ~1.5MB | ~3MB | ~40MB | ~40MB | ~100MB | Library | **~4MB** |
| Singleflight | No | No | No | No | No | No | **Yes** |
| HTTP/3 QUIC | Patch | No | Yes | Yes | Yes | No | **Feature-gated** |
| JWT/OIDC auth | No | No | Yes | Yes | Yes | No | **Feature-gated** |

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

[Full configuration reference](/config/)
