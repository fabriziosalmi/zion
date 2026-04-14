# Zion Edge Gateway

[![CI](https://github.com/fabriziosalmi/zion/actions/workflows/ci.yml/badge.svg)](https://github.com/fabriziosalmi/zion/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/release/fabriziosalmi/zion?include_prereleases&color=blue&label=release)](https://github.com/fabriziosalmi/zion/releases)
[![License](https://img.shields.io/github/license/fabriziosalmi/zion)](https://github.com/fabriziosalmi/zion/blob/master/LICENSE)
[![Performance](https://img.shields.io/badge/Performance-233k%20req%2Fs-success?style=flat&color=brightgreen)](https://github.com/fabriziosalmi/zion/tree/master/benchmarks)
[![WAF](https://img.shields.io/badge/WAF-Zero%20Regex-orange)](https://github.com/fabriziosalmi/zion/blob/master/src/waf.rs)

High-performance TLS reverse proxy with built-in WAF, written in Rust.

## Performance

### Throughput Matrix (Apple M4, TLS 1.3, wrk, 3 rounds × 5s)

Payload × concurrency grid — measures end-to-end TLS throughput through the full proxy stack.

| Mode | Payload | c=1 | c=10 | c=100 |
|---|---|---|---|---|
| **Dynamic** (Go backend) | 1 MB | 2,067 | 3,491 | 3,138 |
| | 10 MB | 323 | 406 | 203 |
| | 100 MB | 9,334 | 22,758 | 18,865 |
| **Static** (uncached proxy) | 1 MB | 14,328 | 35,543 | 46,416 |
| | 10 MB | 11,889 | 41,116 | 53,144 |
| | 100 MB | 15,669 | 46,118 | 39,295 |
| **Cached RAM** (L1+L2) | 1 MB | 30,247 | 88,181 | **140,301** |
| | 10 MB | 33,781 | 80,246 | 123,936 |
| | 100 MB | 36,067 | 90,091 | 96,706 |

**Peak**: 233K req/s HTML (5KB) · 209K cache hit · 92K WAF POST · 6.7 GB/s TLS throughput

### Native Benchmark (Apple M4, 5 runs x 10s, c=100)

| Endpoint | Median req/s | Best Run | CV% | Errors |
|----------|-------------|----------|-----|--------|
| HTML SSR 5KB | **233,341** | 236,755 | 2.0% | 0 |
| Cache Hit JS 4KB (RAM) | **209,381** | 214,546 | 9.8% | 0 |
| CSS 3KB (cached) | **191,574** | 203,969 | 4.5% | 0 |
| TLS Proxy API GET 1KB | **93,253** | 97,019 | 3.0% | 0 |
| WAF POST JSON | **91,893** | 93,415 | 3.1% | 0 |
| JS 4KB (no cache) | **81,470** | 82,723 | 2.3% | 0 |
| PNG 8KB (no cache) | **66,753** | 68,020 | 2.7% | 0 |
| WOFF2 16KB (no cache) | **59,262** | 60,679 | 3.0% | 0 |
| SQLi blocked | Yes (400) | | | |
| XSS blocked | Yes (400) | | | |

Reproduce: `bash benchmarks/bench-native.sh`

<details>
<summary>Bottleneck analysis</summary>

- **Dynamic 10 MB ≈ 300 req/s**: Go backend generates payload at runtime → CPU-bound in Go
- **Cached 1 MB c=100 → 140K req/s = 140 GB/s pre-TLS, 6.7 GB/s post-TLS**: rustls encryption is the ceiling
- **Cached 1 KB c=100 → 141K req/s**: With small payloads, TLS record overhead dominates — req/s is similar
- **Static vs Cached (2.5–3x speedup)**: Cache eliminates upstream round-trip + TCP overhead

</details>

### Fair Comparison with nginx (Docker, 1 CPU, 256 MB)

| Endpoint | nginx 1.27 | Zion TLS | Zion WAF | Zion Full | Best Δ | Errors |
|---|---|---|---|---|---|---|
| API GET (1KB) | 29,404 | 27,517 | 27,438 | 27,537 | -6.3% | 0 |
| HTML (5KB) | 25,657 | 52,581 | 53,016 | 53,368 | **+108.0%** | 0 |
| JS (4KB) | 23,152 | 18,165 | 18,037 | 32,366 | **+39.8%** | 0 |
| PNG (8KB) | 17,409 | 13,411 | 14,345 | 24,770 | **+42.3%** | 0 |
| WAF POST | 27,772 | 26,173 | 25,653 | 26,909 | -3.1% | 0 |
| CSS cached | 27,436 | 16,800 | 14,949 | 25,111 | -8.5% | 0 |

Full methodology: `bash benchmarks/bench-scientific.sh` (5 runs, CI95). 
📥 **[Download the Official Scientific Benchmark Report v0.1.0 (PDF)](docs/benchmarks/Zion-v0.1.0-Scientific-Report.pdf)**

## Features

**Core Proxy**
- TLS 1.3 termination (rustls + aws-lc-rs hardware crypto)
- Multi-SNI with per-domain certificates + FNV hash lookup
- Zero-downtime TLS & QUIC hot-reload (ArcSwap + watch channels)
- Session tickets + 0-RTT early data with method gating (425 Too Early, RFC 8470)
- ACME auto-renewal via `instant-acme` (HTTP-01, `--features acme`)
- Thread-local SNI cache with generation tracking
- Predictive cert pre-warming (auto-renew 120s before expiry)
- HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC) support with unified security pipeline
- WebSocket proxy (HTTP Upgrade + bidirectional pipe, TLS-to-upstream)
- SSE streaming proxy (zero-buffer)
- Two-level RAM cache: L1 thread-local (~5ns, O(1) LRU) + L2 DashMap (~30ns)
- L1/L2 generation-based coherence (no stale data after cache update)
- Request coalescing (singleflight): N concurrent cache misses = 1 upstream fetch
- L2 eviction: expired-first, then oldest-TTL fallback
- Radix tree routing (~30ns lookup)
- Parallel Background Health Checks (O(1) blocking via `tokio::task::JoinSet`)
- Modular Dispatch Architecture (zero-allocation hot paths)
- io_uring multishot accept (Linux, feature-gated)

**WAF (Zero-Regex, O(N) Single-Pass)**
- Aho-Corasick scanner: 80+ patterns (SQLi, XSS, CMDi, SSRF, Log4Shell)
- SIMD pre-filter: memchr3 fast-reject before Aho-Corasick (skips clean bodies)
- Shannon entropy analysis (detect obfuscated payloads)
- simd-json structural validation
- Depth + string length enforcement
- Content-Type strict validation
- Body size enforcement

**Security (Zero Latency)**
- HSTS, X-Content-Type-Options, X-Frame-Options
- Referrer-Policy, Permissions-Policy
- Per-route Content-Security-Policy
- Server header stripped
- URI length limit (8 KB), method whitelist
- TLS handshake timeout (10s), HTTP request timeout (60s)
- Header bomb prevention (64 headers, 32 KB max)
- Per-IP rate limiting (atomic, lock-free, configurable)
- Hop-by-hop header stripping (RFC 7230)
- CORS (configurable origins, pre-flight OPTIONS)

**Observability**
- `/healthz`, `/readyz` (Kubernetes probes)
- `/metrics` (Prometheus text format, 11 counters)
- `X-Request-ID` (auto-generated or client-preserved)
- Structured logging (text or JSON)

**Operations**
- Config validation at startup (fail fast)
- Graceful drain on shutdown (30s timeout)
- Upstream health checking (30s interval)
- Bootstrap auto-detection (CPU, RAM, L1d cache, features)
- TCP tuning: TCP_NODELAY, TCP_DEFER_ACCEPT, TCP_FASTOPEN, TCP_QUICKACK, SO_BUSY_POLL
- SO_REUSEPORT (Linux), sys_membarrier (Linux)
- `target-cpu=native` build optimization (NEON/AES-CE/AVX2)
- systemd unit file + Docker HEALTHCHECK

## Quick Start

```bash
# Build
cargo build --release

# With ACME auto-renewal (Let's Encrypt)
cargo build --release --features acme

# Linux: enable io_uring multishot accept (kernel 5.19+)
cargo build --release --features io-uring-accept

# Run
ZION_CONFIG=zion.toml ./target/release/zion
```

## Configuration

```toml
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"
key_path = "/etc/ssl/zion/tls.key"

[upstreams]
backend = "http://127.0.0.1:8000"
frontend = "http://127.0.0.1:3000"

[[route]]
path = "/api/{*rest}"
upstream = "backend"
waf = true

[[route]]
path = "/_next/static/{*rest}"
upstream = "frontend"
mode = "static_cache"

[[route]]
path = "/{*rest}"
upstream = "frontend"
```

See [zion.example.toml](zion.example.toml) for the full configuration reference.

## Architecture

```
Client → TLS 1.3 → Security Gates → Radix Router → WAF Pipeline → Proxy/Cache → Upstream
                         │                              │
                    URI limit              Aho-Corasick (70+ patterns)
                    Method whitelist       Entropy analysis
                    Rate limiter           simd-json validation
                    CORS pre-flight        Depth/size limits
```

## Benchmarking

```bash
# Payload × concurrency matrix (36 cells, 2 warmup + 3 measure, ~15 min)
bash benchmarks/bench-matrix.sh

# Quick validation (1 round × 3s, ~2 min)
bash benchmarks/bench-matrix.sh --quick

# Smoke test (10 endpoint types, ~90s)
bash benchmarks/bench-smoke.sh

# Scientific benchmark vs nginx (5 runs, CI95, Docker)
bash benchmarks/bench-scientific.sh

# Live dashboard
cd benchmarks && python3 -m http.server 8888
# open http://localhost:8888/dashboard.html
```

Results are saved to `benchmarks/results/matrix-history.json` with automatic delta comparison between runs (same config only — quick vs quick, full vs full).

## Testing

```bash
# Unit tests (154)
cargo test

# Integration tests (19 — requires running Zion + Go backend)
# 1. cd benchmarks/backend && go run test-server.go &
# 2. ZION_CONFIG=tests/zion-test.toml ./target/release/zion &
# 3. Run:
cargo test --test integration -- --ignored --test-threads=1
```

> **Note:** Integration tests use `curl` to exercise the full TLS proxy stack.
> Unit tests (`cargo test`) have no external dependencies.

## License

MIT
