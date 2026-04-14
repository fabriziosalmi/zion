# Zion Edge Gateway

[![CI](https://github.com/fabriziosalmi/zion/actions/workflows/ci.yml/badge.svg)](https://github.com/fabriziosalmi/zion/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/release/fabriziosalmi/zion?include_prereleases&color=blue&label=release)](https://github.com/fabriziosalmi/zion/releases)
[![License](https://img.shields.io/github/license/fabriziosalmi/zion)](https://github.com/fabriziosalmi/zion/blob/master/LICENSE)
[![Performance](https://img.shields.io/badge/Performance-233k%20req%2Fs-success?style=flat&color=brightgreen)](https://github.com/fabriziosalmi/zion/tree/master/benchmarks)
[![WAF](https://img.shields.io/badge/WAF-Zero%20Regex-orange)](https://github.com/fabriziosalmi/zion/blob/master/src/waf.rs)

High-performance TLS reverse proxy with built-in WAF, written in Rust.

## Performance

### Native Benchmark (Apple M4, Rust backend, 5 runs x 10s, c=100)

| Endpoint | Median req/s | Best Run | CV% | Errors |
|----------|-------------|----------|-----|--------|
| HTML SSR 5KB | **233,170** | 235,370 | 1.1% | 0 |
| CSS 3KB (cached) | **209,573** | 215,408 | 3.4% | 0 |
| Cache Hit JS 4KB (RAM) | **195,318** | 207,521 | 7.1% | 0 |
| TLS Proxy API GET 1KB | **106,505** | 107,189 | 2.1% | 0 |
| WAF POST JSON | **103,206** | 103,547 | 0.5% | 0 |
| JS 4KB (no cache) | **102,892** | 104,135 | 1.3% | 0 |
| PNG 8KB (no cache) | **99,496** | 101,290 | 1.7% | 0 |
| WOFF2 16KB (no cache) | **83,870** | 86,242 | 2.5% | 0 |
| SQLi blocked | Yes (400) | -- | -- | -- |
| XSS blocked | Yes (400) | -- | -- | -- |

**Peak**: 233K req/s HTML (TLS 1.3 e2e) -- 210K cache hit -- 107K API proxy -- 103K WAF POST (CV 0.5%)

Reproduce: `bash benchmarks/bench-native.sh`

### Fair Comparison with nginx (Docker, 1 CPU, 256 MB)

| Endpoint | nginx 1.27 | Zion TLS | Zion WAF | Zion Full | Best Delta | Errors |
|---|---|---|---|---|---|---|
| API GET (1KB) | 29,404 | 27,517 | 27,438 | 27,537 | -6.3% | 0 |
| HTML (5KB) | 25,657 | 52,581 | 53,016 | 53,368 | **+108.0%** | 0 |
| JS (4KB) | 23,152 | 18,165 | 18,037 | 32,366 | **+39.8%** | 0 |
| PNG (8KB) | 17,409 | 13,411 | 14,345 | 24,770 | **+42.3%** | 0 |
| WAF POST | 27,772 | 26,173 | 25,653 | 26,909 | -3.1% | 0 |
| CSS cached | 27,436 | 16,800 | 14,949 | 25,111 | -8.5% | 0 |

Full methodology: `bash benchmarks/bench-scientific.sh` (5 runs, CI95).

<details>
<summary>Throughput Matrix (Apple M4, Go backend, TLS 1.3, wrk)</summary>

Payload x concurrency grid -- measures end-to-end TLS throughput. These numbers use the Go backend (lower ceiling than Rust backend above).

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

</details>

## Features

**Core Proxy**
- TLS 1.3 termination (rustls + hardware crypto: AES-NI, AES-CE)
- HTTP/2 upstream multiplexing (hyper-rustls ALPN negotiation)
- Multi-SNI with per-domain certificates and FNV hash lookup
- Zero-downtime TLS and QUIC hot-reload (ArcSwap + watch channels)
- Session tickets + 0-RTT early data with method gating (425 Too Early, RFC 8470)
- ACME auto-renewal via `instant-acme` (HTTP-01, `--features acme`)
- JWT/OIDC authentication gate (`--features auth`)
- HTTP/1.1, HTTP/2, HTTP/3 QUIC (`--features http3`)
- WebSocket proxy (HTTP Upgrade + bidirectional pipe, TLS-to-upstream)
- SSE streaming proxy (zero-buffer)

**Cache**
- Two-level RAM cache: L1 thread-local (~5ns, O(1) LRU) + L2 DashMap (~30ns)
- L1/L2 generation-based coherence (no stale data after update)
- Request coalescing (singleflight): N concurrent cache misses = 1 upstream fetch
- Thread-local route lookup cache (FNV hash, ~5ns hot path)
- Connection pool pre-warming at startup

**WAF (Zero-Regex, O(N) Single-Pass)**
- Aho-Corasick scanner: 192 patterns, 14 categories (SQLi, XSS, CMDi, SSRF, NoSQL, deserialization, GraphQL, LDAP, XXE, SSTI, CRLF, Log4Shell)
- Shannon entropy analysis (detect obfuscated payloads)
- simd-json structural validation (depth + string length limits)
- Content-Type strict validation with delimiter enforcement
- Body size enforcement, DELETE body inspection
- Iterative normalization (URL-decode, SQL comments, JSON unicode)

**Security**
- HSTS (2-year, includeSubDomains, preload), X-Content-Type-Options, X-Frame-Options
- Referrer-Policy, Permissions-Policy, per-route CSP
- Server header stripped, hop-by-hop headers stripped (RFC 7230)
- URI length limit (8 KB path+query), method whitelist (7 methods)
- Per-IP rate limiting (lock-free atomic, configurable window)
- CORS with FNV O(1) origin lookup, case-insensitive (RFC 6454)
- TLS handshake timeout (10s), connection timeout (1h for H2/WS/SSE)
- Header bomb prevention (64 headers, 16 KB buffer)

**Observability**
- `/healthz`, `/readyz` inline fast-path (~1us, bypasses full pipeline)
- `/metrics` Prometheus text format (lock-free sharded counters, differential histogram)
- `X-Request-ID` (stack-buffer, zero-alloc) + W3C `traceparent` propagation
- Structured logging (text or JSON)

**Operations**
- Config validation at startup (fail fast, validates all profile references)
- Graceful drain on shutdown (30s timeout, semaphore-tracked)
- Upstream health checking (30s interval, EWMA latency, gray failure detection)
- Bootstrap auto-detection (CPU cores, RAM, L1d cache, AES-NI/NEON, kernel features)
- TCP tuning: TCP_NODELAY, TCP_DEFER_ACCEPT, TCP_FASTOPEN, TCP_QUICKACK, TCP_CORK, SO_BUSY_POLL
- SO_REUSEPORT, sys_membarrier, io_uring multishot accept (Linux)
- `target-cpu=native` build optimization, PGO build script included
- systemd unit file + Docker HEALTHCHECK

## Quick Start

```bash
# Build
cargo build --release

# With optional features
cargo build --release --features "acme,auth,http3"

# Linux: io_uring multishot accept (kernel 5.19+)
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
Client -> TLS 1.3 -> Security Gates -> Radix Router -> WAF Pipeline -> Proxy/Cache -> Upstream
                         |                                |
                    URI limit                  Aho-Corasick (192 patterns)
                    Method whitelist           Entropy analysis
                    Rate limiter              simd-json validation
                    CORS pre-flight           Depth/size limits
```

17 modules, ~8,600 lines of Rust. See [architecture docs](https://fabriziosalmi.github.io/zion/guide/architecture) for the full module map and request lifecycle.

## Benchmarking

```bash
# Native scientific benchmark (8 endpoints x 5 runs, ~8 min)
bash benchmarks/bench-native.sh

# Payload x concurrency matrix (36 cells, ~15 min)
bash benchmarks/bench-matrix.sh

# Quick validation (~2 min)
bash benchmarks/bench-matrix.sh --quick

# Docker comparison vs nginx (5 runs, CI95)
bash benchmarks/bench-scientific.sh

# PGO optimized build (+10-20%)
bash benchmarks/bench-pgo.sh
```

Results saved to `benchmarks/bench-history.json` with automatic delta comparison.

## Testing

```bash
# Unit tests (154)
cargo test

# Integration tests (19 -- requires running Zion + backend)
# 1. cd benchmarks/backend && cargo run --release &
# 2. ZION_CONFIG=tests/zion-test.toml ./target/release/zion &
# 3. Run:
cargo test --test integration -- --ignored --test-threads=1
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## License

MIT
