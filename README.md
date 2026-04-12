# Zion Edge Gateway

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

**Peak**: 140K req/s cached (1 MB, c=100) · 141K req/s cached (1 KB, c=100) · 6.7 GB/s TLS throughput

<details>
<summary>Bottleneck analysis</summary>

- **Dynamic 10 MB ≈ 300 req/s**: Go backend generates payload at runtime → CPU-bound in Go
- **Cached 1 MB c=100 → 140K req/s = 140 GB/s pre-TLS, 6.7 GB/s post-TLS**: rustls encryption is the ceiling
- **Cached 1 KB c=100 → 141K req/s**: With small payloads, TLS record overhead dominates — req/s is similar
- **Static vs Cached (2.5–3x speedup)**: Cache eliminates upstream round-trip + TCP overhead

</details>

### Fair Comparison with nginx (Docker, 1 CPU, 256 MB)

| Endpoint | nginx | Zion | Delta |
|---|---|---|---|
| API GET 1 KB | 27,166 | 28,669 | +6% |
| HTML 5 KB | 16,298 | 61,556 | **+278%** |
| CSS cached | 20,756 | 43,973 | **+112%** |
| WAF POST | 24,873 | 26,690 | +7% |

Full methodology: `bash benchmarks/bench-matrix.sh` (36 cells, 2 warmup + 3 measure rounds, stddev reported).

## Features

**Core Proxy**
- TLS 1.3 termination (rustls + aws-lc-rs hardware crypto)
- Multi-SNI with per-domain certificates + FNV hash lookup
- Zero-downtime TLS hot-reload (ArcSwap + generation counter + fs watcher)
- Session tickets + 0-RTT early data with method gating (425 Too Early, RFC 8470)
- ACME auto-renewal via `instant-acme` (HTTP-01, `--features acme`)
- Thread-local SNI cache with generation tracking
- Predictive cert pre-warming (auto-renew 120s before expiry)
- HTTP/1.1 + HTTP/2 auto-detection
- WebSocket proxy (HTTP Upgrade + bidirectional pipe, TLS-to-upstream)
- SSE streaming proxy (zero-buffer)
- Two-level RAM cache: L1 thread-local (~5ns) + L2 DashMap (~30ns)
- L2 eviction: expired-first, then oldest-TTL fallback
- Radix tree routing (~30ns lookup)
- io_uring multishot accept (Linux, feature-gated)

**WAF (Zero-Regex, O(N) Single-Pass)**
- Aho-Corasick scanner: 70+ patterns (SQLi, XSS, CMDi, SSRF, Log4Shell)
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
- TCP tuning: TCP_NODELAY, TCP_DEFER_ACCEPT, TCP_FASTOPEN, TCP_QUICKACK
- SO_REUSEPORT (Linux), sys_membarrier (Linux)
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
# Unit tests (99)
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
