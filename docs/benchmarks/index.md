# Benchmarks

All benchmarks use [wrk](https://github.com/wg/wrk) with consistent methodology. Numbers represent requests per second (higher is better).

## Native Benchmark (Apple M4, v0.1.4, Rust backend)

Measured with `bench-native.sh` (5 runs x 10s, c=100, median reported). Includes all v0.1.4 security fixes and 25 performance optimizations. Rust backend (pure hyper, 194K raw req/s) eliminates the backend as a bottleneck.

| Endpoint | Median req/s | Best Run | CV% | Errors |
|---|---|---|---|---|
| HTML SSR 5KB | **233,170** | 235,370 | 1.1% | 0 |
| CSS 3KB (cached) | **209,573** | 215,408 | 3.4% | 0 |
| Cache Hit JS 4KB (RAM) | **195,318** | 207,521 | 7.1% | 0 |
| TLS Proxy API GET 1KB | **106,505** | 107,189 | 2.1% | 0 |
| WAF POST JSON | **103,206** | 103,547 | 0.5% | 0 |
| JS 4KB (no cache) | **102,892** | 104,135 | 1.3% | 0 |
| PNG 8KB (no cache) | **99,496** | 101,290 | 1.7% | 0 |
| WOFF2 16KB (no cache) | **83,870** | 86,242 | 2.5% | 0 |

Security validation: SQLi and XSS injection blocked (HTTP 400).

### Go vs Rust Backend Impact

| Endpoint | Go Backend | Rust Backend | Delta |
|---|---|---|---|
| TLS Proxy API | 93,253 | **106,505** | **+14.2%** |
| WAF POST | 91,893 | **103,206** | **+12.3%** |
| JS uncached | 75,500 | **102,892** | **+36.3%** |
| PNG 8KB | 59,537 | **99,496** | **+67.1%** |
| WOFF2 16KB | 53,087 | **83,870** | **+58.0%** |

Cache-hit paths are unchanged (backend not involved), confirming the Go runtime was the ceiling.

## Fair Docker Comparison

Both Zion and nginx run in Docker containers with identical resource limits: **1 CPU, 256 MB RAM**. Same backend, same routes, same TLS certificates.

| Endpoint | nginx 1.27 | Zion TLS | Zion WAF | Zion Full | Best Delta | Errors |
|---|---|---|---|---|---|---|
| API GET (1KB) | 29,404 | 27,517 | 27,438 | 27,537 | -6.3% | 0 |
| HTML (5KB) | 25,657 | 52,581 | 53,016 | 53,368 | **+108.0%** | 0 |
| JS (4KB) | 23,152 | 18,165 | 18,037 | 32,366 | **+39.8%** | 0 |
| PNG (8KB) | 17,409 | 13,411 | 14,345 | 24,770 | **+42.3%** | 0 |
| WAF POST | 27,772 | 26,173 | 25,653 | 26,909 | -3.1% | 0 |
| CSS cached | 27,436 | 16,800 | 14,949 | 25,111 | -8.5% | 0 |

## Native Linux (1-core, bare metal)

| Scenario | nginx (req/s) | Zion (req/s) | Delta |
|---|---|---|---|
| API GET (TLS proxy) | 12,300 | 12,500 | Parity |
| HTML page (TLS proxy) | 10,300 | 41,700 | **+303%** |
| WAF POST (Aho-Corasick) | 11,900 | 11,600 | Parity |

## Methodology

- **Tool**: wrk 4.2.0, 2 threads, 100 connections
- **Runs**: 5 measurement runs x 10s each, median reported
- **Statistics**: Median, CI95, coefficient of variation (CV%)
- **TLS**: Self-signed certificates, TLS 1.3, rustls 0.23, session tickets + 0-RTT
- **Backend**: Rust test server (hyper, 194K raw req/s) or Go test server (matrix)
- **Build**: opt-level=3, LTO=fat, codegen-units=1, panic=abort, target-cpu=native, mimalloc
- **Docker**: `--cpus=1 --memory=256m` for fair nginx comparison
- **Reproducibility**: `bash benchmarks/bench-native.sh`
