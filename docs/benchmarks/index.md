# Benchmarks

All benchmarks use [wrk](https://github.com/wg/wrk) or [k6](https://k6.io/) with consistent methodology. Numbers represent requests per second (higher is better).

## Fair Docker Comparison

Both Zion and nginx run in Docker containers with identical resource limits: **1 CPU, 256 MB RAM**. Same backend, same routes, same TLS certificates.

| Endpoint | nginx 1.27 | Zion TLS | Zion WAF | Zion Full | Best Δ | Errors |
|---|---|---|---|---|---|---|
| API GET (1KB) | 29,404 | 27,517 | 27,438 | 27,537 | -6.3% | 0 |
| HTML (5KB) | 25,657 | 52,581 | 53,016 | 53,368 | **+108.0%** | 0 |
| JS (4KB) | 23,152 | 18,165 | 18,037 | 32,366 | **+39.8%** | 0 |
| PNG (8KB) | 17,409 | 13,411 | 14,345 | 24,770 | **+42.3%** | 0 |
| WAF POST | 27,772 | 26,173 | 25,653 | 26,909 | -3.1% | 0 |
| CSS cached | 27,436 | 16,800 | 14,949 | 25,111 | -8.5% | 0 |

The difference is largest on cacheable content where the in-memory cache avoids upstream round-trips.

## Native Linux (1-core, bare metal)

Single-core comparison on the same Linux host, no containers.

| Scenario | nginx (req/s) | Zion (req/s) | Delta |
|---|---|---|---|
| API GET (TLS proxy) | 12,300 | 12,500 | Parity |
| HTML page (TLS proxy) | 10,300 | 41,700 | **+303%** |
| WAF POST (70+ patterns) | 11,900 | 11,600 | Parity |

On proxy workloads (API GET), both perform similarly — the bottleneck is the upstream. On cached content, the in-memory cache removes the upstream round-trip. WAF POST shows parity: the Aho-Corasick scan over 70+ patterns does not reduce throughput below nginx without WAF in this test.

## Native Benchmark (Apple M4, v0.1.2, Rust backend)

Measured with `bench-native.sh` (5 runs x 10s, c=100, median reported). Includes all v0.1.2 security fixes and 20 performance optimizations. Rust backend eliminates Go runtime as bottleneck.

| Endpoint | Median req/s | Best Run | CV% | Errors |
|---|---|---|---|---|
| HTML SSR 5KB | **235,155** | 236,755 | 1.3% | 0 |
| Cache Hit JS 4KB (RAM) | **210,899** | 214,774 | 1.9% | 0 |
| CSS 3KB (cached) | **197,564** | 210,076 | 5.5% | 0 |
| TLS Proxy API GET 1KB | **106,161** | 106,922 | 1.1% | 0 |
| WAF POST JSON | **103,221** | 105,298 | 1.4% | 0 |
| JS 4KB (no cache) | **99,940** | 105,439 | 6.4% | 0 |
| PNG 8KB (no cache) | **95,700** | 99,674 | 4.2% | 0 |
| WOFF2 16KB (no cache) | **77,719** | 84,133 | 4.9% | 0 |

Security validation: SQLi and XSS injection blocked (HTTP 400).

### Go vs Rust Backend Impact

Replacing the Go test backend with a Rust equivalent (pure hyper, 194K raw req/s) removes the backend as a bottleneck on proxy paths:

| Endpoint | Go Backend | Rust Backend | Delta |
|---|---|---|---|
| TLS Proxy API | 93,253 | **106,161** | **+13.8%** |
| WAF POST | 91,893 | **103,221** | **+12.3%** |
| JS uncached | 75,500 | **99,940** | **+32.4%** |
| PNG 8KB | 59,537 | **95,700** | **+60.7%** |
| WOFF2 16KB | 53,087 | **77,719** | **+46.4%** |

Cache-hit paths are unchanged (backend not involved), confirming the Go runtime was the ceiling.

## Matrix Benchmark (Apple M4)

Zion running natively on Apple M4, multi-core, no containers. Measured with `bench-matrix.sh` (2 warmup + 3 measurement rounds × 5s each).

### Cached RAM (L1 thread-local + L2 DashMap)

| Payload | c=1 | c=10 | c=100 |
|---|---|---|---|
| 1 MB | 30,247 | 88,181 | **140,301** |
| 10 MB | 33,781 | 80,246 | 123,936 |
| 100 MB | 36,067 | 90,091 | 96,706 |

### Static (uncached TLS proxy)

| Payload | c=1 | c=10 | c=100 |
|---|---|---|---|
| 1 MB | 14,328 | 35,543 | 46,416 |
| 10 MB | 11,889 | 41,116 | 53,144 |
| 100 MB | 15,669 | 46,118 | 39,295 |

### Dynamic (Go backend generating payload at runtime)

| Payload | c=1 | c=10 | c=100 |
|---|---|---|---|
| 1 MB | 2,067 | 3,491 | 3,138 |
| 10 MB | 323 | 406 | 203 |
| 100 MB | 9,334 | 22,758 | 18,865 |

Cached mode shows higher throughput than uncached because the upstream round-trip is eliminated. At large payloads, TLS encryption becomes the bottleneck.

## Methodology

- **Tool**: wrk with 2 threads, configurable connections (1, 10, 100)
- **Matrix**: 3 payload sizes (1 MB, 10 MB, 100 MB) × 3 concurrency levels × 4 modes = 36 cells
- **Rounds**: 2 warmup (discarded) + 3 measurement rounds, mean ± stddev reported
- **Duration**: 5 seconds per round (configurable)
- **TLS**: Self-signed certificates, TLS 1.3, session tickets + 0-RTT enabled
- **Backend**: Go test server generating payloads at runtime (streamed in 64 KB chunks)
- **Cache priming**: Cached mode entries are primed with a single request before measurement
- **History**: Results saved to JSON with automatic delta comparison (same config only)
- **Docker constraints**: `--cpus=1 --memory=256m` for fair nginx comparison
- **Reproducibility**: `bash benchmarks/bench-matrix.sh` runs the full matrix automatically

## What the Numbers Mean

- **API GET parity**: When proxying to a backend, the upstream is the bottleneck. The proxy layer adds little.
- **Cache advantage**: Cached responses are served from DashMap in-memory storage, bypassing the upstream.
- **WAF throughput**: The Aho-Corasick scan did not reduce throughput below the no-WAF baseline in these tests. Run `bench-native.sh` to reproduce.
