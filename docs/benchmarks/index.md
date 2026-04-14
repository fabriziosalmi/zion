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

## Native Benchmark (Apple M4, v0.1.2)

Measured with `bench-native.sh` (5 runs x 10s, c=100, median reported). Includes all v0.1.2 security fixes and performance optimizations.

| Endpoint | Median req/s | Best Run | CV% | Errors |
|---|---|---|---|---|
| HTML SSR 5KB | **233,341** | 236,755 | 2.0% | 0 |
| Cache Hit JS 4KB (RAM) | **209,381** | 214,546 | 9.8% | 0 |
| CSS 3KB (cached) | **191,574** | 203,969 | 4.5% | 0 |
| TLS Proxy API GET 1KB | **93,253** | 97,019 | 3.0% | 0 |
| WAF POST JSON | **91,893** | 93,415 | 3.1% | 0 |
| JS 4KB (no cache) | **81,470** | 82,723 | 2.3% | 0 |
| PNG 8KB (no cache) | **66,753** | 68,020 | 2.7% | 0 |
| WOFF2 16KB (no cache) | **59,262** | 60,679 | 3.0% | 0 |

Security validation: SQLi and XSS injection blocked (HTTP 400).

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
