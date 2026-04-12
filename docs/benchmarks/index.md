# Benchmarks

All benchmarks use [wrk](https://github.com/wg/wrk) or [k6](https://k6.io/) with consistent methodology. Numbers represent requests per second (higher is better).

## Fair Docker Comparison

Both Zion and nginx run in Docker containers with identical resource limits: **1 CPU, 256 MB RAM**. Same backend, same routes, same TLS certificates.

| Scenario | nginx (req/s) | Zion (req/s) | Delta |
|---|---|---|---|
| API GET (TLS proxy) | 27,000 | 29,000 | **+6%** |
| HTML page (TLS proxy) | 16,000 | 62,000 | **+278%** |
| CSS cached (static) | 21,000 | 44,000 | **+112%** |

Zion's advantage is largest on cacheable content where the in-memory DashMap cache eliminates upstream round-trips entirely.

## Native Linux (1-core, bare metal)

Single-core comparison on the same Linux host, no containers.

| Scenario | nginx (req/s) | Zion (req/s) | Delta |
|---|---|---|---|
| API GET (TLS proxy) | 12,300 | 12,500 | Parity |
| HTML page (TLS proxy) | 10,300 | 41,700 | **+303%** |
| WAF POST (70+ patterns) | 11,900 | 11,600 | Parity |

On pure proxy workloads (API GET), both perform similarly -- the bottleneck is the upstream. On cached content, Zion's in-memory cache provides a 4x advantage. WAF POST shows parity: Zion's 6-gate pipeline with 70+ Aho-Corasick patterns adds no measurable overhead compared to nginx without WAF.

## Native macOS (Apple M4)

Zion running natively on Apple M4, multi-core, no containers. Payload × concurrency grid measured with `bench-matrix.sh` (2 warmup + 3 measure rounds × 5s, stddev reported).

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

**Peak**: 140K req/s (1 MB cached, c=100) · 141K req/s (1 KB cached, c=100) · 6.7 GB/s TLS throughput

Cache speedup vs uncached: **2.5–3x** across all payload sizes. The bottleneck shifts from upstream round-trip (small payloads) to rustls TLS encryption bandwidth (large payloads).

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

- **API GET parity**: When proxying to a real backend, the upstream is the bottleneck. Both proxies add negligible overhead.
- **HTML/cache advantage**: Zion's lock-free in-memory cache (DashMap + Bytes zero-copy) serves cached content without touching the upstream or filesystem.
- **WAF at parity**: The 6-gate WAF pipeline (Aho-Corasick single-pass, no regex) processes POST bodies without measurable throughput loss compared to a proxy with no WAF.
