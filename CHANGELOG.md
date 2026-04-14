# Changelog

All notable changes to Zion Edge Gateway are documented here.

## [0.1.3] - 2026-04-15

### Fixed (Copilot code review)
- Fix `.cargo/config.toml`: `cfg(any())` is always false, replaced with `[build]`
- Fix singleflight: inflight entry cleaned up on proxy error, client disconnect, and upstream frame error (prevents waiter deadlock)
- Fix WAF SIMD pre-filter: removed unsound fast-reject that skipped raw Aho-Corasick scan (patterns like `union select` have no trigger bytes)
- Fix metrics ArcSwap: combined timestamp + buffer into single atomic `ArcSwap<(u64, Bytes)>` (prevents readers seeing stale buffer)
- Fix JWKS backoff: failure after success resets to 5s (was stuck at 3600s), cap reduced to 300s
- Fix bench-pgo.sh: PID capture was in subshell, now uses Rust backend
- Fix PDF report: version strings updated to match release

### Added
- Rust benchmark backend (pure hyper, 194K raw req/s, replaces Go)
- Apple-native docs homepage (custom CSS, dark mode, frosted glass nav)
- docs/config/auth.md (JWT/OIDC configuration)
- docs/config/http3.md (HTTP/3 QUIC support)

### Changed
- Architecture docs: 17 modules documented (was 11)
- Benchmark numbers: Rust backend eliminates Go bottleneck (+14-61% on proxy paths)

### Benchmark Results (Apple M4, Rust backend, v0.1.3)

| Endpoint | req/s | CV% |
|----------|------:|----:|
| HTML SSR 5KB | 233,170 | 1.1% |
| CSS 3KB (cached) | 209,573 | 3.4% |
| TLS Proxy API 1KB | 106,505 | 2.1% |
| WAF POST JSON | 103,206 | 0.5% |
| JS 4KB (uncached) | 102,892 | 1.3% |
| PNG 8KB (uncached) | 99,496 | 1.7% |
| WOFF2 16KB (uncached) | 83,870 | 2.5% |

## [0.1.2] - 2026-04-14

### Security (28 bugs fixed)

**Critical (7)**
- Fix request smuggling via forwarded `Transfer-Encoding` header (proxy.rs)
- Fix cache poisoning: cache key now includes query string (dispatch.rs)
- Fix WebSocket 101 response: forward `Sec-WebSocket-Accept` from upstream (proxy.rs)
- Fix WAF bypass via multi-layer URL encoding: normalization iterates until convergence (waf.rs)
- Fix WAF POST/PUT/PATCH path: no longer skips CORS headers, metrics, or request-ID (dispatch.rs)
- Fix `Vary` header check: exact token matching prevents disabling cache for gzip upstreams (dispatch.rs)
- Fix HTTP/80 handler: add rate limiting and URI length check (main.rs)

**High (8)**
- Fix L1/L2 cache coherence: generation counter invalidates stale L1 entries (cache.rs)
- Fix WAF: validate DELETE request bodies (dispatch.rs, waf.rs)
- Fix CORS: block OPTIONS preflight from disallowed origins (dispatch.rs)
- Fix cache: preserve `Content-Encoding` header on cache hits (dispatch.rs, cache.rs)
- Fix SSRF detection: add HTTPS, hex IP, decimal IP, DNS rebinding patterns (waf.rs)
- Fix EWMA latency: use CAS loop for atomic updates (health.rs)
- Fix TLS cert generation: `Acquire` ordering on ARM for data plane reads (tls.rs)
- Fix client cert fingerprint: correct misleading SHA256 comment (main.rs)

**Medium (13)**
- Fix URI length check to include query string (dispatch.rs)
- Add spaceless command injection patterns (waf.rs)
- Lower path traversal detection to 2-level (waf.rs)
- Fix Content-Type matching to require delimiter after type (waf.rs)
- Fix Bearer token extraction: case-insensitive per RFC 6750 (auth.rs)
- Fix JWKS refresh: retry with exponential backoff (auth.rs)
- Validate `auth_profile` references in config at load time (config.rs)
- Increase connection timeout to 1h for HTTP/2 mux and WebSocket (main.rs)
- Fix TLS prewarm/watcher race via generation check (tls.rs)
- Log setsockopt failures instead of ignoring (net.rs)
- Watch all SNI cert directories for hot-reload (tls.rs)
- Fix CORS origin: case-insensitive per RFC 6454 (security.rs)

### Performance (20 optimizations)

**Compiler/Build**
- Enable `target-cpu=native` via `.cargo/config.toml` (NEON/AES-CE on Apple Silicon)
- Add PGO build script (`benchmarks/bench-pgo.sh`) for 10-20% additional gain

**Allocation Elimination**
- Traceparent: stack `[u8;55]` buffer replaces 3x `format!` (-500ns/req)
- CORS origin: `HeaderValue` clone instead of `String` allocation
- WAF content-type: borrow from `parts.headers` instead of pre-clone
- Cache key: `Arc::from()` direct instead of `String` intermediate

**Lock/Contention Reduction**
- WebSocket TLS config: `OnceLock` (built once, not per-upgrade)
- Metrics render: `ArcSwap` replaces `RwLock` (lock-free `/metrics`)
- Histogram observe: 3 atomics instead of 17 (non-cumulative differential buckets)
- HTTP builder: `Arc` wrap (ref-count bump instead of deep clone)

**Data Structures**
- L1 cache: O(1) LRU via index-based doubly-linked list (was O(N) VecDeque)
- Host validation: single-pass byte scan (was 8 separate `contains()` calls)
- CORS origin: FNV hash set O(1) lookup (was `Vec` linear scan)

**WAF Pipeline**
- SIMD pre-filter: `memchr3` fast-reject before Aho-Corasick (-200-500ns for clean bodies)
- Normalization iterations capped at 2 (was 7)
- Thread-local buffer shrink-to-fit above 64KB (prevents OOM)

**Innovative**
- Request coalescing (singleflight): N concurrent cache misses = 1 upstream fetch
- Health probe inline fast-path: `/healthz` responds in ~1us, bypasses full pipeline
- `SO_BUSY_POLL` on Linux: spin-poll NIC queue for -5-15us p99 latency

### Benchmark Results (Apple M4, TLS 1.3)

| Endpoint | req/s |
|----------|------:|
| HTML SSR 5KB | 233,341 |
| Cache Hit JS 4KB | 209,381 |
| CSS 3KB (cached) | 191,574 |
| TLS Proxy API 1KB | 93,253 |
| WAF POST JSON | 91,893 |
| SQLi/XSS blocked | Yes |

## [0.1.1] - 2026-04-12

- Initial public release
- TLS 1.3 reverse proxy with WAF, cache, rate limiting
- 141K req/s cached throughput
- Docker comparison vs nginx (+108% HTML, +42% PNG)
