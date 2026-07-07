# Optimization log

Changes made to improve throughput and latency, with rationale. Throughput claims reference the [`benchmarks/baseline/`](https://github.com/fabriziosalmi/zion/tree/master/benchmarks/baseline) harness.

## Architectural

| Change | Rationale |
|---|---|
| HTTP/2 upstream multiplexing | `hyper-rustls` HttpsConnector with ALPN H2 negotiation for HTTPS upstreams |
| TLS connection pre-warming | Health checks reuse shared HttpClient; startup pre-warm task fires GET to all upstreams |
| `TCP_CORK` on listener (Linux) | Batches TLS record + HTTP headers into full MSS segments |
| Connection pool pre-warming | Fires GET to all upstreams before accept loop starts |
| Thread-local route lookup cache | FNV hash of path maps to cached `Arc<ResolvedRoute>` (~5ns vs ~30ns radix tree) |

## Compiler / build

| Change | Rationale |
|---|---|
| `target-cpu=native` (.cargo/config.toml) | Unlocks NEON/AES-CE on Apple Silicon, AVX2/AES-NI on x86_64 |
| PGO build script (`bench-pgo.sh`) | Two-phase profile-guided optimization for 10-20% additional throughput |

## Hot path allocation elimination

| Change | Rationale |
|---|---|
| Traceparent: `[u8;55]` stack buffer | Replaces 3x `format!` heap allocations (-500ns/req) |
| CORS origin: `HeaderValue` clone | Avoids `String` allocation per CORS request |
| WAF content-type: borrow from `parts.headers` | Eliminates `to_owned()` clone on POST/PUT/PATCH |
| Cache key: `Arc::from()` direct | Skips intermediate `String` allocation on cache miss |

## Lock / contention reduction

| Change | Rationale |
|---|---|
| WebSocket TLS: `OnceLock<Arc<ClientConfig>>` | Builds root cert store once, not per WS upgrade |
| Metrics render: `ArcSwap<(u64, Bytes)>` | Lock-free `/metrics` endpoint, atomic timestamp+buffer pair |
| Histogram: non-cumulative differential buckets | 3 atomic ops per observation instead of 17; prefix sums at render time |
| HTTP builder: `Arc<AutoBuilder>` | Per-connection clone is ref-count bump, not deep copy |

## Data structures

| Change | Rationale |
|---|---|
| L1 cache: O(1) LRU (index-based doubly-linked list) | Replaces O(N) VecDeque linear scan on every cache hit |
| L1/L2 generation-based coherence | Atomic generation counter invalidates stale L1 entries after L2 update |
| Host validation: single-pass byte scan | Replaces 8 separate `contains()` calls |
| CORS origin: FNV hash set | O(1) lookup replaces `Vec` linear scan; case-insensitive via pre-lowercased storage |

## WAF pipeline

| Change | Rationale |
|---|---|
| Two pattern sets selected per profile via `mode` | `balanced` (default, ~100 high-precision patterns) or `aggressive` (~240, broader recall). Categories: SQLi, XSS, CMDi, path traversal, SSRF/cloud-metadata, LDAP, XXE, SSTI, CRLF, Log4Shell, prototype pollution; NoSQL, deserialization, generic XSS handlers, JS API sinks live in aggressive |
| Aho-Corasick (no regex) | O(N) single-pass, no backtracking, case-insensitive, ReDoS-immune by construction |
| Normalisation: iterative re-scan | URL-decode (`%XX`, `+`), SQL comment strip (`/* … */`), JSON unicode (`\uXXXX`); decode loop runs up to 3 passes (catches single, double, triple encoding) and re-scans after each pass |
| Buffer shrink-to-fit (>64KB) | Prevents permanent memory inflation from adversarial large bodies |
| Entropy gate: JSON-string-aware (default 6.5 bits/byte) | For application/json, computed only on bytes inside string literals so structural punctuation doesn't dilute the signal. Threshold leaves base64/JWT through; per-profile threshold + kill-switch |
| DELETE body inspection | RFC 9110 allows bodies on DELETE |
| Content-Type delimiter enforcement | Requires `;` or ` ` delimiter after type match |

## Innovative

| Change | Rationale |
|---|---|
| Request coalescing (singleflight) | N concurrent cache misses = 1 upstream fetch (thundering herd protection) |
| Health probe inline fast-path | `/healthz` responds in ~1us, bypasses full process_request pipeline |
| `SO_BUSY_POLL` (Linux) | Spin-poll NIC queue 50us before sleeping; -5-15us p99 latency |

## Allocator

| Change | Rationale |
|---|---|
| `mimalloc` global allocator | Reduces allocation contention under concurrent load compared to system malloc |

## TLS

| Change | Rationale |
|---|---|
| TLS 1.3 default | 1-RTT handshake instead of 2-RTT (TLS 1.2) |
| Session cache 16,384 entries | More resumed sessions avoid full ECDHE key exchange |
| Session tickets (Ticketer) | Stateless resumption, works across process restarts |
| 0-RTT early data (16 KB max) | Clients can send data before handshake completes (idempotent methods only) |
| Server cipher order enforced | `ignore_client_order = true` |
| `send_half_rtt_data = true` | Server sends data before client Finished on resumed connections |
| `FnvHashMap` for SNI map | ~2x faster than SipHash for short hostname keys |
| Thread-local SNI cache | Invalidated via dual-generation counter (instance + global) |
| `Acquire`/`Release` ordering | Prevents stale cert serving on ARM (Graviton) after hot-reload |
| `sys_membarrier` (Linux) | Ensures all threads observe new cert config after reload |
| Cert pre-warming (120s) | Pre-builds `ServerConfig` before expiry; race-protected via generation check |
| TLS handshake timeout (10s) | Drops connections that stall during handshake |

## Network (Linux)

| Change | Rationale |
|---|---|
| `TCP_NODELAY` | Disables Nagle's algorithm on all connections |
| `SO_REUSEPORT` | Kernel-level connection distribution across listeners |
| `TCP_DEFER_ACCEPT` | Kernel holds connection until client sends data |
| `TCP_FASTOPEN` | Data in SYN packet for returning clients (256 pending queue) |
| `TCP_QUICKACK` | Immediate ACK instead of delayed ACK timer |
| `TCP_CORK` | Batches writes on listener; combined with NODELAY on accept |
| `SO_BUSY_POLL` (50us) | Spin-poll NIC queue before sleeping; trades CPU for latency |
| Listen backlog 1024 | Prevents SYN drops under burst load |
| io_uring single-shot accept | Feature-gated: dedicated accept thread, one SQE re-submitted per connection |

## Proxy

| Change | Rationale |
|---|---|
| HTTP/2 upstream via hyper-rustls | ALPN H2 for HTTPS upstreams; eliminates head-of-line blocking |
| Connection pooling (128 idle per host) | Reuse upstream TCP+TLS connections; 30s idle timeout |
| Hop-by-hop header stripping (RFC 7230) | Transfer-Encoding, TE, Trailer, Proxy-Authorization, Keep-Alive |
| SSE stream: no-buffer headers | `Cache-Control: no-cache`, `X-Accel-Buffering: no` |
| WebSocket: OnceLock TLS config | Root cert store built once, not per WS TLS upgrade |
| WebSocket: forward handshake headers | Sec-WebSocket-Accept, Protocol, Extensions from upstream 101 |

## WAF

| Change | Rationale |
|---|---|
| Aho-Corasick (no regex) | O(N) single-pass, no backtracking; all patterns of the active mode scanned simultaneously |
| Skip body inspection for GET/HEAD/OPTIONS | POST/PUT/PATCH/DELETE bodies are inspected |
| Entropy check only for bodies >= 256 bytes | Short payloads lack sufficient data for meaningful entropy analysis |
| `simd-json` for JSON validation | SIMD-accelerated JSON parsing where hardware supports it |
| Byte-level content-type matching | No string allocation; case-insensitive byte prefix comparison |

## Cache

| Change | Rationale |
|---|---|
| Two-level: L1 thread-local + L2 DashMap | L1 zero contention (~5ns), L2 sharded locks (~30ns) |
| L1 O(1) LRU via doubly-linked list | Index-based nodes in Vec with free-list recycling |
| L1 sized from detected L1d cache | 50% of L1d for hot entries |
| L1/L2 generation coherence | Atomic counter bumped on L2 insert; stale L1 entries detected on get |
| Cache key includes query string | Prevents cache poisoning (/api?a=1 vs /api?a=2) |
| Content-Encoding preserved | Gzip-compressed responses served with correct header |
| Singleflight coalescing | DashMap + `tokio::sync::watch`; `wait_for` inspects current value at first poll, so a waiter that subscribes after the fetcher has already published `true` still observes it (race-free). Inflight entry is cleaned up on all exit paths. |
| L2 eviction: expired-first | TTL-expired before live entries; oldest-TTL fallback |
| `Bytes` (reference-counted) | Cloning is Arc increment, not memcpy |
| Thread-local route LRU | FNV hash of path; O(1) get/insert/evict via intrusive doubly-linked list (capacity 256 per worker). Replaces a previous "first 256 then no more inserts" map that could be locked out by a flood of distinct paths. |
| Connection pool pre-warming | Fires GET to all upstreams at startup |

## Hyper tuning

| Change | Rationale |
|---|---|
| Max headers: 64 (default: 100) | Reduces memory per connection from malformed requests |
| Max header buffer: 16 KB | Limits memory consumption from oversized headers |
| Connection timeout: 1 hour | Supports HTTP/2 mux, WebSocket, SSE long-lived connections |
