# Optimization Log

Changes made to improve throughput and latency, with rationale. Throughput claims reference `wrk` benchmark results from `benchmarks/bench-native.sh`.

## Architectural (v0.1.3)

| Change | Rationale |
|---|---|
| HTTP/2 upstream multiplexing | `hyper-rustls` HttpsConnector with ALPN H2 negotiation for HTTPS upstreams |
| TLS connection pre-warming | Health checks reuse shared HttpClient; startup pre-warm task fires GET to all upstreams |
| `TCP_CORK` on listener (Linux) | Batches TLS record + HTTP headers into full MSS segments |
| Connection pool pre-warming | Fires GET to all upstreams before accept loop starts |
| Thread-local route lookup cache | FNV hash of path maps to cached `Arc<ResolvedRoute>` (~5ns vs ~30ns radix tree) |

## Compiler / Build (v0.1.2)

| Change | Rationale |
|---|---|
| `target-cpu=native` (.cargo/config.toml) | Unlocks NEON/AES-CE on Apple Silicon, AVX2/AES-NI on x86_64 |
| PGO build script (`bench-pgo.sh`) | Two-phase profile-guided optimization for 10-20% additional throughput |

## Hot Path Allocation Elimination (v0.1.2)

| Change | Rationale |
|---|---|
| Traceparent: `[u8;55]` stack buffer | Replaces 3x `format!` heap allocations (-500ns/req) |
| CORS origin: `HeaderValue` clone | Avoids `String` allocation per CORS request |
| WAF content-type: borrow from `parts.headers` | Eliminates `to_owned()` clone on POST/PUT/PATCH |
| Cache key: `Arc::from()` direct | Skips intermediate `String` allocation on cache miss |

## Lock / Contention Reduction (v0.1.2)

| Change | Rationale |
|---|---|
| WebSocket TLS: `OnceLock<Arc<ClientConfig>>` | Builds root cert store once, not per WS upgrade |
| Metrics render: `ArcSwap<(u64, Bytes)>` | Lock-free `/metrics` endpoint, atomic timestamp+buffer pair |
| Histogram: non-cumulative differential buckets | 3 atomic ops per observation instead of 17; prefix sums at render time |
| HTTP builder: `Arc<AutoBuilder>` | Per-connection clone is ref-count bump, not deep copy |

## Data Structures (v0.1.2)

| Change | Rationale |
|---|---|
| L1 cache: O(1) LRU (index-based doubly-linked list) | Replaces O(N) VecDeque linear scan on every cache hit |
| L1/L2 generation-based coherence | Atomic generation counter invalidates stale L1 entries after L2 update |
| Host validation: single-pass byte scan | Replaces 8 separate `contains()` calls with one `iter().any(matches!())` |
| CORS origin: FNV hash set | O(1) lookup replaces `Vec` linear scan; case-insensitive via pre-lowercased storage |

## WAF Pipeline (v0.1.2-v0.1.4)

| Change | Rationale |
|---|---|
| 192 patterns, 14 attack categories | SQLi, XSS (42), CMDi, path traversal, SSRF (14), NoSQL, deserialization, GraphQL, LDAP, XXE, SSTI, CRLF, Log4Shell |
| Aho-Corasick (no regex) | O(N) single-pass, no backtracking, case-insensitive, ReDoS-immune by construction |
| Normalization: iterative until convergence | URL-decode, SQL comment strip, JSON unicode; capped at 2 iterations with equality check |
| Buffer shrink-to-fit (>64KB) | Prevents permanent memory inflation from adversarial large bodies |
| DELETE body inspection | RFC 9110 allows bodies on DELETE; previously skipped |
| Content-Type delimiter enforcement | `application/jsonFOO` no longer matches `application/json` (requires `;` or ` ` delimiter) |

## Innovative (v0.1.2)

| Change | Rationale |
|---|---|
| Request coalescing (singleflight) | N concurrent cache misses = 1 upstream fetch (thundering herd protection) |
| Health probe inline fast-path | `/healthz` responds in ~1us, bypasses full process_request pipeline |
| `SO_BUSY_POLL` (Linux) | Spin-poll NIC queue 50us before sleeping; -5-15us p99 latency |

## Allocator

| Change | Rationale |
|---|---|
| `mimalloc` global allocator | 2-3x faster than system malloc on small allocations; reduces contention |

## TLS

| Change | Rationale |
|---|---|
| TLS 1.3 default | 1-RTT handshake instead of 2-RTT (TLS 1.2) |
| Session cache 16,384 entries | Resumed sessions avoid full ECDHE key exchange |
| Session tickets (Ticketer) | Stateless resumption, works across process restarts |
| 0-RTT early data (16 KB max) | Clients send data before handshake completes (idempotent methods only) |
| `send_half_rtt_data = true` | Server sends data before client Finished on resumed connections |
| `FnvHashMap` for SNI map | Simpler hash function for short hostname keys (~2x faster than SipHash) |
| Thread-local SNI cache | Avoids cross-thread HashMap access; invalidated via dual-generation counter |
| `Acquire`/`Release` ordering for cert generation | Prevents stale cert serving on ARM (Graviton) after hot-reload |
| `sys_membarrier` (Linux) | Ensures all threads observe new cert config after reload |
| Cert pre-warming (120s before expiry) | Pre-builds `ServerConfig` before renewal trigger fires |
| Pre-warm/watcher race protection | Generation check before/after build detects concurrent reloads |
| TLS handshake timeout (10s) | Drops connections that stall during handshake |

## Network (Linux)

| Change | Rationale |
|---|---|
| `TCP_NODELAY` | Disables Nagle's algorithm on all connections |
| `TCP_CORK` | Batches writes on listener; combined with NODELAY on accept for optimal behavior |
| `SO_REUSEPORT` | Kernel-level connection distribution across listeners |
| `TCP_DEFER_ACCEPT` (5s) | Kernel holds connection until client sends data (with warning on failure) |
| `TCP_FASTOPEN` (256 queue) | Data in SYN packet for returning clients |
| `TCP_QUICKACK` | Immediate ACK instead of delayed ACK timer |
| `SO_BUSY_POLL` (50us) | Spin-poll NIC queue before sleeping; trades CPU for latency |
| Listen backlog 1024 | Prevents SYN drops under burst load |
| io_uring multishot accept | Feature-gated: one syscall for N connections |

## Proxy

| Change | Rationale |
|---|---|
| HTTP/2 upstream via hyper-rustls | ALPN negotiation for HTTPS upstreams; eliminates head-of-line blocking |
| Connection pooling (128 idle per host) | Reuse upstream TCP+TLS connections; 30s idle timeout |
| Hop-by-hop header stripping (RFC 7230) | Transfer-Encoding, TE, Trailer, Proxy-Authorization, Keep-Alive, Proxy-Connection |
| SSE stream: no-buffer headers | `Cache-Control: no-cache`, `X-Accel-Buffering: no` |
| WebSocket: OnceLock TLS config | Root cert store built once, not per WS TLS upgrade |
| WebSocket: forward handshake headers | Sec-WebSocket-Accept, Protocol, Extensions from upstream 101 |

## Cache

| Change | Rationale |
|---|---|
| Two-level cache: L1 + L2 | L1 thread-local (zero contention), L2 shared DashMap |
| L1 O(1) LRU via doubly-linked list | Index-based nodes in Vec with free-list recycling |
| L1 sized from detected L1d cache | Bootstrap reads CPU cache info, allocates 50% for L1 entries |
| L1/L2 generation coherence | Atomic counter bumped on L2 insert; stale L1 entries detected on get |
| Cache key includes query string | Prevents cache poisoning (/api?a=1 vs /api?a=2) |
| Content-Encoding preserved | Gzip-compressed responses served with correct header |
| Singleflight coalescing | DashMap + Notify; inflight cleanup on all exit paths (error, disconnect) |
| L2 eviction: expired-first | Scans for TTL-expired entries before evicting live ones |
| `Bytes` (reference-counted) | Cloning cached response is an Arc increment, not memcpy |

## Hyper Tuning

| Change | Rationale |
|---|---|
| Max headers: 64 | Reduces memory per connection from malformed requests |
| Max header buffer: 16 KB | Optimal for L1 CPU cache on micro-payloads (API/CSS) |
| Connection timeout: 1 hour | Supports HTTP/2 mux, WebSocket, SSE long-lived connections |
