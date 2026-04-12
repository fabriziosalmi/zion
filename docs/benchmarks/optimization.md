# Optimization Log

Timeline of performance changes with measured impact. All measurements taken with wrk, 4 threads, 100 connections.

## Architecture-Level Optimizations

| Change | Impact | Rationale |
|---|---|---|
| `mimalloc` global allocator | +15-25% throughput | Faster small allocations, reduced contention under concurrency |
| Pre-parsed upstream URIs at boot | -1 URI parse per request | `Scheme` + `Authority` stored in `ResolvedRoute`, only path set at runtime |
| Thread-local IP buffer for X-Forwarded-For | Zero allocation per request | Reuses a 45-byte buffer via `thread_local!` |
| Static `HeaderValue` constants | ~25ns for 5 security headers | Pre-compiled at compile time, just `clone()` (Arc increment) |
| `ArcSwap` for TLS acceptor | Lock-free hot-reload | No mutex on the TLS accept path |

## TLS Optimizations

| Change | Impact | Rationale |
|---|---|---|
| TLS 1.3 default | 1 fewer RTT per handshake | 1-RTT vs 2-RTT handshake |
| Session cache 256 → 16,384 | Fewer full key exchanges | Each resumed session saves ~1ms ECDHE |
| Session tickets (Ticketer) | Stateless resumption | No server-side storage, works across restarts |
| 0-RTT early data (16 KB) | Data in first flight | Clients send data before handshake completes |
| Server cipher order | Strongest cipher selected | `ignore_client_order = true` |
| `send_half_rtt_data = true` | Data sent before client Finished | Cuts latency on resumed connections |
| FNV hash for SNI map | ~2x faster than SipHash | Short keys (hostnames) benefit from simpler hash |
| Thread-local SNI cache | ~15ns SNI lookup | Avoids HashMap contention, generation-tracked invalidation |
| CERT_GENERATION atomic counter | Lock-free reload detection | Thread-local caches check generation, no lock needed |
| `sys_membarrier` (Linux) | Cross-CPU visibility | Ensures all threads see new cert after reload |
| Predictive cert pre-warming | Zero-latency rotation | Builds new TLS config 120s before cert expiry |
| ASN.1 DER cert expiry parser | No OpenSSL dependency | Minimal parser for Not After field only |
| TLS handshake timeout (10s) | Prevents slowloris on TLS | Drops connections that stall during handshake |

## Network Optimizations

| Change | Impact | Rationale |
|---|---|---|
| `TCP_NODELAY` on all connections | Reduced latency | Disables Nagle's algorithm |
| `SO_REUSEPORT` (Linux) | Kernel-level load balancing | Multiple listeners, no accept contention |
| `TCP_DEFER_ACCEPT` (Linux) | Fewer wakeups | Kernel holds connection until client sends data |
| `TCP_FASTOPEN` (Linux) | 0-RTT TCP for returning clients | Data in SYN packet, 256 pending queue |
| `TCP_QUICKACK` (Linux) | ~40ms RTT reduction | Immediate ACK, no delayed ACK timer |
| Listen backlog 1024 (8192 on Linux) | Handle burst connections | Prevents SYN drops under load |
| io_uring multishot accept (Linux) | One syscall for N connections | Feature-gated: `--features io-uring-accept` |

## Proxy Optimizations

| Change | Impact | Rationale |
|---|---|---|
| Connection pooling (128 idle per host) | Reuse upstream TCP connections | `pool_max_idle_per_host(128)`, 30s idle timeout |
| Hop-by-hop header removal | Correct HTTP proxy behavior | Remove `Host`, `Connection` before forwarding |
| SSE stream: no-buffer headers | Real-time event delivery | `Cache-Control: no-cache`, `X-Accel-Buffering: no` |
| WebSocket: dedicated TCP connection | No pool interference | Long-lived, bidirectional, not using pooled client |

## WAF Optimizations

| Change | Impact | Rationale |
|---|---|---|
| Aho-Corasick (no regex) | O(N) single-pass, ReDoS-immune | 70+ patterns scanned simultaneously |
| Skip body inspection for GET/HEAD/DELETE/OPTIONS | Zero cost for read requests | Only POST/PUT/PATCH bodies are inspected |
| Entropy check only for bodies >= 256 bytes | Saves ~1us per small POST | Short payloads lack sufficient data for meaningful analysis |
| `simd-json` for JSON validation | 10x faster than serde_json | SIMD-accelerated parsing where available |
| Zero-alloc content-type matching | No string allocation | Byte-level prefix comparison, case-insensitive |

## Cache Optimizations

| Change | Impact | Rationale |
|---|---|---|
| Two-level cache: L1 + L2 | ~5ns L1 hit, ~30ns L2 hit | L1 thread-local (zero contention), L2 shared DashMap |
| L1 sized from L1d cache detection | Optimal per-CPU utilization | Bootstrap detects L1d size, allocates 50% for cache entries |
| L1 LRU eviction | Keeps hot entries | Monotonic counter, evict least recently accessed |
| L2 eviction: expired-first | Reclaims dead entries | Scans for TTL-expired before evicting live entries |
| L2 fallback: oldest-TTL | Approximates FIFO | `min_by_key(expires_at)` when no expired entries found |
| `Bytes` (reference-counted) | Zero-copy cache serve | Cloning cached response is an atomic increment |
| L1 TTL check on read | Prevents stale serves | L1 entries carry TTL from L2 |
| Max-entry eviction | Bounded memory | Two-phase: expired sweep + oldest eviction |

## Hyper Tuning

| Change | Impact | Rationale |
|---|---|---|
| Max headers: 64 (default: 100) | Header bomb prevention | Reduces attack surface |
| Max header buffer: 32 KB (default: 400 KB) | Memory protection | Prevents header-based memory exhaustion |
| Request timeout: 60s | Slowloris protection | Kills connections that don't complete a request |
