# Optimization Log

Changes made to improve throughput and latency, with rationale. Throughput claims reference `wrk` benchmark results from `benchmarks/bench-native.sh`.

## Allocator

| Change | Rationale |
|---|---|
| `mimalloc` global allocator | Reduces allocation contention under concurrent load compared to system malloc |

## TLS

| Change | Rationale |
|---|---|
| TLS 1.3 default | 1-RTT handshake instead of 2-RTT (TLS 1.2) |
| Session cache 256 → 16,384 | More resumed sessions avoid full ECDHE key exchange |
| Session tickets (Ticketer) | Stateless resumption, works across process restarts |
| 0-RTT early data (16 KB max) | Clients can send data before handshake completes (idempotent methods only) |
| Server cipher order enforced | `ignore_client_order = true` |
| `send_half_rtt_data = true` | Server sends data before client Finished on resumed connections |
| `FnvHashMap` for SNI map | Simpler hash function for short hostname keys |
| Thread-local SNI cache | Avoids shared HashMap access; invalidated via atomic generation counter |
| Atomic generation counter for reload | Thread-local caches compare generation, no lock needed |
| `sys_membarrier` (Linux) | Ensures all threads observe new cert config after reload |
| Pre-build TLS config before cert expiry | Builds new `ServerConfig` 120s before detected expiry (via ASN.1 DER Not After parser) |
| TLS handshake timeout (10s) | Drops connections that stall during handshake |

## Network (Linux)

| Change | Rationale |
|---|---|
| `TCP_NODELAY` | Disables Nagle's algorithm on all connections |
| `SO_REUSEPORT` | Kernel-level connection distribution across listeners |
| `TCP_DEFER_ACCEPT` | Kernel holds connection until client sends data |
| `TCP_FASTOPEN` | Data in SYN packet for returning clients (256 pending queue) |
| `TCP_QUICKACK` | Immediate ACK instead of delayed ACK timer |
| Listen backlog 1024 (8192 on Linux) | Prevents SYN drops under burst load |
| io_uring multishot accept | Feature-gated (`--features io-uring-accept`): one syscall for N connections |

## Proxy

| Change | Rationale |
|---|---|
| Connection pooling (128 idle per host) | Reuse upstream TCP connections; `pool_max_idle_per_host(128)`, 30s idle timeout |
| Hop-by-hop header removal | Remove Connection, Keep-Alive, etc. before forwarding (RFC 7230) |
| SSE stream: no-buffer headers | `Cache-Control: no-cache`, `X-Accel-Buffering: no` |
| WebSocket: dedicated TCP connection | Long-lived bidirectional, not using pooled HTTP client |

## WAF

| Change | Rationale |
|---|---|
| Aho-Corasick (no regex) | O(N) single-pass, no backtracking, 70+ patterns scanned simultaneously |
| Skip body inspection for GET/HEAD/DELETE/OPTIONS | Only POST/PUT/PATCH bodies are inspected (configurable) |
| Entropy check only for bodies >= 256 bytes | Short payloads lack sufficient data for meaningful entropy analysis |
| `simd-json` for JSON validation | SIMD-accelerated JSON parsing where hardware supports it |
| Byte-level content-type matching | No string allocation; case-insensitive byte prefix comparison |

## Cache

| Change | Rationale |
|---|---|
| Two-level cache: L1 + L2 | L1 is thread-local (no cross-thread access), L2 is shared DashMap |
| L1 sized from detected L1d cache | Bootstrap reads CPU cache info, allocates 50% for L1 entries |
| L1 LRU eviction | Monotonic counter tracks access recency |
| L2 eviction: expired-first | Scans for TTL-expired entries before evicting live ones |
| L2 fallback: oldest-TTL | `min_by_key(expires_at)` when no expired entries found |
| `Bytes` (reference-counted) | Cloning cached response is an Arc atomic increment, not a memcpy |
| L1 TTL check on read | L1 entries carry TTL from L2, prevents serving stale data |
| Max-entry eviction | Two-phase: expired sweep + oldest eviction when at capacity |

## Hyper Tuning

| Change | Rationale |
|---|---|
| Max headers: 64 (default: 100) | Reduces memory per connection from malformed requests |
| Max header buffer: 32 KB (default: 400 KB) | Limits memory consumption from oversized headers |
| Request timeout: 60s | Drops connections that don't complete a request |
