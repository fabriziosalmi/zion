# Architecture

Zion is a single async Rust binary built on Tokio, Hyper, and rustls. All state is lock-free. All hot-path operations are zero-allocation where possible.

## Module Map

```
src/
├── main.rs        # Entrypoint, HTTPS/HTTP listeners, request dispatch
├── bootstrap.rs   # Hardware detection, auto-tuning (CPU, RAM, features)
├── config.rs      # TOML parsing, validation, radix tree construction
├── tls.rs         # TLS config, SNI (FNV + thread-local cache), session tickets, 0-RTT, pre-warming
├── waf.rs         # 6-gate WAF pipeline (Aho-Corasick, entropy, simd-json)
├── proxy.rs       # Upstream forwarding (standard, stream, WebSocket)
├── cache.rs       # Two-level cache: L1 thread-local + L2 DashMap, expired-first eviction
├── uring.rs       # io_uring multishot accept (Linux, feature-gated)
├── metrics.rs     # Atomic Prometheus counters
├── health.rs      # Background upstream health checker
└── logging.rs     # Structured logging (text/JSON)
```

## Request Lifecycle

```
Client
  │
  ├─ HTTP :80 ──────► ACME challenge proxy OR 301 → HTTPS
  │
  └─ HTTPS :443
       │
       ▼
  ┌─ TLS Handshake ─────────────────────────────────────┐
  │  rustls + SNI resolution (SingleCert or SniResolver) │
  │  Session tickets + 16384 cache, 0-RTT early data     │
  └──────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Pre-routing Security Gates ────────────────────────┐
  │  1. URI length check (>8192 bytes → 414)            │
  │  2. Method whitelist (GET/POST/PUT/PATCH/DELETE/     │
  │     HEAD/OPTIONS only)                               │
  │  3. Built-in endpoints (/healthz, /readyz, /metrics) │
  │  4. Per-IP rate limiter (DashMap, atomic counters)   │
  │  5. CORS pre-flight (OPTIONS → 204 with headers)    │
  └─────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Radix Tree Lookup (~15ns) ─────────────────────────┐
  │  matchit router → ResolvedRoute (pre-parsed URI,    │
  │  upstream scheme/authority, WAF profile, cache)      │
  └─────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ WAF Pipeline (if enabled) ─────────────────────────┐
  │  Gate 1: Body size (O(1))                           │
  │  Gate 2: Content-Type validation (zero-alloc)       │
  │  Gate 3: Aho-Corasick injection scan (O(N))         │
  │  Gate 4: Entropy analysis (Shannon, >=256 bytes)    │
  │  Gate 5: JSON structural validation (simd-json)     │
  │  Gate 6: Fixed-length profiling                     │
  └─────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Dispatch by Mode ──────────────────────────────────┐
  │  standard     → proxy_pass (pooled HTTP client)     │
  │  sse_stream   → proxy_pass_stream (no-buffer)       │
  │  static_cache → RAM lookup or fetch + cache         │
  │  websocket    → HTTP Upgrade + bidirectional pipe   │
  └─────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Response Processing ───────────────────────────────┐
  │  Security headers (HSTS, XFO, XCTO, Referrer,      │
  │    Permissions-Policy, Server removal)               │
  │  CORS headers (if origin matched)                   │
  │  X-Request-ID (propagate or generate)               │
  │  Metrics recording (atomic increment, ~2ns)         │
  └─────────────────────────────────────────────────────┘
       │
       ▼
  Client
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| `mimalloc` global allocator | 2-3x faster than system malloc on small allocations |
| `ArcSwap` for TLS acceptor | Lock-free atomic pointer swap for hot-reload |
| Pre-parsed upstream URIs | Zero URI parsing per request (done once at boot) |
| `DashMap` for cache + rate limiter | Sharded concurrent map, no mutex contention |
| `FnvHashMap` for SNI lookup | ~3ns hash vs ~18ns SipHash for short hostnames |
| Thread-local SNI cache | ~15ns SNI resolution (generation counter invalidation) |
| io_uring multishot accept (Linux) | One syscall for N connections, feature-gated |
| Two-level L1+L2 cache | L1 thread-local (~5ns), L2 shared DashMap (~30ns) |
| `OnceLock` for WAF scanner | Aho-Corasick automaton built once, used forever |
| Semaphore for connection limit | Scales with detected RAM (25% of total / 50KB per conn) |
| Thread-local IP buffer | Avoids allocation for X-Forwarded-For formatting |
| Static `HeaderValue` constants | Security headers pre-compiled, zero runtime cost |

## Concurrency Model

Zion uses Tokio's multi-threaded runtime with worker count auto-tuned to available CPU cores (N-1 on machines with >4 cores). Each accepted connection gets a spawned task. Connection count is bounded by a semaphore sized to available RAM.
