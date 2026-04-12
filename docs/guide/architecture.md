# Architecture

Zion is a single async Rust binary built on Tokio, Hyper, and rustls.

## Module Map

```
src/
├── main.rs        # Entrypoint, HTTPS/HTTP listeners, request dispatch
├── bootstrap.rs   # Platform detection at boot (CPU, RAM, kernel features)
├── config.rs      # TOML parsing, validation, radix tree construction
├── tls.rs         # TLS config, SNI resolution, session tickets, 0-RTT, reload
├── waf.rs         # 6-gate WAF pipeline (Aho-Corasick, entropy, simd-json)
├── proxy.rs       # Upstream forwarding (standard, stream, WebSocket)
├── cache.rs       # Two-level cache: L1 thread-local + L2 DashMap
├── uring.rs       # io_uring multishot accept (Linux, feature-gated)
├── metrics.rs     # Prometheus counters (atomic u64)
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
  │  Session cache (16384 entries), 0-RTT early data     │
  └──────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Pre-routing Checks ──────────────────────────────┐
  │  1. URI length check (>8192 bytes → 414)          │
  │  2. Method whitelist (7 methods, else 405)        │
  │  3. Built-in endpoints (/healthz, /readyz, /metrics)│
  │  4. Per-IP rate limiter (DashMap + atomic counter) │
  │  5. CORS pre-flight (OPTIONS → 204 with headers)  │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Radix Tree Route Lookup ──────────────────────────┐
  │  matchit router → ResolvedRoute (pre-parsed URI,   │
  │  upstream, WAF profile, cache config)              │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ WAF Pipeline (if enabled on route) ───────────────┐
  │  Gate 1: Body size (len check)                     │
  │  Gate 2: Content-Type validation (byte prefix)     │
  │  Gate 3: Aho-Corasick injection scan (O(N))        │
  │  Gate 4: Entropy analysis (Shannon, >=256 bytes)   │
  │  Gate 5: JSON structural validation (simd-json)    │
  │  Gate 6: Fixed-length profiling                    │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Dispatch by Mode ─────────────────────────────────┐
  │  standard     → proxy_pass (pooled HTTP client)    │
  │  sse_stream   → proxy_pass_stream (no buffering)   │
  │  static_cache → L1/L2 lookup or fetch + store      │
  │  websocket    → HTTP Upgrade + bidirectional pipe   │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Response Processing ──────────────────────────────┐
  │  Security headers (HSTS, XFO, XCTO, Referrer,     │
  │    Permissions-Policy, Server header removal)       │
  │  CORS headers (if origin matched)                  │
  │  X-Request-ID (propagate or generate)              │
  │  Prometheus counter increment                      │
  └────────────────────────────────────────────────────┘
       │
       ▼
  Client
```

## Design Decisions

| Decision | Rationale |
|---|---|
| `mimalloc` global allocator | Reduces allocation contention under concurrent load vs system malloc |
| `ArcSwap` for TLS acceptor | Atomic pointer swap for certificate reload without mutex on accept path |
| Pre-parsed upstream URIs | URI scheme + authority parsed once at boot, stored in `ResolvedRoute` |
| `DashMap` for cache + rate limiter | Sharded concurrent map, avoids single-mutex bottleneck |
| `FnvHashMap` for SNI lookup | Simpler hash function; beneficial for short keys (hostnames) |
| Thread-local SNI cache | Avoids cross-thread HashMap access; invalidated via generation counter |
| io_uring multishot accept (Linux) | Reduces accept syscalls; feature-gated behind `--features io-uring-accept` |
| Two-level L1+L2 cache | L1 is thread-local (no cross-thread contention), L2 is shared DashMap |
| `OnceLock` for WAF scanner | Aho-Corasick automaton built once on first request, reused for process lifetime |
| Semaphore for connection limit | Bound derived from detected RAM: `(RAM_MB / 4) * 1024 / 50`, clamped 1k–100k |

## Concurrency Model

Zion uses Tokio's multi-threaded runtime. Worker count is set to available CPU cores (N-1 on machines with >4 cores). Each accepted connection is a spawned task. Total concurrent connections are bounded by a Tokio semaphore.
