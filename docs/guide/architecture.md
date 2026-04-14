# Architecture

Zion is a single async Rust binary built on Tokio, Hyper, and rustls. ~8,600 lines across 17 modules.

## Module Map

```
src/
├── main.rs        # Entrypoint, HTTPS/HTTP listeners, connection handling
├── dispatch.rs    # Request pipeline: routing, WAF gate, cache, CORS, metrics
├── config.rs      # TOML parsing, validation, radix tree construction
├── tls.rs         # TLS config, SNI resolution, session tickets, 0-RTT, hot-reload
├── waf.rs         # 6-gate WAF pipeline (Aho-Corasick, SIMD pre-filter, entropy, simd-json)
├── proxy.rs       # Upstream forwarding (standard, stream, WebSocket, TLS-to-upstream)
├── cache.rs       # Two-level cache: L1 thread-local (O(1) LRU) + L2 DashMap
├── security.rs    # CORS (FNV O(1)), rate limiter, security headers, trusted proxies
├── metrics.rs     # Prometheus: sharded counters, differential histogram, ArcSwap render
├── health.rs      # Upstream health checker, EWMA latency, gray failure detection
├── auth.rs        # JWT/OIDC validation gate (feature: --features auth)
├── acme.rs        # ACME HTTP-01 auto-renewal (feature: --features acme)
├── quic.rs        # HTTP/3 QUIC listener (feature: --features http3)
├── uring.rs       # io_uring multishot accept (feature: --features io-uring-accept)
├── bootstrap.rs   # Platform detection (CPU, RAM, L1d cache, AES-NI/NEON, kernel features)
├── net.rs         # Socket tuning (SO_REUSEPORT, TCP_FASTOPEN, TCP_QUICKACK, SO_BUSY_POLL)
└── logging.rs     # Structured logging (text/JSON)
```

## Request Lifecycle

```
Client
  │
  ├─ HTTP :80 ──────► ACME challenge proxy OR 301 → HTTPS
  │
  ├─ HTTPS :443 (TCP) ──► TLS 1.3 (HTTP/1.1 + HTTP/2)
  │
  └─ HTTPS :443 (UDP) ──► QUIC (HTTP/3, feature-gated)
       │
       ▼
  ┌─ TLS Handshake ─────────────────────────────────────┐
  │  rustls + SNI resolution (SingleCert or SniResolver) │
  │  Session cache (16384 entries), 0-RTT early data     │
  │  Hardware crypto: AES-NI (x86), AES-CE (ARM)        │
  └──────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Health Probe Fast-Path ───────────────────────────┐
  │  /healthz, /readyz → 200 OK (~1us, bypasses below) │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Pre-routing Security Gates ──────────────────────────┐
  │  1. URI length check (path+query >8192 bytes → 414)   │
  │  2. Method whitelist (7 methods, else 405)             │
  │  3. 0-RTT replay protection (non-idempotent → 425)    │
  │  4. Client IP resolution (rightmost-untrusted-hop)     │
  │  5. Per-IP rate limiter (DashMap + atomic, lock-free)  │
  │  6. Built-in endpoints (/metrics → internal IPs only)  │
  │  7. CORS pre-flight (OPTIONS → 204 with headers)       │
  └────────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Radix Tree Route Lookup ──────────────────────────┐
  │  matchit router → ResolvedRoute (pre-parsed URI,   │
  │  upstream, WAF profile, cache config, auth profile) │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Auth Gate (if --features auth + auth_profile set) ┐
  │  JWT validation: HMAC/RSA/ECDSA via jsonwebtoken   │
  │  Claims forwarded as X-Auth-Subject, X-Auth-Email  │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ WAF Pipeline (if enabled on route) ───────────────┐
  │  SIMD pre-filter: memchr3 fast-reject (clean → skip)│
  │  Gate 1: Body size enforcement (O(1))               │
  │  Gate 2: Content-Type validation (delimiter-aware)  │
  │  Gate 3: Aho-Corasick injection scan (80+ patterns) │
  │  Gate 4: Entropy analysis (Shannon, >=256 bytes)    │
  │  Gate 5: JSON structural validation (simd-json)     │
  │  Gate 6: Fixed-length profiling                     │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Dispatch by Mode ─────────────────────────────────┐
  │  standard     → proxy_pass (pooled HTTP client)    │
  │  sse_stream   → proxy_pass_stream (no buffering)   │
  │  static_cache → singleflight + L1/L2 lookup/fetch  │
  │  websocket    → HTTP Upgrade + bidirectional pipe   │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Response Processing ──────────────────────────────┐
  │  Security headers (HSTS, XFO, XCTO, Referrer,     │
  │    Permissions-Policy, hop-by-hop stripping)        │
  │  CORS headers (if origin matched, FNV O(1))        │
  │  X-Request-ID (stack-buffer, zero alloc)           │
  │  W3C traceparent (stack-buffer, zero alloc)        │
  │  Alt-Svc: h3 (if --features http3)                │
  │  Prometheus metrics (sharded counters, ~2ns)       │
  └────────────────────────────────────────────────────┘
       │
       ▼
  Client
```

## Design Decisions

| Decision | Rationale |
|---|---|
| `mimalloc` global allocator | 2-3x faster than system malloc on small allocations |
| `ArcSwap` for TLS acceptor + metrics cache | Atomic pointer swap without mutex on hot path |
| `target-cpu=native` build | Unlocks NEON/AES-CE/AVX2 for auto-vectorization |
| Pre-parsed upstream URIs | Scheme + authority parsed once at boot, only path set at runtime |
| `DashMap` for cache + rate limiter | Sharded concurrent map, avoids single-mutex bottleneck |
| `FnvHashSet` for CORS origins | O(1) origin lookup vs O(n) linear scan |
| Thread-local L1 with O(1) LRU | Index-based doubly-linked list, zero contention on cache hits |
| Generation counter for L1/L2 coherence | Stale L1 entries detected via atomic compare, no broadcast needed |
| Singleflight for cache misses | DashMap + Notify coalesces concurrent identical requests |
| Differential histogram buckets | 3 atomic ops per observation instead of 17 (prefix sums at render time) |
| `OnceLock` for WAF scanner + WS TLS | Aho-Corasick / root cert store built once, reused for process lifetime |
| SIMD pre-filter (`memchr3`) | Fast-reject clean bodies before full Aho-Corasick scan |
| Stack buffers for request ID + traceparent | Zero heap allocation on per-request headers |
| `Arc<AutoBuilder>` for HTTP builder | Per-connection clone is ref-count bump, not deep copy |
| io_uring multishot accept (Linux) | Batches N connections per syscall |
| `SO_BUSY_POLL` (Linux) | Spin-poll NIC queue 50us for lower p99 latency |
| Semaphore for connection limit | Bound from detected RAM: `(RAM_MB / 4) * 1024 / 50`, clamped 1k-100k |

## Concurrency Model

Zion uses Tokio's multi-threaded runtime. Worker count is set to available CPU cores (N-1 on machines with >4 cores), pinned to physical cores via `core_affinity`. Each accepted connection is a spawned task. Total concurrent connections are bounded by a Tokio semaphore.

## Optional Features

| Feature | Flag | Description |
|---------|------|-------------|
| ACME auto-renewal | `--features acme` | HTTP-01 challenge, auto-renew via Let's Encrypt |
| JWT/OIDC auth | `--features auth` | Per-route JWT validation (HMAC, RSA, ECDSA, JWKS) |
| HTTP/3 QUIC | `--features http3` | UDP listener on same port, Alt-Svc advertisement |
| io_uring accept | `--features io-uring-accept` | Linux 5.19+, multishot accept batching |

Build with multiple features:
```bash
cargo build --release --features "acme,auth,http3"
```
