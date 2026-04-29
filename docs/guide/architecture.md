# Architecture

Zion is a single async Rust binary built on Tokio, Hyper, and rustls. <!-- zion-stats:modules-lines (kept in sync by scripts/update-readme-stats.sh) -->
~15,900 lines across 21 source files.

## Module Map

```
src/
├── main.rs        # Entrypoint, HTTPS/HTTP listeners, connection handling, mTLS fingerprint extraction
├── dispatch.rs    # Request pipeline: routing (LRU + radix), WAF gates, cache, CORS, metrics; thread-local route LRU lives here
├── config.rs      # TOML parsing, validation, radix tree construction
├── tls.rs         # TLS config, SNI resolution, session tickets, 0-RTT, hot-reload, predictive prewarming
├── waf.rs         # 5-gate WAF pipeline (Aho-Corasick balanced/aggressive, entropy, simd-json)
├── proxy.rs       # Upstream forwarding + XffMode policy (append/rewrite/drop), WebSocket TLS-to-upstream
├── cache.rs       # Two-level cache: L1 thread-local (O(1) LRU) + L2 DashMap
├── security.rs    # CORS (FNV O(1)), rate limiter (packed-atomic, lock-free), security headers, trusted-proxy CIDR resolution
├── metrics.rs     # Prometheus: sharded counters, differential histogram, ArcSwap render
├── health.rs      # Upstream health checker, EWMA latency, gray failure detection
├── auth.rs        # JWT/OIDC validation gate (feature: --features auth)
├── acme.rs        # ACME HTTP-01 auto-renewal (feature: --features acme)
├── quic.rs        # HTTP/3 QUIC listener (feature: --features http3)
├── uring.rs       # io_uring multishot accept (feature: --features io-uring-accept)
├── bootstrap.rs   # Platform detection (CPU, RAM, L1d cache, AES-NI/NEON, kernel features) + AES-GCM calibration
├── net.rs         # Socket tuning (SO_REUSEPORT, TCP_FASTOPEN, TCP_QUICKACK, TCP_DEFER_ACCEPT, TCP_CORK, SO_BUSY_POLL)
├── doctor.rs      # `zion doctor` environment diagnostic
├── init.rs        # `zion init` interactive wizard + `zion auto` ephemeral mode (feature: --features init)
├── tui.rs         # `zion top` live dashboard (feature: --features tui)
├── cli.rs         # Command-line argument parsing
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
  │  Hardware crypto: AES-NI (x86), AES-CE (ARM)         │
  │  mTLS (optional): SHA-256 leaf fingerprint extracted │
  │     and forwarded as `X-Client-Cert-Fingerprint`     │
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
  ┌─ Route Lookup ─────────────────────────────────────┐
  │  Thread-local LRU (FNV hash, O(1), cap 256) →      │
  │    fall through to matchit radix tree on miss →    │
  │    promote to MRU. Returns ResolvedRoute (pre-     │
  │    parsed URI, upstream, WAF profile, cache cfg).  │
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
  │  Gate 1: Body size enforcement (O(1))               │
  │  Gate 2: Content-Type validation (delimiter-aware)  │
  │  Gate 3: Aho-Corasick scan — pattern set selected   │
  │           per profile mode (balanced ~120 /         │
  │           aggressive ~190); raw + iterative         │
  │           normalisation (URL-decode, SQL comment    │
  │           strip, JSON unicode), up to 3 passes      │
  │  Gate 4: Entropy analysis (Shannon ≥256 bytes;      │
  │           JSON-string-only for application/json;    │
  │           per-profile threshold + kill-switch)      │
  │  Gate 5: JSON structural validation (simd-json) +   │
  │           depth + per-string length limits          │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Dispatch by Mode ─────────────────────────────────┐
  │  standard     → proxy_pass (pooled HTTP client)    │
  │  sse_stream   → proxy_pass_stream (no buffering)   │
  │  static_cache → singleflight (watch channel) +     │
  │                  L1/L2 lookup/fetch + tee-reader   │
  │                  (cache build runs in parallel     │
  │                  with client streaming)            │
  │  websocket    → HTTP Upgrade + bidirectional pipe  │
  │                  (TLS-to-upstream supported)       │
  │                                                     │
  │  All modes apply X-Forwarded-For policy:           │
  │    append   → preserve inbound chain + add our IP  │
  │    rewrite  → drop inbound, emit single trusted    │
  │    drop     → strip, emit nothing                  │
  └────────────────────────────────────────────────────┘
       │
       ▼
  ┌─ Response Processing ──────────────────────────────┐
  │  Security headers (HSTS, XFO, XCTO, Referrer,      │
  │    Permissions-Policy, hop-by-hop stripping)       │
  │  CORS headers (if origin matched, FNV O(1))        │
  │  X-Request-ID (stack-buffer, zero alloc)           │
  │  W3C traceparent (stack-buffer, zero alloc)        │
  │  Alt-Svc: h3 (if --features http3)                 │
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
| Same primitive for the route LRU | Per-worker thread-local cache (cap 256). Replaces a previous "first 256 then no more inserts" map that could be locked out by a flood of distinct paths. |
| Generation counter for L1/L2 coherence | Stale L1 entries detected via atomic compare, no broadcast needed |
| Singleflight via `tokio::sync::watch` | `Receiver::wait_for` inspects the current value at first poll, so a waiter that subscribes *after* the fetcher has already published completion still observes it — race that the previous `Notify`-based implementation could lose, leaving a waiter hung until the client timed out |
| SHA-256 leaf fingerprint for mTLS forward header | Replaces a 64-bit XOR-fold (which produced massive collision classes) emitted as `X-Client-Cert-DN`. Header renamed to `X-Client-Cert-Fingerprint` and prefixed `sha256:`; ACL via fingerprint is now safe. |
| Differential histogram buckets | 3 atomic ops per observation instead of 17 (prefix sums at render time) |
| `OnceLock` for WAF scanners + WS TLS | One Aho-Corasick automaton per WAF mode (balanced + aggressive); root cert store for upstream WS TLS — both built once on first hit, reused for process lifetime |
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
