# Changelog

All notable changes to Zion Edge Gateway are documented here.

## [0.1.7] - 2026-04-29

Hardening pass: closes one concurrency bug, removes one foot-gun, replaces
two stale defaults, and aligns README + docs 1:1 with the code.

### Fixed (correctness)
- **Singleflight cache miss could hang waiters until client timeout.** The
  previous `tokio::sync::Notify`-based coalesce had a race: if the fetcher
  completed between the waiter's `inflight.get()` and its `.notified().await`,
  the wake was missed because `notify_waiters()` does not store a permit.
  Replaced with `tokio::sync::watch::Sender<bool>`; `Receiver::wait_for`
  inspects the current value at first poll, so a late subscriber still
  observes completion. Verified with a deterministic test that pins the
  post-completion subscribe path. (`src/dispatch.rs`, `src/main.rs`)
- **`X-Client-Cert-DN` was a 64-bit XOR-fold of the leaf DER.** The header
  name implied a Distinguished Name but the value had massive collision
  classes (any two certs whose first 64 bytes XOR-equal collide) and no
  cryptographic property. Replaced with `X-Client-Cert-Fingerprint:
  sha256:HEX` (SHA-256 of the leaf DER, openssl/nginx convention). Tests
  pin the format and the NIST SHA-256 vector.
  **Breaking:** consumers reading `X-Client-Cert-DN` must migrate.
  (`src/main.rs`, `src/tls.rs`)
- **Thread-local route cache stopped accepting inserts at 256 entries.**
  Was `if c.len() < 256 { insert }` — a flood of distinct paths could
  permanently lock out subsequent hot-route promotion. Replaced with a real
  O(1) LRU (intrusive doubly-linked list backed by a Vec, free-list for
  index recycling). Adversarial-flood test pins the fix. (`src/dispatch.rs`)
- **WAF Gate 6 was advertised but not implemented.** The module header and
  several doc pages described a sixth "fixed-length profiling" gate that
  did not exist in `validate_request`. Removed the advertisement; the WAF
  is now described as 5 gates (its real shape) everywhere.

### Changed (defaults)
- **WAF detection modes.** New `WafProfile.mode = "balanced" | "aggressive"`.
  `balanced` is the default (high precision: ~120 anchored / CVE-class
  patterns). `aggressive` is opt-in (~190 patterns total: balanced plus
  ~70 broad-substring patterns including `alert(`, `eval(`, `confirm(`,
  `document.cookie`, `innerhtml`, `$gt`, `$ne`, `$regex`, `os.system(`,
  `pickle.loads`, `Runtime.getRuntime`, generic event handlers like
  `onclick=`/`onmouseover=`/…). The previous monolithic 192-pattern set
  flagged a long list of legitimate developer-tool / educational / log-
  shipping payloads — those patterns are now opt-in via aggressive mode.
  - **Breaking for users who relied on those patterns:** add
    `mode = "aggressive"` to the relevant `[waf_profile.X]`.
- **Entropy gate threshold raised from 5.5 to 6.5 bits/byte** (now
  per-profile via `entropy_threshold`). The old default flagged any
  base64 / JWT / signed URL of meaningful length — pure base64 has a
  theoretical max entropy of 6.0, so 5.5 was below it. The new default
  sits clearly above 6.0 and still flags random/encrypted blobs (~7.5–8.0).
  Per-profile kill-switch via `entropy_check = false`.
- **JSON-aware entropy.** For `application/json` content-types, the gate
  now computes Shannon entropy only on bytes inside string literals,
  skipping structural punctuation and numeric tokens that would otherwise
  dilute the signal. Skipped entirely if string-content < 128 bytes.
- **`bootstrap.calibration_us` is now `Option<u64>`.** Previously the
  field reported the few microseconds spent in the `ZION_BOOT_FAST=1`
  env-var check as if it were a real measurement; CI/Ansible consumers
  could not distinguish "calibrated in 80 ms" from "skipped, here's
  21 µs of overhead." JSON snapshot serialises `null` when skipped.

### Added
- **`server.xff_mode = "append" | "rewrite" | "drop"`** outbound XFF
  policy. `append` (default) preserves the previous behaviour (safe
  behind a sanitising edge). `rewrite` strips inbound XFF and emits a
  single trusted entry — recommended when Zion is the front edge,
  closes the spoofing foot-gun where attacker-controlled `XFF[0]`
  reached upstream apps. `drop` strips inbound and emits nothing.
  `X-Real-IP` is now always sourced from the resolved client IP and
  never trusted from an inbound header. (`src/proxy.rs`, `src/config.rs`,
  `src/dispatch.rs`, `src/main.rs`)
- `scripts/update-readme-stats.sh`: rewrites README badges (modules /
  lines / unit-test count) from authoritative sources, with a `--check`
  mode for CI.

### Operations
- **`bench-native.sh` now tracks `Non-2xx or 3xx responses`** and aborts
  the run if any non-success response was returned. The previous script
  honoured the "Zero-error tolerance" claim only for socket errors —
  503-flood scenarios produced clean-looking output.
- **Removed crate-level `#![allow(dead_code)]`, `#![allow(unused_imports)]`,
  `#![allow(unused_variables)]`** from `src/main.rs`. The 17 warnings that
  surfaced are all addressed: unused imports removed, true dead code
  deleted, feature-gated symbols annotated puntually with comments.
  `cargo build --release` now emits 0 warnings; CI can pin this with
  `RUSTFLAGS='-D warnings'`.

### Tests
- 261 → **300** unit tests passing. New tests cover: 4× singleflight
  primitive (incl. the post-completion subscribe path), 4× SHA-256 mTLS
  fingerprint (format / NIST vector / determinism / diffusion), 8× route
  LRU (incl. adversarial flood), ~30× WAF balanced-vs-aggressive contract
  (`balanced_allows_*` + `aggressive_denies_*`) + 5× entropy gate
  (base64 passes, random blocks, kill-switch, configurable threshold,
  JSON-string-only function), 11× XFF policy (append preserves spoofed,
  rewrite strips multi-hop, drop emits nothing, X-Real-IP never trusted).
- `tests/integration.rs`: 19 integration tests unchanged.

### Documentation
- Full audit of `README.md` and `docs/`. Removed: `192 patterns / 14
  categories` claim (replaced with mode-aware description), `6-gate
  pipeline` (5 gates was always the truth), `SIMD pre-filter (memchr3)`
  (never existed), `Zero false positives` (was AI-slop marketing,
  contradicts the WAF reality), `~8,600 lines / 17 modules` (now
  ~15,900 / 21, kept in sync by the script), stale version strings,
  the false claim that Zion "rejects requests on detection of double
  encoding" (it actually re-scans after each decode pass, up to 3).
  Added: `Detection Modes` section (`docs/config/waf.md`),
  `X-Forwarded-For Policy` and `mTLS Client Certificate Forwarding`
  sections (`docs/security/hardening.md`), updated `zion.example.toml`
  with all new fields.

## [0.1.4] - 2026-04-15

### WAF Pattern Expansion (88 -> 192, +104 patterns)

14 attack categories, zero false positives, single O(N) Aho-Corasick pass.

**New categories:**
- XSS Event Handlers (+21): oninput=, onchange=, ondragstart=, ontouchstart=, onpointerover=, etc.
- XSS Tags (+7): img src, body onload, video onerror, details ontoggle, math xlink
- XSS JS Sinks (+7): confirm(, prompt(, window.location, innerHTML, outerHTML, srcdoc=
- NoSQL Injection (+12): $gt, $ne, $regex, $where, .find({, .aggregate([
- Deserialization/RCE (+16): Java (Runtime.getRuntime), Python (pickle.loads, os.system), PHP (unserialize, php://filter, phar://)
- GraphQL Injection (+6): __schema, __type, introspection probes
- LDAP Injection (+6): )(cn=*, ldap://, )(objectclass=*
- XML/XXE (+8): <!ENTITY, SYSTEM "file://, <xsl:, data:text/html
- SSTI (+6): #{7*7}, ${7*7}, {{7*7}}, <%=, {%import
- CRLF/Header Injection (+4): %0d%0a, %0aSet-Cookie:, %0aLocation:
- SSRF Cloud (+5): Azure IMDS, DigitalOcean, Oracle Cloud, Kubernetes, OpenStack
- Windows Path Traversal (+3): C:\windows\, C:\inetpub\
- Open Redirect (+2): /\evil, /%09/

**Tests:** 177 passed (+23 vs v0.1.3), including false-positive safety checks.

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
