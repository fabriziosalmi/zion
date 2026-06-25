# Zion Edge Gateway

<!-- Build status -->
[![CI](https://github.com/fabriziosalmi/zion/actions/workflows/ci.yml/badge.svg)](https://github.com/fabriziosalmi/zion/actions/workflows/ci.yml)
[![Supply chain](https://github.com/fabriziosalmi/zion/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/fabriziosalmi/zion/actions/workflows/supply-chain.yml)
[![CodeQL](https://github.com/fabriziosalmi/zion/actions/workflows/codeql.yml/badge.svg)](https://github.com/fabriziosalmi/zion/actions/workflows/codeql.yml)

<!-- Security & compliance certifications -->
[![SLSA Level 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/spec/v1.0/levels#build-l3)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/12756/baseline)](https://www.bestpractices.dev/projects/12756)
[![FIPS-ready](https://img.shields.io/badge/FIPS_140--3-ready_(--features_fips)-success.svg)](docs/security/fips.md)
[![ASVS L2](https://img.shields.io/badge/OWASP_ASVS-L2_mapped-blue.svg)](docs/security/asvs.md)

<!-- Project metadata -->
[![Version](https://img.shields.io/github/v/release/fabriziosalmi/zion?include_prereleases&color=blue&label=release)](https://github.com/fabriziosalmi/zion/releases)
[![MSRV](https://img.shields.io/badge/MSRV-1.82%20core%20%2F%201.88%20full-blue.svg)](Cargo.toml)
[![License](https://img.shields.io/github/license/fabriziosalmi/zion)](https://github.com/fabriziosalmi/zion/blob/master/LICENSE)

<!-- Capabilities -->
[![Performance](https://img.shields.io/badge/TLS_proxy-107k%20req%2Fs%20%C2%B7%20cache%20222k%20(M4)-success?style=flat&color=brightgreen)](https://github.com/fabriziosalmi/zion/tree/master/benchmarks)
[![WAF](https://img.shields.io/badge/WAF-Zero%20Regex-orange)](https://github.com/fabriziosalmi/zion/blob/master/src/waf.rs)

<p align="center">
  <img src="docs/img/boot.png" alt="Zion boot output: live AES-GCM calibration, performance tier badge, routes table, and ready banner" width="720">
</p>

High-performance TLS reverse proxy with built-in WAF, written in Rust.

## Performance

### Native Benchmark (Apple M4, v0.4.2, Rust backend, 5×10s, c=100, wrk)

End-to-end TLS 1.3 over loopback to a zero-overhead hyper backend. Median of 5
runs; **0 errors (all 2xx) on every row**.

| Endpoint | Path | Median req/s | CV% |
|---|---|--:|--:|
| TLS proxy — JS 4KB | `/_next/static/chunk.js` | **108,055** | 1.3% |
| TLS proxy — API GET 1KB | `/api/v1/data` | **107,220** | 8.3% |
| TLS proxy — PNG 8KB | `/_next/static/hero.png` | **104,851** | 0.7% |
| TLS proxy — HTML SSR 5KB | `/` | **102,658** | 2.8% |
| TLS proxy — WOFF2 16KB | `/_next/static/font.woff2` | **92,748** | 0.8% |
| TLS + **WAF** — POST JSON | `/api/v1/data` | **101,295** | 3.7% |
| TLS + **cache hit** — JS 4KB (RAM) | `/_next/static/chunk.js` | **190,532** | 2.2% |
| TLS + **cache hit** — CSS 3KB (RAM) | `/_next/static/style.css` | **222,410** | 1.9% |
| **WAF** — SQLi / XSS | — | blocked (400) | — |

**Reliable baseline**: ~**100–108k req/s** end-to-end TLS proxy to a live upstream
(92k for 16 KB bodies), ~**101k** with the WAF scanning every request, and
**190–222k** for cache hits served from RAM — all at **zero errors**. Peak
(cache, CSS): **222k req/s**. (Reference: the bare hyper backend tops out at
~255k req/s, so the proxy path costs ~2.4× for TLS termination + relay.)

Reproduce: `bash benchmarks/certs/generate.sh && bash benchmarks/bench-native.sh`

> **Corrected number.** Earlier READMEs headlined "HTML SSR 5KB — 233k req/s".
> That was an artifact: before v0.4.2 the bare `/` did not match the catch-all
> route (a matchit edge case) and returned **404**, so the benchmark was timing a
> 404 error path — not a proxied response (verified: that run was 100% non-2xx).
> v0.4.2 (#171) fixes the routing; `/` now correctly proxies the 5 KB HTML at
> ~103k, in line with every other proxy path. The honest baseline above replaces
> the bogus peak.

### Fair comparison with nginx 1.27 (Docker, v0.4.2, 1 CPU / 256 MB each, c=100, 10s×5)

Both behind identical cgroup limits, same backend, same TLS material, HTTP/1.1
over TLS 1.3 (wrk has no h2 client). Median ± CI95, **0 errors** on every cell,
all CV < 15%. Response sizes verified byte-identical nginx-vs-Zion per endpoint.

| Endpoint | nginx 1.27 | Zion TLS | Zion +WAF | Zion full (cache) | Best Δ vs nginx |
|---|--:|--:|--:|--:|--:|
| API GET 1KB | 26,008 | 25,041 | 25,342 | 24,230 | −3% |
| HTML SSR 5KB | 20,520 | 14,944 | 16,084 | 15,961 | −22% |
| JS 4KB | 21,076 | 16,477 | 17,337 | **31,953** | **+52%** |
| PNG 8KB | 16,510 | 13,081 | 12,689 | **24,142** | **+46%** |
| WAF POST JSON | 24,039 | 24,470 | 23,299 | 20,496 | +2% |
| CSS 3KB | 22,382 | 16,716 | 17,332 | **31,386** | **+40%** |

Honest snapshot (not a victory lap — nginx is mature, hand-tuned C): **nginx
leads raw uncached proxy** by ~3–27%; Zion is **at parity on API GET / WAF POST**
(−3% / +2%) and **wins on cacheable assets** (+40–52%) where its in-RAM cache
skips the origin round-trip — all while terminating TLS 1.3 *and* running the
WAF inline. For a one-month-old Rust proxy that is a solid, honest place to be.

Reproduce: `bash benchmarks/bench-scientific.sh`.

> The previous table claimed "Zion HTML +108% vs nginx" — that was the same
> pre-#171 404 artifact (Zion fast-404'd `/` while nginx served the real HTML).
> This run verifies byte-identical response sizes + 200-only + counts non-2xx,
> so it cannot recur.

## Features

**v0.2.x Tracks (feature-gated, default-off)**
- **XDP pre-filter** (`--features xdp`, Linux): eBPF LPM-trie drop at the NIC driver layer. Blocked source IPs never reach the userspace TLS handshake — frees CPU for legitimate traffic and keeps the WAF gate cheap.
- **kTLS post-handshake offload** (`--features ktls`, Linux 5.10+ with `CONFIG_TLS=y`): once the rustls handshake completes the socket is flipped into in-kernel TLS via `SOL_TLS`. Removes the userspace AEAD trip and unlocks `sendfile`-class zero-copy for static cache hits. Handshake cipher must be TLS 1.3 AES-GCM or ChaCha20-Poly1305. Falls back to userspace TLS on upgrade failure.
- **ML-augmented WAF** (`--features ml-waf`): 16-dim feature extractor + tract-onnx scorer on the WAF hot path, 200µs p99 budget. The score is reported as a metric and travels into the request as a header — never a hard gate; the local Aho-Corasick + entropy gate stays authoritative.
- **AIMP serverless mesh** (`--features sovereign-aimp`): Ed25519-signed UDP gossip of WAF rule deltas + IP-reputation across a fleet, source-bound revocation, replay LRU, ts-window admission, last-writer-wins merge, periodic anti-entropy. No central control plane — each node keeps serving with its last known map when the mesh partitions. Configure under `[sovereign_aimp]` in `zion.toml` (or via `ZION_AIMP_*` env vars for back-compat).

**Core Proxy**
- TLS 1.3 termination (rustls + hardware crypto: AES-NI, AES-CE)
- HTTP/2 upstream multiplexing (hyper-rustls ALPN negotiation)
- Multi-SNI with per-domain certificates and FNV hash lookup
- Zero-downtime TLS and QUIC hot-reload (ArcSwap + watch channels)
- Zero-downtime config hot-reload — `zion.toml` changes (routes, upstreams, WAF profiles, CORS, rate-limit, XFF policy, trusted proxies, **listen ports**) atomic-swap into the running process. Listener rebind: edit `[server.listen_*]`, save, the daemon binds the new address and drains the old one without dropping in-flight connections. Invalid configs and bind failures are rejected; the previous state survives. Generation counter exposed via Prometheus and `/_zion/snapshot.json`. See [`docs/deploy/hot-reload.md`](https://fabriziosalmi.github.io/zion/deploy/hot-reload).
- Session tickets + 0-RTT early data with method gating (425 Too Early, RFC 8470)
- ACME auto-renewal via `instant-acme` (HTTP-01, `--features acme`)
- JWT/OIDC authentication gate (`--features auth`)
- HTTP/1.1, HTTP/2, HTTP/3 QUIC (`--features http3`)
- WebSocket proxy (HTTP Upgrade + bidirectional pipe, TLS-to-upstream)
- SSE streaming proxy (zero-buffer)

**Cache**
- Two-level RAM cache: L1 thread-local (O(1) LRU, intrusive linked list) + L2 DashMap
- L1/L2 generation-based coherence (no stale data after update)
- Request coalescing (singleflight): N concurrent cache misses → 1 upstream fetch (`tokio::sync::watch`-based, race-free even when the fetcher completes between subscribe and await)
- Thread-local route LRU (FNV hash, O(1) get/insert/evict — capacity 256 entries per worker)
- Connection pool pre-warming at startup

**WAF (Zero-Regex, O(N) Single-Pass)**
- Aho-Corasick scanner with two pattern sets:
  - `balanced` (default): ~100 high-precision patterns — anchored SQLi/XSS/CMDi, specific SSRF endpoints, CVE-class strings (Log4Shell, XXE)
  - `aggressive` (opt-in via `mode = "aggressive"`): adds ~90 broad-substring patterns (`alert(`, `eval(`, `$gt`, `os.system(`, generic event handlers) for higher recall on admin/internal routes
- Shannon entropy analysis (default 6.5 bits/byte; for JSON, computed on string literals only). Configurable threshold + kill-switch per profile.
- simd-json structural validation (depth + string length limits)
- Content-Type strict validation with delimiter enforcement
- Body size enforcement, DELETE body inspection
- Iterative normalization (URL-decode, SQL comments, JSON unicode escape)
- mTLS forward header: `X-Client-Cert-Fingerprint: sha256:HEX` (SHA-256 of leaf DER)
- Outbound `X-Forwarded-For` policy: `append` (default), `rewrite` (single trusted entry), `drop`

**Security**
- HSTS (2-year, includeSubDomains, preload), X-Content-Type-Options, X-Frame-Options
- Referrer-Policy, Permissions-Policy, per-route CSP
- Server header stripped, hop-by-hop headers stripped (RFC 7230)
- URI length limit (8 KB path+query), method whitelist (7 methods)
- Per-IP rate limiting (lock-free atomic, configurable window)
- Per-IP concurrent-connection cap (`max_connections_per_ip`, enforced at accept; 0 = off)
- CORS with FNV O(1) origin lookup, case-insensitive (RFC 6454)
- TLS handshake timeout (10s), connection timeout (1h for H2/WS/SSE)
- Header bomb prevention (64 headers, 16 KB buffer)

**Observability**
- `/healthz`, `/readyz` inline fast-path (~1us, bypasses full pipeline)
- `/metrics` Prometheus text format (lock-free sharded counters, differential histogram)
- `X-Request-ID` (stack-buffer, zero-alloc) + W3C `traceparent` propagation
- Structured logging (text or JSON)

**Operations**
- Config validation at startup (fail fast, validates all profile references)
- Graceful drain on shutdown (30s timeout, semaphore-tracked)
- Adaptive upstream recovery (#173): healthy upstreams probed every 30 s; a DOWN upstream is re-probed on a per-upstream **decorrelated-jitter backoff** (100 ms → 3 s cap, AWS/Brooker), so a recovered origin returns to service in **~1.4 s instead of up to 30 s** (~21× faster, measured on the v0.4.2 e2e rig) — jitter avoids a recovery thundering-herd. EWMA latency (α=0.125) + gray-failure circuit breaker (ignores EWMA > 2000 ms). Backoff state survives config reload (Arc-reuse); request path stays lock-free.
- Bootstrap auto-detection (CPU cores, RAM, L1d cache, AES-NI/NEON, kernel features)
- Performance Tier badge at boot (S/A/B/C with live AES-GCM calibration)
- Live TUI dashboard (`zion top`, opt-in `--features tui`)
- Interactive bootstrap wizard (`zion init`, opt-in `--features init`)
- One-shot dev mode (`zion auto --upstream :3000`, opt-in `--features init`)
- Environment diagnostic (`zion doctor`, always-on)
- Platform JSON dump for CI / automation (`zion bootstrap`)
- WAF Shadow Mode (`waf_shadow = true`) — log + count, never block
- JSON snapshot endpoint (`/_zion/snapshot.json`, internal-only)
- TCP tuning: TCP_NODELAY, TCP_DEFER_ACCEPT, TCP_FASTOPEN, TCP_QUICKACK, SO_BUSY_POLL
- SO_REUSEPORT, sys_membarrier, io_uring single-shot accept (Linux, `--features io-uring-accept`)
- `target-cpu=native` build optimization, PGO build script included
- systemd unit file + Docker HEALTHCHECK

## Sovereign edge & DDoS resistance

Zion is built to be the **operator's toolkit at the edge** — sharp,
composable primitives with explicit knobs, not an auto-magic black box.
You bring the playbook; Zion gives you the levers, each cheap enough to
leave on under load. Defence is layered, outside-in:

| Layer | Primitive | Status |
|---|---|---|
| **L3/4 — NIC** | XDP eBPF LPM-trie source drop (`--features xdp`); blocked IPs never reach the TLS handshake. AIMP-synced blocklist feeds the trie. | ✅ shipping |
| **L7 — pre-routing** | Zero-cost edge gates before any work: URI-length cap, method whitelist, XFF-spoof-resistant client-IP resolution (no rate-limit bypass via forged `X-Forwarded-For`). | ✅ shipping |
| **L7 — admission** | Per-IP **rate** limiter (lock-free fixed-window, `429` over budget) **and** per-IP **concurrent-connection** cap (`max_connections_per_ip`, enforced at accept before the TLS handshake) — the connection-exhaustion lever a slow/backed flood actually hits. Global ceiling = the platform connection semaphore. | ✅ shipping |
| **L7 — inspection** | WAF: zero-regex Aho-Corasick O(N) single-pass, Shannon entropy, simd-json structural limits, 5 gates. | ✅ shipping |
| **Origin tagging** | IT/EU range classification (`--features geo-ita` / `geo-eu`), **IPv4 + IPv6** — O(log N) binary search over baked CIDR data + one atomic, **no GeoIP DB, no syscall**. Class lands on the request (`extensions`), a metric, and an optional log. Answers "% EU vs non-EU traffic" out of the box (see [observability](https://fabriziosalmi.github.io/zion/guide/observability)). | ✅ shipping |
| **Fleet signal** | AIMP serverless mesh (`--features sovereign-aimp`): Ed25519-signed UDP gossip of blocks + IP-reputation, source-bound revocation, no central control plane. Reputation rides to the upstream as `X-Zion-Mesh-Score`. | ✅ shipping (advisory) |
| **Tag-driven enforcement** | `[sovereign.enforce]` (`#150`) promotes the origin tag / mesh score from *signal* to an opt-in `403` deny — e.g. `deny = ["unknown"]` blocks every non-EU source while EU classes pass (sovereign allowlist by complement), or deny above an AIMP reputation threshold. Off by default; local WAF / rate-limit / auth stay authoritative. Counted in `zion_enforcement_denied_total{reason}`. | ✅ shipping |
| **L7 tarpit** | `[sovereign.enforce.tarpit]` (`#151`) escalates an enforcement deny from a cheap `403` to a *held* connection: a flagged source is parked `hold_secs` before the refusal, so a backed flood pays wall-clock + socket budget instead of an instantly-recyclable reject. A hard global ceiling (`max_concurrent`) sheds back to an immediate `403`, so the tarpit can't self-DoS. Off by default. Metrics `zion_tarpit_{active,total,shed_total,held_ms_total}`. | ✅ shipping |

The design rule: tagging and reputation never *silently* gate — the
operator opts a signal into enforcement explicitly, and the local
rate-limiter / WAF / auth stay authoritative.

## Quick Start

Fastest path — TLS proxy in front of a dev backend with one command:

```bash
cargo build --release --features init,tui
./target/release/zion auto --upstream :3000          # generates ephemeral cert + config, runs daemon
```

Zero config, 30 seconds to a tuned production-style setup:

```bash
./target/release/zion init        # interactive wizard: detects local ports, generates zion.toml + self-signed cert
./target/release/zion doctor      # environment check (fd limit, kernel, AES, port-bind perms)
./target/release/zion bootstrap   # dump detected platform as JSON (CI / Ansible / Terraform)
ZION_CONFIG=zion.toml ./target/release/zion        # run
./target/release/zion top         # live dashboard (in another terminal)
```

For automation / CI / container init, the wizard runs unattended:

```bash
./zion init -y \
    --hostname api.example.com \
    --upstream backend=127.0.0.1:8000 \
    --upstream frontend=127.0.0.1:3000
```

Build flavors:

```bash
cargo build --release                            # bare daemon, lean binary
cargo build --release --features init            # + zion init wizard with cert generation
cargo build --release --features tui             # + zion top live dashboard
cargo build --release --features acme            # + Let's Encrypt auto-renewal (HTTP-01)
cargo build --release --features auth            # + JWT/OIDC authentication gate
cargo build --release --features http3           # + HTTP/3 QUIC listener
cargo build --release --features otel            # + OpenTelemetry tracing + OTLP export
cargo build --release --features fips            # + FIPS 140-3 build (aws-lc-rs validated backend)
cargo build --release --features geo-ita         # + Italian ASN/gov/ISP ranges (sovereign edge)
cargo build --release --features io-uring-accept # Linux 5.19+: single-shot accept
```

Stack flavors for a "max" build:

```bash
cargo build --release --features init,tui,acme,auth,http3,otel
```

## Live Dashboard (`zion top`)

Once a Zion daemon is running, `zion top` opens an htop-style TUI with traffic
counters, latency quantiles (p50/p95/p99), status-class breakdown, cache hit
rate, an RPS sparkline, and per-upstream health.

```bash
# Same host as the daemon (default URL is http://127.0.0.1:80/_zion/snapshot.json)
zion top

# Custom endpoint and poll interval
zion top --url http://10.0.0.5:80/_zion/snapshot.json --interval 250
```

The dashboard polls `/_zion/snapshot.json`, an internal-only JSON endpoint that
mirrors `/metrics` with quantiles + platform info. It's served on both the HTTP
and HTTPS listeners for loopback consumers; non-internal IPs get 403.

Keys: `q` quit · `p` pause · `r` redraw.

## Configuration

```toml
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
# Outbound X-Forwarded-For policy: "append" (default), "rewrite", "drop".
# Use "rewrite" when Zion is the front edge — it strips inbound XFF and
# emits a single trusted entry (the resolved client IP).
xff_mode = "append"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"
key_path = "/etc/ssl/zion/tls.key"

[upstreams]
backend = "http://127.0.0.1:8000"
frontend = "http://127.0.0.1:3000"

# WAF profile (named, assignable per route). Mode "balanced" is the
# high-precision default; "aggressive" adds broad-substring patterns
# for higher recall (and higher false-positive rate).
[waf_profile.api]
mode = "balanced"
max_body_mb = 10
entropy_check = true
entropy_threshold = 6.5

[[route]]
path = "/api/{*rest}"
upstream = "backend"
waf_profile = "api"

[[route]]
path = "/_next/static/{*rest}"
upstream = "frontend"
mode = "static_cache"

[[route]]
path = "/{*rest}"
upstream = "frontend"
```

See [zion.example.toml](zion.example.toml) for the full configuration reference.

## Architecture

```
Client -> TLS 1.3 -> Security Gates -> Radix Router -> WAF Pipeline (5 gates) -> Proxy/Cache -> Upstream
                         |                                |
                    URI limit                  Aho-Corasick (~100 balanced / ~190 aggressive)
                    Method whitelist           Entropy analysis (JSON-string-only)
                    Rate limiter              simd-json validation
                    CORS pre-flight           Depth/size limits
```

<!-- zion-stats:modules-lines (kept in sync by scripts/update-readme-stats.sh) -->
40 modules, ~28,000 lines of Rust. See [architecture docs](https://fabriziosalmi.github.io/zion/guide/architecture) for the full module map and request lifecycle.

## Benchmarking

```bash
# Native scientific benchmark (8 endpoints x 5 runs, ~8 min)
bash benchmarks/bench-native.sh

# Payload x concurrency matrix (36 cells, ~15 min)
bash benchmarks/bench-matrix.sh

# Quick validation (~2 min)
bash benchmarks/bench-matrix.sh --quick

# Docker comparison vs nginx (5 runs, CI95)
bash benchmarks/bench-scientific.sh

# PGO optimized build (~10-20% target; shipped as the -pgo release artifact)
bash benchmarks/bench-pgo.sh
```

Results saved to `benchmarks/bench-history.json` with automatic delta comparison.

## Testing

```bash
# Unit tests (597) <!-- zion-stats:test-count (kept in sync by scripts/update-readme-stats.sh) -->
cargo test

# Integration tests (23 -- requires running Zion + backend)
# 1. cd benchmarks/backend && cargo run --release &
# 2. ZION_CONFIG=tests/zion-test.toml ./target/release/zion &
# 3. Run:
cargo test --test integration -- --ignored --test-threads=1
```

## Compliance

- [Threat model (STRIDE)](docs/security/threat-model.md) — surfaces, mitigations, residual risk.
- [OWASP ASVS L2 mapping](docs/security/asvs.md) — control → implementation site → test/evidence.
- [SOC 2 + FedRAMP control mapping](docs/security/compliance-mapping.md) — TSC + NIST 800-53 rev5 evidence for the auditor's binder.
- [FIPS 140-3 build](docs/security/fips.md) — `cargo build --features fips` for the FIPS-validated AWS-LC backend.
- [TLS conformance](docs/security/tls-conformance.md) — BoGo / RFC 8446 / SSL Labs verification recipes.
- [Supply chain](docs/security/supply-chain.md) — SLSA L3 provenance, cosign, SBOM verification.
- [Mesh integration](docs/mesh/integration.md) — `--features sovereign-aimp` operator guide: topology, identity, observability, debugging.
- [Architecture Decision Records](docs/adr/) — the load-bearing engineering choices, in writing.

## Verifying a Release

Every release is signed and carries SLSA v1.0 build provenance. See
[Supply Chain Security](docs/security/supply-chain.md) for the verification
commands. The short version:

```bash
# Binary release (Sigstore-backed provenance via gh CLI)
gh release download v0.4.2 -R fabriziosalmi/zion -p '*x86_64-unknown-linux-musl*' -p 'SHA256SUMS'
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify zion-v0.4.2-x86_64-unknown-linux-musl.tar.gz --owner fabriziosalmi

# Container image (cosign keyless)
cosign verify ghcr.io/fabriziosalmi/zion:v0.4.2 \
    --certificate-identity-regexp "^https://github.com/fabriziosalmi/zion/\\.github/workflows/release\\.yml@refs/tags/v" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
