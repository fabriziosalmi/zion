# Changelog

All notable changes to Zion Edge Gateway are documented here.

## [Unreleased]

## [0.4.4] - 2026-06-25

A WAF-coverage patch. Adds a measured detection/false-positive regression
baseline (`benchmarks/waf-corpus/`, 200 payloads) and, driven by it, plugs the
biggest gaps in the balanced/aggressive pattern sets — command injection, SSRF,
deserialization, and error-based SQLi — lifting aggressive recall from 64.7% to
85.3% against the corpus at an unchanged **0% false-positive rate**.

### Changed

- **WAF command-injection coverage** ([`src/waf.rs`](src/waf.rs)). The CMDi
  patterns only matched a metachar followed by a few specific commands
  (`cat`/`ls`/`rm`/`wget`/`curl`), so bare-metachar and substitution forms slipped
  through. Added unambiguous Unix forms to the balanced set (reverse shells
  `/dev/tcp/` · `nc -e` · `bash -i`, `${IFS}` bypass, brace expansion, `; nc`) and
  the FP-prone forms to aggressive (`$(`, `` `id` ``, `whoami`, `&& ls`, `| sh`).
  Measured against the new `benchmarks/waf-corpus/` baseline: command-injection
  recall **33% → 100%** (aggressive) / 27% → 44% (balanced), overall **64.7% →
  73.3%** (aggressive), **at an unchanged 0% false-positive rate** on the benign
  set. New unit tests lock in both the detections and the no-false-positive guard.
- **WAF SSRF / deserialization / SQLi-error-based / shellshock coverage**
  ([`src/waf.rs`](src/waf.rs)). Continuing against the corpus: internal SSRF
  schemes `gopher://`/`dict://` and error-based SQLi (`extractvalue(` ·
  `updatexml(` · `xp_cmdshell` · `||(select`) to balanced; loopback/decimal-IP
  SSRF (`http://localhost:` · `http://127.0.0.1:` · `http://2130706433`),
  deserialization / prototype-pollution (java `rO0AB`, PHP `O:8:"`, `__proto__`,
  `constructor[prototype`, YAML `!!python/`), shellshock (`() { :` — *not* bare
  `() {`, which is a legit empty function) and quote-paren SQLi OR-variants to
  aggressive. Corpus delta (aggressive): SSRF **33% → 100%**, deserialization
  **33% → 100%**, SQLi **68% → 90%**, overall **73.3% → 85.3%** — still **0%
  false positives**. New unit tests incl. an empty-function precision guard.

## [0.4.3] - 2026-06-25

A cache-observability + operability patch, both items drawn from a real
audiolibri.org stale-content incident: the cache now states its decision on the
wire, and an operator can flush it on deploy instead of waiting out the TTL.
No change to the proxy/WAF data path.

### Added

- **`X-Zion-Cache: HIT|MISS|BYPASS` response header** ([`src/dispatch.rs`](src/dispatch.rs)).
  A cache HIT was previously distinguishable only by the absence of upstream/shield
  headers plus the rewritten `Cache-Control` and the `Age` value — which cost real
  debugging time during a stale-content incident. The cache now states its decision
  explicitly: `HIT` (served from RAM), `MISS` (fetched from upstream and cached as it
  streams), `BYPASS` (not cacheable — content-negotiated, `no-store`/`private`,
  already-stale-on-arrival, or `max-age=0`).
- **Cache purge endpoint `POST /_zion/cache/purge`** ([`src/cache.rs`](src/cache.rs),
  [`src/dispatch.rs`](src/dispatch.rs)). Flush the in-RAM cache so a deploy hook can
  invalidate immediately instead of waiting out the TTL (previously only a pod restart
  would do it, briefly dropping `:443`). `?prefix=/path` purges matching keys; no prefix
  purges everything. Internal-only (same IP gate as `/metrics`) and POST-only; returns
  `{"purged":N,"scope":...}`. L2 is cleared directly; the existing generation counter
  lazily invalidates every thread-local L1 — no cross-thread iteration.

## [0.4.2] - 2026-06-25

A cache-correctness patch fixing stale content served by the edge cache. The
RAM cache now emits an `Age` header and honours the origin's freshness, so
content updates propagate within the origin's real lifetime instead of being
pinned for the full profile TTL and re-freshed on every downstream hit.

### Fixed

- **Cached responses now carry an `Age` header** ([`src/cache.rs`](src/cache.rs),
  [`src/dispatch.rs`](src/dispatch.rs)). On a RAM hit the cache previously
  re-stamped a fresh `Cache-Control: max-age=<ttl>` with **no `Age`**, so every
  downstream cache (the shield Varnish, browsers) reset its freshness clock on
  each hit and served content far past its real lifetime — observed as stale
  content on audiolibri.org. Each entry now records its birth time (seeded from
  the upstream `Age`, so time spent behind the shield counts) and serves a
  correct `Age`, letting downstream caches subtract elapsed time.
- **The origin's freshness is now honoured for the cache lifetime**
  ([`src/dispatch.rs`](src/dispatch.rs)). The entry TTL is derived from the
  origin's `s-maxage`/`max-age`, clamped to the profile TTL as a ceiling,
  instead of blanket-applying the profile TTL. A response that is `max-age=0`
  or already older than its lifetime on arrival is streamed through uncached.

## [0.4.1] - 2026-06-18

A hardening + supply-chain patch: one user-facing TLS fix, a completed
Node 24 / SHA-pinned CI migration, a green-again fuzz harness, a sweep of
safe dependency bumps, and a new mesh-cost benchmark. No behaviour change to
the proxy/WAF/cache data path.

### Added

- **`benchmarks/bench-mesh.sh`** (#72) — reproducer that measures the
  `--features sovereign-aimp` cost as an RPS delta vs a default build across
  three operating points (idle / lookup-active / 3-node mesh-active) on the
  API-GET hot path, with the issue's acceptance gates (<1% / <3% / <5%)
  enforced. Harness only; numbers belong on a Linux rig.

### Fixed

- **TLS handshake errors are no longer swallowed** (#201,
  [`src/tls.rs`](src/tls.rs)). `spawn_https_handler` collapsed the
  handshake-error and 10s-timeout cases into one arm that only bumped a
  counter, losing the rustls error string. Split into distinct, rate-limited
  (≈1 line/s, process-wide) log lines for the error vs timeout cases, each
  with the client address; the metric still counts every failure. Benefits
  both the tokio and io_uring accept paths.
- **`cargo-fuzz build` green again on master** (#205,
  [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml)). The repo-root
  `rust-toolchain.toml` (1.88) shadowed dtolnay's nightly inside the checkout,
  so `cargo install cargo-fuzz` built under 1.88 and tripped a transitive
  dep's 1.91 MSRV. Drop the pin for the (nightly-only) fuzz job.

### Changed

- **Node 24 GitHub Actions migration completed** and the last mutable action
  refs SHA-pinned (#200, #203, #206) — `attest-build-provenance`/`attest-sbom`
  → v4.1.0, plus checkout/codeql/setup-qemu/cargo-deny bumps; every workflow
  now pins by full commit SHA.
- **Dependency bumps** (verified to build all-features + hold the 1.82 MSRV
  floor): matchit 0.8→0.9 (#204), socket2 0.5→0.6, webpki-roots 0.26→1.0,
  crossterm 0.28→0.29 (#207); docker rust 1.95→1.96 (#178),
  docker/metadata-action 5→6 (#190); rand 0.9→0.10 in the standalone bench
  backend (#208). simd-json 0.17, toml 1.1, and notify 8 were intentionally
  held back — their transitive deps require rustc 1.85, above zion's 1.82 MSRV.

## [0.4.0] - 2026-06-16

### Added

- **L7 tarpit / slow-drip for flagged sources** (#151,
  [`src/tarpit.rs`](src/tarpit.rs)). Closes the anti-DDoS enforcement arc
  (#147 → #155 → #150 → #151). When tag-driven enforcement (#150) decides to
  deny a request, the operator can now escalate the cheap `403` into a
  *held* connection: the flagged source is parked for a bounded `hold_secs`
  before the refusal, so a backed flood pays wall-clock and socket budget
  instead of getting an instant, immediately-recyclable reject.
  - **Config** `[sovereign.enforce.tarpit]` — `enabled` (default `false`),
    `hold_secs` (default `10`), `max_concurrent` (default `128`). Only takes
    effect when `[sovereign.enforce] enabled = true`; geo-gated like the rest
    of enforcement. Config-load warns if `enabled` with `max_concurrent = 0`
    (sheds every request → no-op) or `hold_secs > 60` (over-long holds tie up
    connections), and **clamps `max_concurrent` to ¼ of the global connection
    ceiling** so held connections can't pin the admission pool (self-DoS guard).
  - **Bounded** — a single global ceiling caps concurrently held requests; at
    the ceiling the tarpit *sheds* back to the immediate `403`. A held request
    keeps its global connection permit + per-IP slot for the hold, so the
    ceiling is clamped to a small fraction (¼) of the connection pool.
    Admission is one CAS; a held request is one parked tokio timer + the open
    socket, released by an RAII guard (gauge and held-time stay correct on
    early return / panic). The deny still denies — the tarpit only changes how
    long the flagged client waits.
  - **Metrics** `zion_tarpit_active` (gauge), `zion_tarpit_total`,
    `zion_tarpit_shed_total`, `zion_tarpit_held_ms_total` (counters).

### Fixed

- **`io-uring-accept` now serves HTTPS end-to-end** (#195,
  [`src/uring.rs`](src/uring.rs), [`src/main.rs`](src/main.rs)). The opt-in,
  off-by-default `io-uring-accept` feature (Linux) was previously
  non-functional — it never served a single request. Three masked lifecycle
  bugs are fixed: (1) a *borrowed* listener fd was recycled out from under the
  accept thread, so `io_uring_setup` reused the freed number and `accept()`
  flooded `EBADF`/`ENOTSOCK` at ~10⁶/s — the thread now owns a `dup()`ed fd;
  (2) `tokio::net::TcpStream::from_std` was called on the bare accept
  `std::thread` and panicked "no reactor running" — the conversion now happens
  inside a runtime context; (3) the accept loop was handed a throwaway shutdown
  `watch` channel whose sender was dropped immediately, so the loop returned at
  once and every accepted connection was RST during the TLS ClientHello — it is
  now wired to the real process shutdown signal. Verified on Linux 6.17
  (concurrent `/healthz` 20/20, flood = 0, panics = 0).
- Guard against running outside a Git repository (#186).

### Security

- High-severity dependency bump in `Cargo.toml` (#185); `rand` → 0.9.3 (#183).

### Dependencies

- `hyper` 1.9.0 → 1.10.1 (#167), `memchr` 2.8.0 → 2.8.2 (#166).
- CI actions: `upload-artifact` → 7.0.1 (#142), `checkout` → 6.0.2 (#141),
  `download-artifact` → 8.0.1 (#140), `setup-buildx-action` → 4.1.0 (#139),
  `deploy-pages` → 5.0.0 (#138).

### Deferred

- Per-byte **slow header/body drip** (the endlessh-style trickle). The
  bounded delayed-hold already imposes the wall-clock + socket cost that is
  the point of a tarpit; a streaming-body trickle is a follow-up. Tarpit on
  the plain `429` rate-limit path (currently scoped to the `[sovereign.enforce]`
  deny points) is likewise a follow-up.
- **Per-IP tarpit sub-cap.** The ceiling is global, and on HTTP/2 each held
  *stream* consumes a slot, so one source (a few H2 connections) can occupy a
  large share of the holding capacity and push other flagged sources to a fast
  `403`. This degrades the tarpit's effectiveness but not zion's stability (the
  shed fallback is the safe pre-tarpit behaviour, and the global / per-IP
  connection caps still bound sockets). A per-IP sub-cap is a follow-up.

## [0.3.4] - 2026-06-05

### Security

- **CVE-2026-49975 ("HTTP/2 Bomb") hardening.** The HTTP/2 Bomb chains an
  HPACK decompression bomb with a flow-control "hold". Zion's single-connection
  resistance was *inherited* from hyper/h2 defaults rather than asserted, and
  the multi-connection variant was unbounded with the per-IP cap off (the
  default). This makes the ceilings explicit and on by default. Verified live
  on the e2e rig: released 0.3.3 advertised the inherited
  `max_concurrent_streams = 200`; a single-connection bomb stayed bounded
  (~3 MB/conn, RSS flat, 0 panics), confirming the premise.
  - **Explicit HTTP/2 limits** ([`src/main.rs`](src/main.rs)) — pinned on the
    server builder instead of inherited: `max_concurrent_streams = 128` (was
    the inherited 200), `max_header_list_size = 16 KiB`,
    `max_pending_accept_reset_streams = 20` (CVE-2023-44487 Rapid-Reset bound),
    plus HTTP/2 keep-alive PINGs (30 s / 10 s) to reap a connection gone silent
    mid-hold. A regression test pins the invariant that worst-case retained
    header memory per connection (`streams × header-list`) stays ≤ 4 MiB.
  - **Per-IP connection cap ON by default** ([`src/config.rs`](src/config.rs),
    [`src/main.rs`](src/main.rs)) — `server.max_connections_per_ip` is now
    tri-state: omitted → **auto** (~1/8 of the global connection ceiling,
    scaling with RAM so it won't pinch CGNAT/large-NAT on big nodes); `0` →
    explicitly disabled; `N` → explicit. Resolved in `try_build` and read live
    at accept, so a hot-reload retunes it without dropping live connections.
  - **`compute_conn_limit` re-based to 256 KB/connection**
    ([`src/bootstrap.rs`](src/bootstrap.rs)) — was 50 KB, which
    under-provisioned the global ceiling ~5× against an *active* HTTP/2
    connection (1 MB flow-control window + per-stream/HPACK state + TLS
    buffers). The per-connection worst case stays bounded by the explicit H2
    limits and the per-IP cap above.

### Fixed

- **Rate-limit map scavenger spawned unconditionally**
  ([`src/main.rs`](src/main.rs)) — it was gated on the boot-time
  `rate_limit_rps > 0`, so enabling the limiter via hot-reload (`0 → N`) left
  the per-IP rate map without garbage collection, risking unbounded growth to
  `MAX_RATE_MAP_ENTRIES` and the fail-closed path for new IPs. It now always
  runs (a cheap no-op when the map is empty) and reads the window live. A
  regression test pins that a hot-reload carries `rate_limit_rps`,
  `rate_limit_window`, and `max_connections_per_ip` into the new snapshot.

## [0.3.3] - 2026-06-03

### Fixed

- **Passive upstream failover on connection-level errors**
  ([`src/proxy.rs`](src/proxy.rs), [`src/dispatch.rs`](src/dispatch.rs)).
  A `standard`-mode route over a multi-upstream `[upstream]` pool now
  fails over to the next healthy upstream when the selected backend
  refuses the connection, instead of returning `502` until the
  background health prober ejected it (steady probe interval).
  `proxy_pass_ha` buffers the request body once and replays it; on a
  connection-level failure it marks the upstream unhealthy — bringing
  its next probe forward via `next_probe_at_us = 0` so it rejoins on
  recovery — before retrying the next pool member. Idempotent methods
  (GET/HEAD/OPTIONS/PUT/DELETE/TRACE) retry on any transport error;
  non-idempotent methods only on a pure connect error (`is_connect()` —
  the request provably never reached the upstream). Single-upstream
  pools keep the zero-overhead `proxy_pass` streaming path; Websocket /
  SSE forwards are unchanged (no safe replay). Measured on a live
  2-node cluster: a rolling backend kill went from 170/350 failed
  requests to 0/350. ([#179](https://github.com/fabriziosalmi/zion/pull/179))

## [0.3.2] - 2026-06-01

Resilience and correctness, validated on a real two-node Proxmox e2e bench
(real FQDN, real Let's Encrypt TLS 1.3). Adds adaptive self-heal so a recovered
origin returns to service in ~1.4 s instead of up to 30 s, closes 24 data-plane
findings from a live bug-hunt, and fixes a `/metrics` content-negotiation bug
that made standard Prometheus unable to scrape.

### Added

- **Adaptive decorrelated-jitter origin recovery (#173)** — replaces the fixed
  30 s upstream health-probe interval with a per-upstream decorrelated-jitter
  backoff (AWS / Marc Brooker). A DOWN upstream is re-probed on a 100 ms→3 s
  schedule, so a recovered origin returns to service in **~1.4 s instead of
  ~30 s** (measured live on the e2e rig, ~21× faster), with jitter to avoid a
  recovery thundering-herd across a co-dead pool or mesh replicas. HEALTHY
  upstreams keep the unchanged 30 s steady cadence — zero happy-path
  regression, identical steady-state origin load. Backoff state rides the
  config-reload `Arc`-reuse so an in-progress walk survives reloads; the
  request path is untouched (lock-free). `fastrand` promoted to a direct dep.

### Fixed

- **`/metrics` content-negotiation (#172)** — OpenMetrics exemplars were emitted
  under the classic `text/plain; version=0.0.4` content-type, which standard
  Prometheus rejects, making the target unscrapeable. `/metrics` now
  content-negotiates on the `Accept` header: classic exposition (no exemplars,
  no `# EOF`) by default, OpenMetrics only when the client asks for
  `application/openmetrics-text`.
- **24 data-plane findings from a live e2e bug-hunt (#171)** — request-path
  hardening surfaced by real-traffic testing: catch-all-root + trailing-slash
  routing, header-read / body-read / upstream timeouts (504/408), inbound
  client-cert-fingerprint header strip, forwarding hygiene on the WebSocket
  path, WAF whitespace/unicode/overlong-encoding evasion gates, cache GET-gating
  + `Cache-Control` honoring, and security-header injection on all responses.

### Validated

- Two-node Proxmox e2e benchmark (`benches/e2e/`): Zion on **2 Skylake vCPU**
  sustains **96 k req/s** cache+WAF+TLS and **43 k req/s** proxy+WAF+TLS at
  ~40 MB RSS, and holds **flat RSS (OLS −26 MB/h, no leak)** under a
  4.67 M-request mixed attack while serving 4.66 M legit cache-hits — 0 panics.

## [0.3.1] - 2026-06-01

A focused patch on operability and documentation honesty. Makes the
daemon's own resource footprint observable in production — the answer to
"can you debug a silent memory leak without restarting?" — and corrects
three FIPS-guide claims about tooling that did not exist.

### Added

- **Runtime resource introspection (#163)** — two new `/metrics` gauges,
  `zion_process_resident_memory_bytes` (RSS via `/proc/self/status`
  `VmRSS`) and `zion_process_open_fds` (`/proc/self/fd` entry count),
  sampled **once per scrape** off the hot connection path — the existing
  1-second render cache throttles the two `/proc/self` reads, so there is
  no per-request cost. Surfaced on three operator planes: `/metrics`,
  `/_zion/snapshot.json`, and the `zion top` TUI (new "rss" / "open fds"
  rows, version-skew tolerant via `#[serde(default)]`). A steadily
  climbing RSS or fd count under flat traffic is now visible on a
  dashboard within one scrape cycle, no restart required. Linux-only;
  both gauges render as `0` on other platforms so a single dashboard
  works across hosts. No new dependencies, no `unsafe`. New Grafana
  leak-detection queries in
  [`docs/deploy/observability.md`](docs/deploy/observability.md).
- **`zion doctor` memory-introspection check (#163)** — a preflight that
  confirms `/proc/self/status` is readable on the host and reports the
  current RSS, warning up front when a hardened container runtime masks
  `/proc` (where the gauges would otherwise silently read `0`).

### Fixed

- **FIPS guide referenced tooling that does not exist (#164)** — the guide
  promised a `scripts/fips-self-check.sh` helper, a `ci.yml` `flavor=fips`
  job, and a `release.yml` `-fips` artifact, none of which the repo ships.
  Rewrote [`docs/security/fips.md`](docs/security/fips.md) to the honest
  posture: a FIPS build is a manual `cargo build --features fips` today,
  carries no SLSA provenance attestation (unlike the default release
  binaries), and its chain of custody is the operator's to establish.
  CI/release wiring is noted as future work.

## [0.3.0] - 2026-05-30

The first tagged release since v0.2.2. Completes the **v0.3 — Compliance
frontier** milestone (BoGo TLS conformance in CI) and ships the
**Sovereign Edge** origin tagging (IT/EU, IPv4 + IPv6) plus the first
**anti-DDoS admission levers** (per-IP concurrent-connection limit,
tag-driven enforcement). The full OpenTelemetry stack moved to 0.32 and
the CI / supply-chain were hardened. Supersedes the unreleased 0.2.3 line.

### Added

- **BoGo TLS conformance suite in CI (#56)**
  ([`.github/workflows/tls-conformance.yml`](.github/workflows/tls-conformance.yml)).
  Runs BoringSSL's BoGo suite (~600 cases) against the exact `rustls` +
  `aws-lc-rs` versions zion pins — version-locked, so a future
  `Cargo.lock` bump that regresses conformance goes red on the bumping
  PR. Closes the v0.3 milestone. Corrected the long-standing doc/issue
  myth that BoGo could be pointed at zion's `:443` (it drives a *shim*).
- **Sovereign Edge — IT/EU origin tagging, IPv4 + IPv6 (#147)**
  (`--features geo-ita` / `geo-eu`). Classifies the client IP via an
  O(log N) binary search over baked CIDR tables (a `u32` table + a
  parallel `u128` table for IPv6) — no GeoIP DB, no syscall, one atomic.
  `geo-eu` is a hybrid model: every EU-27 RIPE allocation is the
  `Eu` baseline, curated EU ASN sets override it with gov/residential/
  datacenter roles. Answers "% EU vs non-EU traffic" out of the box via
  `zion_sovereign_classifications_total{class}`. Dataset auto-refreshes
  weekly (`sovereign-data.yml`, RIPE NCC + Team Cymru).
- **Per-IP concurrent-connection limit (#155)** —
  `server.max_connections_per_ip` (0 = off). Caps how many sockets one
  source IP may hold open at once, enforced at accept *before* the TLS
  handshake (the resource a slow/backed flood drains). RAII release,
  zero overhead when disabled, hot-reloadable. Metric
  `zion_connections_rejected_per_ip`.
- **Tag-driven enforcement (#150)** — `[sovereign.enforce]` promotes the
  origin tag / AIMP mesh score from a *signal* to an opt-in `403` deny.
  `deny = ["unknown"]` on a `geo-eu` build blocks every non-EU source
  while the EU classes pass (sovereign allowlist by complement), or deny
  above a mesh-reputation threshold. Off by default; local WAF /
  rate-limit / auth stay authoritative. Metric
  `zion_enforcement_denied_total{reason}`. A README "Sovereign edge &
  DDoS resistance" section maps the layered defence.
- **ACME issue → renew → revoke soak in CI (#59)**
  ([`.github/workflows/acme-soak.yml`](.github/workflows/acme-soak.yml),
  [`src/acme.rs`](src/acme.rs)). New `acme-soak` weekly + on-demand
  workflow drives the full certificate lifecycle against a hermetic
  [Pebble](https://github.com/letsencrypt/pebble) test CA with mocked DNS
  (`pebble-challtestsrv`) — no real Let's Encrypt, no external DNS, no
  rate limits. A hidden `zion acme-soak` subcommand runs zion's *real*
  `renew_once` / `revoke_cert` paths and asserts the lifecycle counters
  move, so an ACME-flow regression fails the soak. New metrics
  `zion_acme_renewals_total` and `zion_acme_renewal_failures_total`;
  new operator-facing `revoke_cert` for retiring a compromised key.
  Docs: [`docs/config/acme.md`](docs/config/acme.md). Fault-injection
  legs (nonce-collision, key-rollover, TTL-edge) are tracked as a
  follow-up.

### Fixed

- **ACME HTTP-01 token cleanup raced validation.** `do_renewal_native`
  removed the challenge tokens from the responder store *before*
  `poll_ready`, but the ACME server fetches them *during* that poll —
  yielding a 404 / `unauthorized`. Tokens are now dropped only after
  `poll_ready` returns. Surfaced by the new #59 Pebble soak (real
  Let's Encrypt validated fast enough to usually mask it).

- **Mesh chaos coverage + inbound claim rate-cap (#71)**
  ([`src/aimp_cp.rs`](src/aimp_cp.rs)). Three failure-mode tests pin the
  gossip subsystem under adversarial conditions: split-brain
  reconciliation (LWW converges both halves to the one newest
  observation, no double-count, no permanent ban), claim flood (a
  per-source-node token bucket caps a flooding peer — including a
  compromised one with a valid key — while other sources keep flowing),
  and slow gossip (a wedged peer's backlog arriving in a burst yields no
  duplicate decisions — replays and stale claims change nothing). The
  rate-cap is new behaviour: opt-in via `sovereign_aimp.inbound_claims_per_sec`
  (0 = disabled, the default, so the legitimate anti-entropy full-map
  re-broadcast stays unthrottled) with `inbound_claim_burst` headroom,
  surfaced as `zion_mesh_claims_dropped_total{reason="rate"}`.

- **BPF demux v2 — unified-port co-existence integration test +
  loader status documented**
  ([`tests/integration.rs`](tests/integration.rs),
  [`bpf/README.md`](bpf/README.md)). New `t30_unified_port_*`
  integration test pins one of the two open acceptance items on
  issue #53: TCP HTTPS on `:4433` keeps working when zion is built
  with `--features http3` AND the QUIC listener occupies the same
  port via UDP. The probe is OS-portable (binds UDP locally; either
  trips `EADDRINUSE` and confirms QUIC is up, or succeeds and logs
  that the build was TCP-only). New `bpf/README.md` documents the
  loader-runtime status: aya 0.13 has no typed `SkReuseport`
  program helper, so the userspace `Ebpf::load_file` +
  `setsockopt(SO_ATTACH_REUSEPORT_EBPF)` path is **deferred** —
  tracked in [#100](https://github.com/fabriziosalmi/zion/issues/100)
  with the precise upstream-aya gap and three viable closing paths
  (upstream contribution, libbpf-rs switch, hand-rolled
  `bpf(BPF_PROG_LOAD)` FFI). (#53 partial)
- **`[access_log]` config block — PII redaction on the access-log
  path** ([`src/config.rs`](src/config.rs),
  [`src/dispatch.rs`](src/dispatch.rs),
  [`docs/guide/observability.md`](docs/guide/observability.md)).
  New `include_headers: Vec<String>` (default empty, lowercased on
  parse) and `mtls_fingerprint: bool` (default true). Configured
  headers are pulled from the request before dispatch consumes it,
  passed through the existing
  `audit::CompiledRedaction::redact_header_value` policy
  (`[redact.headers]`), packed into a single JSON `headers` field
  on the `tracing::info!(target: "access", ...)` event. The mTLS
  leaf-cert SHA-256 fingerprint surfaces on a dedicated `mtls_fp`
  field — never redacted (it's already a hash). When the audit log
  is enabled and `[access_log]` opts in, a parallel
  `kind = "request_completed"` audit event mirrors the same field
  set with HMAC-chain coverage. New proptest pin
  (`redacted_header_json_never_contains_secret_value`) verifies the
  rendered JSON never leaks a redacted-list header value as a
  substring, for any input. (#60)
- **SOC 2 + FedRAMP control-mapping document**
  ([docs/security/compliance-mapping.md](docs/security/compliance-mapping.md))
  — TSC (CC + A + C + PI) tables and NIST 800-53 rev5 (AC, AU, CM,
  IA, SC, SI, SA) mapped to in-binary code paths, workflow files,
  and operator-side residuals. Each row links to the implementation
  site and to the deployment-side doc the auditor still needs from
  the operator. Cross-referenced from the README "Compliance"
  section. (#61)
- **Mesh observability — counters + audit-kind taxonomy**
  ([`src/metrics.rs`](src/metrics.rs), [`src/audit.rs`](src/audit.rs)).
  Eight always-on Prometheus counters under `zion_mesh_*`
  (`claims_emitted`, `claims_received`, `claims_dropped_total{reason=...}`
  with `signature`/`replay`/`other`, `score_lookups`,
  `gossip_bytes_in`, `gossip_bytes_out`). Wired at the four mesh
  callsites: `try_merge` accept + each rejection path, `publish_block`
  enqueue, `run_receiver` byte counting, `run_publisher` /
  `run_anti_entropy` byte counting, dispatcher's `cp.lookup` positive
  path. Counters are zero on builds without `--features
  sovereign-aimp` so operators can grep the same metric names
  regardless of build flavour. New canonical audit-kind constants
  (`audit::kind::{AUTH_*, CONFIG_RELOAD, REQUEST_BLOCKED,
  ADMIN_ACCESS, PANIC, MESH_PUBLISH, MESH_RECEIVE, MESH_PEER_*,
  MESH_QUORUM_DECISION}`) replace ad-hoc string literals at future
  callsites. Performance budget documented at
  [docs/perf/mesh-overhead.md](docs/perf/mesh-overhead.md) (target
  < 0.5 % throughput on a 100k rps host). (#69)
- **STRIDE threat-model addendum on the mesh (AIMP) surface** — new
  §10 in [docs/security/threat-model.md](docs/security/threat-model.md)
  walking the six STRIDE categories against the mesh: Ed25519 signing
  for Spoofing, Noise AEAD + Merkle-CRDT integrity for Tampering,
  signed audit trail for Repudiation, opt-in IP anonymisation for
  Information disclosure, per-peer rate-cap + LRU for DoS, and
  revocation-key-signed claims plus quorum thresholds for Elevation
  of privilege. ASVS map ([docs/security/asvs.md](docs/security/asvs.md))
  gets a new V9.2.4 row pointing at the addendum, and
  [docs/guide/observability.md](docs/guide/observability.md) gains a
  Mesh section listing the `zion_mesh_*` counters + audit-event
  kinds. (#70)
- **ADR-0008 + mesh integration guide** — formal architectural record
  for embedding AIMP as the mesh control-plane bus
  ([docs/adr/0008-mesh-aimp-integration.md](docs/adr/0008-mesh-aimp-integration.md)),
  alongside an operator-facing deployment guide
  ([docs/mesh/integration.md](docs/mesh/integration.md)) covering peer
  topology, identity management, anti-entropy tuning, and
  diagnostics. README "Compliance" section gains a Mesh sub-link. (#73)
- **SO_REUSEPORT + BPF demux foundation (`bpf-demux` feature)**
  (partial — see Deferred). New `src/bpf_demux.rs` module with a
  three-state `DemuxReadiness` probe (`Ready` /
  `KernelTooOld { release }` / `MissingCapability`), wired at boot
  with a structured log line. New eBPF source crate
  `bpf/zion-bpf-demux/` (mirrors `xdp/zion-xdp-prog/`'s layout) plus
  `bpf/build.sh` produces `bpfel-unknown-none` ELF that the loader
  reads from `ZION_BPF_DEMUX_OBJECT` (defaults to the build path).
  The v1 program returns `SK_PASS` — the userspace attach hook + map
  populate + body-replacement-with-real-routing are deferred. (#53
  partial — see Deferred)
- **kTLS secret-extraction fix + boot probe + `Memfd` cache helper**
  (partial — see Deferred). Three pieces:
    - `tls.rs` now sets `ServerConfig.enable_secret_extraction = true`
      under `--features ktls` (Linux). The existing `try_upgrade` path
      that wraps the post-handshake stream in `KtlsStream` requires
      this to be true; without it `config_ktls_server` fails and the
      connection is closed. This was a real bug on the kTLS path.
    - Boot log line `ktls=enabled|disabled: <reason>` emitted at
      startup when the feature is on, populated by the existing
      `probe_kernel_support` helper.
    - New `src/memfd.rs` module wrapping `memfd_create(2)` —
      `Memfd::from_bytes(label, &[u8])` produces a kernel-tmpfs-backed
      file handle. `MIN_MEMFD_THRESHOLD = 64 KB`. The dispatch-side
      sendfile path that consumes this is the deferred piece. (#52
      partial — see Deferred)
  `ktls` feature now depends on `io-uring-rw` per the issue spec.
- **io_uring rw capability probe + `io-uring-rw` feature gate**
  (partial — see Deferred). New `bootstrap::Platform.has_io_uring_rw_kernel`
  bool, populated at boot via `uname(2)` parsed against the 5.19+
  threshold (where `IORING_OP_READV_FIXED` and the rest of the rw
  surface zion would target are stable). Boot log line emitted only
  when the feature is on; the bool is unconditionally surfaced on
  `/metrics`. Two new chaos tests
  (`tests/chaos.rs::tcp_read_terminates_cleanly_*`) pin the
  "connection reset mid-read returns clean io::Error, never panics or
  hangs" contract — applies to today's tokio path AND to the future
  `IoUringStream` adapter so any regression is caught the moment the
  follow-up lands. (#51 partial — see Deferred)
- **NUMA-aware sharding for `rate_map` + `inflight`** — opt-in via
  `--features numa-aware`. On Linux multi-socket boxes, the per-IP
  rate-limit map and the singleflight inflight map split storage into
  one `DashMap` per NUMA node, routed by the calling thread's current
  node (`sched_getcpu(2)` + `/sys/devices/system/node/`). Same-socket
  workers stay cache-local; cross-socket fallback scans on get-miss.
  Single-socket / non-Linux / `--no-default-features` builds collapse
  to a single shard with no routing overhead — verified by criterion
  bench `numa/single_shard/get_hit` matching the bare `DashMap`
  baseline within noise. New `bootstrap::Platform.numa_nodes` field
  exposes the detected count. See [src/numa.rs](src/numa.rs). (#50)
- **PGO release builds (Linux x86_64-gnu)** — release.yml gains an
  opt-in `pgo: true` matrix flag. When set, the build runs a two-pass
  profile-guided pipeline: instrumented binary → 10 s deterministic
  workload via [`scripts/pgo-collect.sh`](scripts/pgo-collect.sh) →
  `llvm-profdata merge` → optimised rebuild. The PGO archive ships
  alongside the regular one with a `-pgo` suffix, its own `SHA256SUMS`
  entry, and its own SLSA build provenance. Default off for every
  target; only `x86_64-unknown-linux-gnu` is PGO'd today (musl +
  aarch64 + macOS + Windows pending). See
  [docs/perf/pgo.md](docs/perf/pgo.md). (#55)
- **Streaming WAF body inspection** — opt-in per WAF profile via
  `[waf_profile.X] streaming = true`. The dispatcher feeds each
  request-body frame to a `StreamingScanner` as it arrives off the wire;
  an injection pattern in the first chunk denies before the rest of the
  upload is read. Frames are reassembled on Allow so the regular
  `validate_request` pipeline still runs the encoded-payload pass +
  entropy + JSON gates that the streamer does not cover. Default is
  `false` (existing buffered behaviour). (#49)
- **Criterion microbench harness** — five `cargo bench` targets under
  `benches/` (waf_streaming, sovereign, traceparent, audit_hmac,
  cache_lookup) covering the hot-path components named in
  [docs/perf/roadmap.md](docs/perf/roadmap.md). Numbers checked in at
  `benchmarks/results/criterion/baseline.json` for trend tracking; CI
  workflow `bench.yml` runs the suite on manual dispatch and posts a
  delta-vs-master summary as a PR comment. See
  [docs/perf/microbench.md](docs/perf/microbench.md). (#54)

### Fixed

- **`scorecard.yml` publish step — top-level write permissions
  rejected by scorecard.dev**. The split workflow shipped in #57
  declared `id-token: write` and `security-events: write` at the
  workflow level, which scorecard-action's webapp verifier rejects
  with `400 Bad Request: "global perm is set to write"`. Move the
  writes to the `scorecard` job's `permissions:` block; top-level
  becomes `read-all`. The first scheduled / manual run after this
  lands publishes the public badge to scorecard.dev. (follow-up to
  #57)

### Changed

- **OpenTelemetry stack migrated 0.27 → 0.32 (#145)** — adapted
  `src/observability.rs` to the post-0.28 SDK API (`SdkTracerProvider`,
  `with_batch_exporter` without a runtime arg, `Resource::builder`,
  semconv `attribute::`). All target versions are MSRV 1.75. The
  cargo-vet baseline was regenerated for the new transitive crates
  (prost 0.14, tonic 0.14, …).
- **CI hardening.** `cargo-audit` / `cargo-vet` now install as **prebuilt
  binaries** (`taiki-e/install-action`) instead of building from source,
  eliminating an intermittent self-hosted-runner build flake (#154).
  Three high-volume workflows (supply-chain, CodeQL, DCO) moved to
  self-hosted runners (#144); `supply-chain.yml` forces
  `RUSTUP_TOOLCHAIN=stable` so the repo's pinned 1.88.0 toolchain can't
  break the audit jobs (#146).
- **Security:** `tar` 0.4.45 → 0.4.46 (Dependabot rust-security group).
- **`cargo-vet` promoted to a required CI gate** — `supply-chain/`
  baseline committed via `cargo vet init`, with audit imports from
  Mozilla, Google, Embark, Bytecode Alliance, ISRG, and Zcash
  reducing the residual exemption set from ~700 to 414 transitive
  crates. The `supply-chain.yml` `cargo-vet` job no longer runs with
  `continue-on-error` — a transitive crate that lacks an audit
  verdict OR an explicit `[[exemptions]]` row now fails the build.
  Workflow for refreshing the baseline documented in
  [docs/security/supply-chain.md](docs/security/supply-chain.md)
  "Updating the cargo-vet baseline". *Operator action required:*
  promote `cargo-vet` to a required status check in the master
  branch protection rule. (#58)
- **OSSF Scorecard split into a minimal workflow** — moved from
  `supply-chain.yml` to a dedicated [`scorecard.yml`](.github/workflows/scorecard.yml)
  with no global `env`/`defaults` blocks, satisfying the
  scorecard-action verification policy required for
  `publish_results: true`. The public badge at scorecard.dev now
  auto-refreshes within ~24 h of the first successful run; the SARIF
  still flows into the GitHub Security tab as before. Triggers
  (master push + 06:00 UTC cron + workflow_dispatch) match the
  previous in-supply-chain shape. (#57)
- **`WafMode` and `WafProfile` moved from `config` to `waf`** — semantic
  home, and lets the bench harness construct profiles via the lib
  surface without dragging the full config-loader dependency graph.
  `config::{WafMode, WafProfile}` re-exports preserve every existing
  import site; no breaking change.

### Deferred

- **BPF demux listener wire-up (issue #53)** — binding N sockets to a
  single SO_REUSEPORT group on `:443`, populating the
  `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` with the per-worker fds, and
  attaching the program via `SO_ATTACH_REUSEPORT_EBPF` is the runtime
  glue we don't ship in v1. It requires reorganising how `main.rs`
  constructs the HTTPS listener (today it's one `bind_with_reuseport`
  call; the BPF flow needs a coordinated bind across worker
  threads). The integration test ("TCP and QUIC clients both reach
  upstream through the unified socket") and the no-regression bench
  on TCP-only workloads land with that PR. The probe + boot log
  shipped today let an operator confirm the host is ready before the
  perf work arrives.
- **kTLS sendfile dispatch path (issue #52)** — the static-cache hot
  path that detects "memfd-backed entry + kTLS-upgraded connection"
  and routes the response through `sendfile(target_socket_fd, memfd,
  ...)` instead of hyper's body machinery is tracked separately. It
  requires (a) plumbing the connection's raw fd through dispatch (a
  layer hyper deliberately abstracts), (b) sidestepping hyper's
  AsyncWrite-driven body-send to avoid double-encoding the payload,
  and (c) a 100 KB+ benchmark to validate the issue's "≥30%
  throughput" target — none of which we ship a half-working version
  of. The `Memfd` helper (`src/memfd.rs`) and the secret-extraction
  fix mean the next PR can focus purely on (a) + (b) + (c) without
  re-litigating the kTLS plumbing.
- **`IoUringStream<R, W>` runtime adapter (issue #51)** — the
  `io_uring_prep_readv` / `writev` integration that replaces tokio's
  read/write half of accepted connections is tracked separately. The
  v0.2.x slice ships only the `io-uring-rw` feature gate, the
  `bootstrap::Platform.has_io_uring_rw_kernel` probe, the chaos
  contract test, and a structured boot log line. The adapter itself
  is research-grade (correct AsyncRead/AsyncWrite over a tokio-driven
  io_uring submission queue is multi-day work that doesn't compress
  cleanly) and we don't ship a delegating stub — operators that
  enable the feature today get the probe and the auto-disable signal,
  not silent userspace I/O dressed up in io_uring trappings.

## [0.2.3] - 2026-05-26

Maintenance release. No code-surface change — dependency hygiene only.

### Changed

- **MSRV-safe lockfile refresh.** `Cargo.lock` rolled forward to the
  latest dependency versions that still resolve under MSRV-core 1.82
  (ADR-0007 anchor): `rustls` 0.23.37→0.23.40, `reqwest` 0.13.2→0.13.3,
  `rcgen` 0.14.7→0.14.8, `serde_json` 1.0.149→1.0.150, `yasna`
  0.5.2→0.6.0, plus `libc`, `mimalloc`/`libmimalloc-sys`, `io-uring`
  0.7.11→0.7.12 and `arc-swap`. `socket2`/`itertools` pinned down to
  MSRV-compatible releases. All bumps are within-major (patch/minor).
- **Dependabot:** hold `hyper-rustls < 0.27.8` — 0.27.8 raises its MSRV
  to rustc 1.85, colliding with the 1.82 anchor. The MSRV CI gate is the
  hard guard; the ignore rule just stops re-proposal until MSRV-core
  moves to 1.85.
- **cargo-vet:** exemptions regenerated to match the refreshed lockfile;
  `imports.lock` refreshed from the trusted audit sources.

## [0.2.2] - 2026-05-08

Wire-up release. v0.2.0 / v0.2.1 introduced the XDP / ML-WAF / AIMP
feature surface; v0.2.2 plugs the remaining loose ends so the v0.2.x
line ships with everything actually wired through the request path.

### Added

- **AIMP `[sovereign_aimp]` TOML block** — promote the v0.2.1 env-var
  bootstrap to a first-class config section. `ZION_AIMP_*` env vars
  still work (back-compat) and act as fallback when a TOML field is
  empty. New keys: `enabled`, `listen`, `peers`, `identity_path`,
  `xdp_block_threshold`, `anti_entropy_secs`. (#63)
- **AIMP identity persistence** — `aimp_cp::bootstrap` now loads the
  Ed25519 secret from `identity_path` on subsequent boots, generating
  + writing it on first boot with `chmod 600`. The derived `node_id`
  is stable across restarts; peers no longer have to re-classify the
  node on every cycle. Upstream `aimp_node` 0.1.0 (commit 4631819)
  exposes `Identity::from_secret_bytes` / `secret_bytes` accessors to
  make this possible without forking the crate. (#68)
- **AIMP lookup pre-WAF (signal, not gate)** — every request now
  consults `cp.lookup(client_ip)` *before* the WAF gate; a known-
  malicious score from the mesh is forwarded upstream as
  `X-Zion-Mesh-Score: 0.NN` so backends can apply additional friction
  (CAPTCHA, longer rate windows) without zion shipping a hard block
  policy that varies by node. The local WAF / auth / rate-limit
  decisions remain authoritative. (#65)
- **AIMP anti-entropy** — periodic per-peer re-broadcast of the local
  reputation map, period configurable via `anti_entropy_secs` (default
  60s, 0 = off). Closes the steady-state convergence gap that
  delta-only gossip leaves on UDP loss / partition heal — N=50 mesh
  reaches 100% within 2× the period instead of stalling at the v0.2.1
  94% ceiling. (#88)
- **kTLS post-handshake wire** — the HTTPS accept loop now wraps the
  TCP stream in `ktls::cork_for_handshake` *before* the rustls
  handshake, then `try_upgrade`s the resulting `TlsStream` into a
  `KtlsStream` that runs record encrypt/decrypt in the kernel. Behind
  `--features ktls` (Linux ≥ 5.10 with `CONFIG_TLS=y`); kTLS upgrade
  failures fall back to userspace TLS on the same connection. (#86)
- **AIMP → XDP reconciler** — restored as `src/aimp_xdp_sync.rs`
  (separate file rather than nested in `aimp_cp.rs` so the
  `examples/aimp_*.rs` crates that embed the control plane via
  `#[path = ...]` don't drag the XDP module they cannot resolve).
  The reconciler subscribes to control-plane updates and reflects
  the IP reputation map into the kernel's `BLOCKED_V4` LPM-trie.

### Fixed

- **io_uring single-shot Accept** — `--features io-uring-accept` now
  uses `opcode::Accept` re-submitted per CQE instead of `AcceptMulti`.
  Closes the v0.2.0 ENOTSOCK race on Proxmox 9.1 LXC + kernel 6.17
  where `AcceptMulti` would emit `res = -88` continuously after the
  first burst — a TFO/DEFER_ACCEPT × multishot interaction that
  transitioned the listener fd into a state io_uring rejected. Costs
  one extra `submission().push()` per accept (~tens of ns); the kernel
  pipeline now stays fed under sustained load. (#87)

### Notes

- Total feature matrix: default, `xdp`, `ktls`, `ml-waf`,
  `sovereign-aimp`, and every combination thereof — all green.
- Test suite: 429 with `--all-features` (v0.2.1: 429; net new tests
  this release covered by the existing `aimp_cp::tests::*` adversarial
  battery — anti-entropy is a behavioural extension, not a new gate).
- Default build is unchanged on the wire: kTLS / XDP / mesh are all
  opt-in and gated.

## [0.1.12] - 2026-05-06

Quality + security release. Closes one Dependabot security alert (medium)
on the `--features auth` build path, removes the boot-time panic surface,
extends the SSOT version guard to every documented version reference,
and brings the `#[ignore]`d integration suite under CI guard so it stops
rotting silently.

### Security

- **`jsonwebtoken` 9.3.1 → 10.3.0**: closes the GHSA Type Confusion that
  could lead to authorization bypass on the `--features auth` JWT
  validator. v10 enforces an explicit choice of CryptoProvider; pinned
  to `aws_lc_rs` to stay aligned with rustls's backend (and the FIPS
  build path). (#43)

### Reliability

- **3 boot-time `panic!` / `exit(1)` sites → structured `ZionError`**
  propagation in `src/main.rs` (router build), `src/auth.rs` (JWT
  algorithm + missing secret/jwks_url), `src/tls.rs` (cert-dir watcher
  setup hoisted out of the spawned task). Hot-reload also benefits via
  the new `try_build` returning `Result`. (#78)
- **Flaky `rate_limiter_caps_at_rps_within_window` proptest fixed**:
  invariant relaxed to `<= 2 * rps as usize` to honour the wall-clock
  window flip the limiter exposes (`SystemTime::now()`-keyed window),
  with the cross-window scenario explained in a comment. (#77)

### Hardening / Process

- **`Cargo.toml` becomes the version SSOT** for the project. `Cargo.lock`,
  `deploy/helm/zion/Chart.yaml`, README, `docs/security/supply-chain.md`,
  `SECURITY.md`, `docs/deploy/hot-reload.md`, and the bug-report issue
  template are now CI-checked against canonical (#75, #80).
  `scripts/bump-version.sh X.Y.Z` propagates to all 7 sites atomically.
- **DCO sign-off enforced locally** via `.githooks/prepare-commit-msg`
  (auto-injects the trailer) and `commit-msg` (refuses commits without
  one). `scripts/install-hooks.sh` switched to
  `git config core.hooksPath .githooks` so hooks update on `git pull`. (#75)
- **README headline numbers (modules / LoC / tests) become an SSOT**
  produced by `scripts/update-readme-stats.sh`; CI fails on drift.
  Underlying script bug fixed: previously did `find -maxdepth 1` and
  `wc -l src/*.rs`, missing `src/sovereign/`. (#76)

### Quality / Polish

- **SPDX `Apache-2.0` header on every Rust file** (32 files in `src/` +
  `tests/`) so the licence is machine-readable for SBOM scanners. (#79)
- **Complete `unsafe` SAFETY audit**: 11/11 unsafe blocks now carry a
  `// SAFETY:` note; added the missing one on `src/net.rs::tune_accepted`. (#79)
- **Module-level docstrings** added on the five files that lacked them:
  `config.rs`, `dispatch.rs`, `main.rs`, `proxy.rs`, `tls.rs`. (#78)
- **Dead-code cleanup**: 5 unreachable items removed
  (`cache.rs::ensure_l1`, `bootstrap.rs::tune_accepted_socket`,
  `tune_listener_socket`, `Platform.recv_buf`, `auth.rs::AuthError::MissingToken`).
  The remaining ~45 `#[allow(dead_code)]` annotations are intentional
  (feature-gated, future-API hooks, deser-only struct fields, test
  helpers) and already documented. (#81)
- **Stale `RELEASE_NOTES.md` removed**: it was a v0.1.6-specific
  announcement that nobody refreshed; `CHANGELOG.md` + GitHub Releases
  cover the role. (#83)
- **README OpenSSF Baseline badge** in place of the broken Scorecard
  badge (publish_results was disabled in v0.1.10 to satisfy the
  Scorecard webapp constraint, which in turn broke the badge endpoint). (#74)

### CI

- **New `integration` workflow**: spins up the test backend on `:9090`
  and zion on `:4433` (with a self-signed cert via
  `benchmarks/certs/generate.sh`) and runs the 19 `#[ignore]`d
  integration tests. They were rotting silently — now load-bearing on
  every PR. (#82)
  - Two pieces of rot the unrun tests had hidden are also fixed in this
    release: `tests/integration.rs::t01` asserted `<h1>Zion Test Backend</h1>`
    (no backend ever served this string), and the Rust test backend
    lacked the `query` / `x_forwarded_proto` echo fields and the
    `/api/v1/events/stream` SSE endpoint that the tests rely on.
- **New `version-sync` and `readme-stats-sync` workflows** wire the SSOT
  scripts above into per-PR enforcement. (#75, #76)
- **Branch protection cleaned**: dropped `SBOM (CycloneDX)` from
  required status checks (release-only, was never green on PRs and made
  every PR `mergeStateStatus: BLOCKED`); fixed `DCO` → `dco-check` name
  mismatch.

### Verification

```text
cargo fmt --all -- --check                          # OK
cargo clippy --locked --all-targets --all-features -- -D warnings   # OK
cargo test  --release                  → 421 passed (lib + main bin + chaos)
cargo test  --release --all-features   → 463 passed
integration tests (CI)                 → 19 passed
scripts/check-version-sync.sh          # OK across 7 reference sites
scripts/update-readme-stats.sh --check # in sync
```

## [0.1.11] - 2026-05-06

Process hardening — version becomes single-source-of-truth, DCO sign-off
becomes draconian. Closes the two CI failure modes seen on recent PRs
(`uninlined_format_args` on Windows + MSRV `--all-targets`, missing
`Signed-off-by` trailer) at the source.

### Added
- **Version SSOT enforcement.** `Cargo.toml` is the canonical version;
  drift across `Cargo.lock`, `deploy/helm/zion/Chart.yaml`,
  `README.md`, and `docs/security/supply-chain.md` is now a hard error.
  - `scripts/check-version-sync.sh` — verify (run by `pre-push` and CI).
  - `scripts/bump-version.sh X.Y.Z` — atomic bump propagated to every site.
  - `.github/workflows/version-sync.yml` — server-side guard on PRs to
    `master` and on every push.
- **Mandatory DCO sign-off via local hooks.**
  - `.githooks/prepare-commit-msg` auto-injects the `Signed-off-by` trailer
    (idempotent, `git interpret-trailers --if-exists addIfDifferent`).
  - `.githooks/commit-msg` refuses commits without a valid trailer.
  - `scripts/install-hooks.sh` switched from copying into `.git/hooks/` to
    `git config core.hooksPath .githooks` — hooks are now version-controlled
    and update on `git pull`.

### Changed
- **CI lint fixes** (already landed post-0.1.10, recorded here for
  release notes): `uninlined_format_args` resolved in `src/doctor.rs`,
  `src/listener.rs`, `src/uring.rs`; MSRV job relaxed for `--all-targets`;
  CodeQL Rust build-mode and Scorecard `publish_results` corrected.
- **Helm chart appVersion** bumped to 0.1.11 (chart `version` unchanged).

### Verification

```text
scripts/check-version-sync.sh                      # OK
cargo check                                        # OK
cargo test                                         # 77 tests, all passing
.githooks/prepare-commit-msg + commit-msg          # idempotent + rejects unsigned
```

## [0.1.10] - 2026-05-05

Supply-chain hardening — closes 3 of the 4 OSSF Scorecard gaps surfaced
on the v0.1.9 release. No code changes; CI / Helm / Dockerfile only.

### Added
- **Branch protection on `master`** (10 required status checks: CI Success,
  cargo-deny ×4, cargo-audit, SBOM CycloneDX, CodeQL ×2, DCO; linear
  history; force-push and delete disabled; conversation resolution
  required).

### Changed
- **All 71 GitHub Action references** across 8 workflow files pinned by
  40-char commit SHA (with `# vX` comment for human readability and
  Dependabot SHA-aware bumping). Resolved via `gh api repos/<o>/<r>/commits/<ref>`.
- **All 6 Docker base images** pinned by digest (`Dockerfile`,
  `benchmarks/Dockerfile.zion`, `benchmarks/backend/Dockerfile`).
- **Token-Permissions** scoped to least-privilege:
  - `dco.yml`: explicit `contents: read` (top + job).
  - `sovereign-data.yml`: top-level `contents: read`; `contents: write`
    + `pull-requests: write` only on the `refresh-ita` job.
- **Helm chart** bumped to 0.2.2 (appVersion 0.1.10).

### Verification

```text
cargo fmt --all -- --check                          # OK
cargo clippy --locked --all-targets --all-features -- -D warnings   # OK
cargo test  --locked --all-features    →  463 passed
cargo deny  --all-features check       →  advisories ok, bans ok, licenses ok, sources ok
helm lint deploy/helm/zion                          # OK
actionlint .github/workflows/*.yml                  # OK
```

OSSF Scorecard sub-checks moved from 0/10 to 10/10:
Token-Permissions, Pinned-Dependencies, Branch-Protection.

## [0.1.9] - 2026-05-05

Five-track quality pass: Trust & supply chain, Observability, Robustness
& API, Performance ceiling, Compliance & conformance. No breaking changes
to existing operators; every new behaviour is opt-in or back-compatible.

### Added — Track A (Trust & Supply Chain)
- **SLSA v1.0 build provenance** for every binary, the `SHA256SUMS` file,
  the SBOM, and every container image — generated by
  `actions/attest-build-provenance@v2` and recorded in the public Sigstore
  Rekor log. (`.github/workflows/release.yml`)
- **Cosign keyless signatures** on every published GHCR multi-arch image,
  bound to the canonical release-workflow OIDC identity.
- **CycloneDX 1.5 SBOM** attached to each release and as a cosign attestation.
- **Cross-compiled binaries** for 7 targets via `cargo-zigbuild`:
  `x86_64-unknown-linux-{gnu,musl}`, `aarch64-unknown-linux-{gnu,musl}`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.
- **`cargo-deny` policy** (`deny.toml`) and **`cargo-audit` config** kept
  in sync; new `.github/workflows/supply-chain.yml` runs daily.
- **CodeQL** (Rust + GitHub Actions) on every PR.
- **Dependabot** with grouping and security-only fast-track.
- **Distroless container** (`gcr.io/distroless/cc-debian12:nonroot`,
  UID 65532, no shell, no SUID).
- **MSRV** dichiarata: `1.82` per il binario core (no-default-features),
  `1.88` con feature opzionali. CI verifica entrambi i floor.
- **Documentazione** [docs/security/supply-chain.md](docs/security/supply-chain.md).

### Added — Track B (Observability)
- **`tracing` always-on** (`tracing-subscriber` JSON or text) replaces the
  bespoke `logging::*` chain for everything past the boot banner.
- **W3C Trace Context** parser with strict RFC validation; malformed
  inbound `traceparent` headers are rejected and counted, never forwarded.
- **OpenMetrics exemplars** on every histogram bucket — each `_bucket{le=…}`
  line carries `# {trace_id="…"} value timestamp` of the latest observation
  in that bucket.
- **OTLP gRPC export** behind `--features otel`. Off by default; pulls in
  `tonic`/`prost` only when enabled.
- **HMAC-SHA256-chained audit log** (`src/audit.rs`) — JSON-Lines, async
  bounded writer, PII redaction applied before signing. New `[audit]` and
  `[redact]` config blocks.
- **Panic hook** writes one structured JSON record to stderr and to a
  "last-gasp" file (`/var/lib/zion/last_panic.jsonl`) before abort.
- New counters: `zion_panics_total`, `zion_audit_events_total`,
  `zion_audit_events_dropped_total`, `zion_traces_emitted_total`,
  `zion_traces_invalid_total`.
- **Documentazione** [docs/guide/observability.md](docs/guide/observability.md).

### Added — Track C (Robustness & API)
- **`enum ZionError`** unifies the boot path's error type
  (`Box<dyn Error>` removed from `main` and `async_main`). Per-category
  Unix exit codes via `to_exit_code()`.
- **`SAFETY:` / `INVARIANT:` audit** of every production
  `unwrap()` / `expect()` / `panic!`; QUIC builders refactored from
  `expect()` to `Result<_, String>`.
- **Property-based tests** (`proptest`): 11 properties on rate-limiter,
  W3C parser, redaction, HMAC determinism.
- **`cargo-fuzz` workspace** with three targets: `traceparent_parser`,
  `redact_query_string`, `audit_chain_verify`. CI build-only verification.
- **Chaos integration tests** (`tests/chaos.rs`): audit queue overflow,
  drain, idempotence.
- **Threat model (STRIDE)** — [docs/security/threat-model.md](docs/security/threat-model.md).
- **Architecture Decision Records** — [docs/adr/](docs/adr/) with 7
  load-bearing decisions (ArcSwap hot-reload, Aho-Corasick, two-level
  cache, HMAC audit, distroless+SLSA, tracing+OTLP, MSRV bicapa).
- **Helm chart 0.2.0**: PodDisruptionBudget, default-deny NetworkPolicy,
  dedicated ServiceAccount with `automountServiceAccountToken: false`,
  pod-level seccomp `RuntimeDefault`, `readOnlyRootFilesystem` with
  emptyDir for ACME state, startupProbe + tunable timeouts,
  topologySpreadConstraints.

### Added — Track D (Performance)
- **Sovereign log: zero-alloc hot path.** The per-request
  `format!("ip=… class=…")` in `dispatch.rs` is replaced by per-class atomic
  counters (`zion_sovereign_classifications_total{class="…"}`) plus a
  `tracing::info!` event with `&'static str` labels.
- **Streaming WAF body scan** (`waf::StreamingScanner`) — chunked
  Aho-Corasick with a 63-byte overlap buffer, early-exit on first match,
  incremental `max_body_mb` enforcement. Public API + tests; dispatch
  wiring tracked in [docs/perf/roadmap.md](docs/perf/roadmap.md).
- **Performance roadmap** for the deferred items: NUMA-aware sharding,
  io_uring r/w vectored, kTLS sendfile, BPF demux for unified TCP/QUIC.

### Added — Track E (Compliance)
- **FIPS 140-3 build** behind `--features fips` — switches to
  `aws-lc-fips-sys` (NIST CMVP Cert. #4759). TLS 1.3 ciphers, audit-log
  HMAC, ticketer all run through the validated module. Documentazione
  in [docs/security/fips.md](docs/security/fips.md).
- **OWASP ASVS L2 mapping** — [docs/security/asvs.md](docs/security/asvs.md):
  V1/V3/V4/V5/V7/V8/V9/V10/V12/V13/V14, control → impl file → test/evidence.
- **TLS conformance plan** — [docs/security/tls-conformance.md](docs/security/tls-conformance.md):
  BoGo / RFC 8446 / SSL Labs recipes.
- **GDPR access log**: structured `tracing::info!(target: "access")` event
  per request with query-string redaction via `[redact.query_params]`.

### Fixed
- **`rustls-webpki` 0.103.10 → 0.103.13** — addresses RUSTSEC-2026-0104
  (reachable panic in CRL parsing). Caught at first run of the new
  supply-chain pipeline.
- **`Ticketer::new().expect()`** — replaced with `?`-propagation; CSPRNG
  starvation now surfaces as `ZionError::Tls` with a clean exit code.
- **Clippy 1.88 lints**: `uninlined_format_args` (170+ sites),
  `clippy::precedence` in `src/security.rs:142,158`, `should_implement_trait`
  on `LogFormat::from_str` → renamed to `parse_or_text`.

### Verification

Local validation against this release:

```text
cargo fmt --all -- --check                          # OK
cargo clippy --locked --all-targets --all-features -- -D warnings   # OK
cargo clippy --locked --all-targets --no-default-features -- -D warnings   # OK
cargo test  --locked --all-features    →  49 lib + 410 bins + 4 chaos = 463 passed
cargo test  --features fips --bins     →  368 passed (FIPS module compiled)
cargo doc   -D warnings --all-features                              # OK
cargo deny  --all-features check       →  advisories ok, bans ok, licenses ok, sources ok
cargo audit                                                          # OK
rustup run 1.82.0 cargo check --no-default-features                  # OK (MSRV floor)
helm lint deploy/helm/zion                                           # OK
```

Verifying a release artifact:

```bash
# Binary
gh release download v0.1.9 -R fabriziosalmi/zion -p '*x86_64-unknown-linux-musl*' -p 'SHA256SUMS'
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify zion-v0.1.9-x86_64-unknown-linux-musl.tar.gz --owner fabriziosalmi

# Container
cosign verify ghcr.io/fabriziosalmi/zion:v0.1.9 \
    --certificate-identity-regexp "^https://github.com/fabriziosalmi/zion/\\.github/workflows/release\\.yml@refs/tags/v" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

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
