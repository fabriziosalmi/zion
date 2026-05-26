# Changelog

All notable changes to Zion Edge Gateway are documented here.

## [Unreleased]

### Added

- **ACME issue → renew → revoke soak in CI (#59)**
  ([`.github/workflows/acme-soak.yml`](.github/workflows/acme-soak.yml),
  [`src/acme.rs`](src/acme.rs)). New `acme-soak` weekly + on-demand
  workflow drives the full certificate lifecycle against a hermetic
  [Pebble](https://github.com/letsencrypt/pebble) test CA with mocked DNS
  (`pebble-challtestsrv`) — no real Let's Encrypt, no external DNS, no
  rate limits. A hidden `zion acme-soak` subcommand runs zion's *real*
  `renew_once` / `revoke_cert` paths and asserts the lifecycle counters
  move, so an ACME-flow regression fails the soak. A matrix leg injects
  `PEBBLE_WFE_NONCEREJECT=50` to prove instant-acme's `badNonce` retry
  holds (the nonce-collision failure mode). New metrics
  `zion_acme_renewals_total` and `zion_acme_renewal_failures_total`;
  new operator-facing `revoke_cert` for retiring a compromised key.
  Docs: [`docs/config/acme.md`](docs/config/acme.md).

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
