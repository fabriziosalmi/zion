# Zion v0.1.5 — Cinematic Boot, Live Calibration, `top` / `init` / `doctor`

The boot ceremony is rebuilt from the ground up, and Zion now ships with
three first-class CLI tools that close the onboarding loop end-to-end:

- **`zion`** — daemon (unchanged, default invocation)
- **`zion top`** — htop-style live dashboard
- **`zion init`** — interactive config wizard with self-signed cert generation
- **`zion doctor`** — environment diagnostic with actionable fixes

Time from a fresh `cargo build` to a running daemon serving HTTPS: **30
seconds**. From the same build to a tuned production environment with all
the gotchas surfaced and fixed: **a couple of minutes**.

Backward compatible — every existing `systemd` / `Docker` / `helm` / `k8s`
invocation works unchanged. Default daemon behavior is identical; new
subcommands are additive.

## Highlights

### Boot ceremony

- 🌈 **Cinematic header** — the `ZION` title cycles 3× through a 6-color
  rainbow (~450 ms) before settling on bold metallic white. Fully
  suppressed when piped to log collectors or under `NO_COLOR`.
- 🏆 **Performance Tier** badge (S/A/B/C) computed from cores, RAM,
  hardware crypto (AES-NI/CE, SHA), SIMD, and OS networking primitives.
- ⚡ **Live AES-128-GCM calibration** at boot via `aws-lc-rs` — the
  hardware ceiling printed in the badge is *measured* in ~80 ms, never an
  estimate. Apple M4 measures ~5–6 M seal/s/core.
- 🧮 **One-line synthesis** — `crypto 3/3 · os net 2/3 · cache 64KB ·
  workers 9 · conns 83K`, screenshot-ready.
- 🗺 **Routes mini-table** — paths aligned, semantic tags colored by
  category (`waf` green, `sse`/`ws`/`static` cyan, `internal` amber).
- 🚦 **READY banner** with snapshot URL and `zion top` hint — closes the
  discoverability loop on the new dashboard.
- ⚠️ **Colored warnings** — all `logging::warn` / `logging::error` get a
  bold amber/red glyph in TTY mode; JSON-mode output is byte-identical
  for log collectors.

### `zion top` — live dashboard

```bash
cargo build --release --features tui
./target/release/zion top
```

htop-style TUI with traffic counters, p50/p95/p99 latency, status-class
breakdown, RPS sparkline, cache hit-rate gauge, per-upstream health.
Polls the new `/_zion/snapshot.json` endpoint at sub-second cadence.

### `zion init` — interactive bootstrap wizard

```bash
cargo build --release --features init
./target/release/zion init                 # interactive
./target/release/zion init -y              # non-interactive (CI / scripting)
```

The wizard:
1. Detects hardware (cores, RAM, OS) and probes common dev ports
   (`3000`, `5173`, `4000`, `5000`, `8000`, `8080`, `8081`, `9000`,
   `3001`) with port-name heuristics.
2. Prompts for hostname, upstreams, listener ports, TLS, WAF.
3. Generates a commented `zion.toml` (~30–50 lines) plus
   `tls/server.crt` + `tls/server.key` (self-signed, 365-day validity).
4. Prints the next-step commands: `zion`, `zion top`, `zion doctor`.

Refuses to overwrite an existing `zion.toml` unless `--force`. Without
the `init` feature, the wizard runs but falls back to printing the
equivalent `openssl` command for the operator.

### `zion doctor` — environment diagnostic

```bash
./target/release/zion doctor
```

Runs a checklist with green/amber/red status and a `fix:` line for each
issue:

- `fd limit` (RLIMIT_NOFILE — fail < 1024, warn < 8192)
- `privileged port :80` and `:443` (try-bind, surface EACCES vs EADDRINUSE)
- `somaxconn` (Linux — warn if < 1024)
- `kernel version` (Linux — note io_uring 5.19+ availability)
- `hardware crypto` (AES-NI + SHA-256 + SIMD)
- `aes calibration` (sanity-checks the live AES-GCM measurement)

Exit code 0 on success/warnings, 2 on hard failures. Always available —
diagnostics aren't feature-gated.

## New CLI

```
zion              # run the gateway daemon (default — unchanged)
zion top          # live TUI dashboard (requires --features tui)
zion init         # interactive wizard (requires --features init for cert gen)
zion doctor       # environment diagnostic (always available)
zion --version    # print version
zion --help       # full help
```

`zion top` accepts `--url <URL>` and `--interval <MS>`.

`zion init` accepts:

| Flag | Effect |
|---|---|
| `-o, --output <PATH>` | Output config path (default `zion.toml`) |
| `-f, --force` | Overwrite an existing config |
| `-y, --non-interactive` | Skip prompts; use defaults + flags |
| `--hostname <H>` | Hostname Zion will serve |
| `--upstream NAME=HOST:PORT` | Declare an upstream (multi-allowed) |
| `--http-port <N>` | Override HTTP port (default 80) |
| `--https-port <N>` | Override HTTPS port (default 443) |
| `--no-tls` | Skip self-signed cert generation |
| `--no-waf` | Skip WAF on `/api/*` routes |

## Override env vars

| Variable | Effect |
|---|---|
| `NO_COLOR=1` | Disables all ANSI colors |
| `ZION_BOOT_PLAIN=1` | Same as `NO_COLOR=1` |
| `ZION_BOOT_ANIMATE=0` | Disables the rainbow header animation |
| `ZION_BOOT_FAST=1` | Skips the 80 ms AES-GCM calibration (CI / k8s init) |

## Quick start

Zero config, 30 seconds to first request:

```bash
cargo build --release --features init,tui
./target/release/zion init                                 # generate zion.toml + cert
./target/release/zion doctor                               # check environment
ZION_CONFIG=zion.toml ./target/release/zion                # run
./target/release/zion top                                  # live dashboard (in another terminal)
```

For CI / container init / scripted provisioning:

```bash
./zion init -y \
    --hostname api.example.com \
    --upstream backend=127.0.0.1:8000 \
    --upstream frontend=127.0.0.1:3000
```

## Compatibility

- ✅ Backward compatible — all existing systemd units, Docker images,
  Kubernetes manifests, and Helm charts continue to work without changes.
- ✅ JSON log format unchanged byte-for-byte (Loki / ELK / Datadog
  parsers unaffected).
- ✅ `/metrics` Prometheus endpoint format unchanged.
- ➕ New endpoint `/_zion/snapshot.json` (internal-only, opt-in via
  consumption — no change to existing routing).

## Internals

- New modules: `bootstrap` (extended), `cli`, `tui`, `init`, `doctor`.
- `Platform` struct gains `tier()`, `tier_score()`, `aes_kops_per_core`,
  `aes_kops_total()`, `calibration_us`, all surfaced in the JSON snapshot.
- `metrics::snapshot_json()` and `LatencyHistogram::quantile_us()` feed
  the TUI and any external dashboard.
- Logging gains TTY-aware colored prefixes for warn/error; format paths
  are testable independently of global `OnceLock` state.
- HTTP listener now binds synchronously so the boot order is
  deterministic: `listening HTTP` → `listening HTTPS` → `READY` banner.
- Test count: **99 → 227** (+128 tests added across this release).
- Zero new mandatory deps. New optional features:
  - `init` pulls `rcgen` (already transitive via `acme`)
  - `tui` pulls `ratatui` 0.29 + `crossterm` 0.28

## Helm chart

The bundled chart in `deploy/helm/zion/` is bumped to `0.1.5` /
`appVersion: "0.1.5"` / `image.tag: "v0.1.5"`. `helm install zion ./deploy/helm/zion`
picks up the new image once the Docker image is published.

## Acknowledgements

Built with multi-step rigor: every visual / functional change is its own
verified increment. Boot polish alone went through 8 sequential steps
(visual integrity, discoverability, honest measurement, animation,
synthesis, routes table, etc.), each individually screenshot-validated
before moving on. No skipping, no batching.
