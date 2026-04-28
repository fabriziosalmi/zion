# Zion v0.1.6 — WAF Shadow Mode, `auto`, `bootstrap` JSON

A pure tooling release on top of v0.1.5: the proxy hot path is unchanged,
but operators get three substantial new ergonomics.

## Highlights

### 🛡 WAF Shadow Mode — risk-free migration from nginx / ModSecurity

```toml
[[route]]
path        = "/api/{*rest}"
upstream    = "backend"
waf_profile = "strict"
waf_shadow  = true   # ← run WAF, but never block; just log + count
```

Each would-be denial:
- emits a `logging::warn` line tagged `event: waf_shadow` with
  `would_block=true`, `source=uri|body|headers`, `reason=…`, and the
  request path. JSON log mode (Loki / ELK / Datadog) gets it
  byte-identical for parsing.
- increments the new `zion_waf_shadow_would_block` Prometheus counter
  (also surfaced in `/_zion/snapshot.json`).
- lets the request through unchanged.

Routes table at boot now shows `waf:shadow` (amber) so operators see
at a glance which routes are simulating vs enforcing. Letting an ops
team observe their real traffic against the WAF profile for hours / days
before flipping to enforce was the #1 ask from sysadmins migrating off
nginx + ModSecurity.

### 🚀 `zion auto --upstream :3000` — no-config dev mode

```bash
cargo build --release --features init
./zion auto --upstream :3000
```

Generates a self-signed cert + ephemeral `zion.toml` in `$TMPDIR/zion-auto-{pid}/`,
points TLS at it, and runs the daemon. Zero config files on the operator's
disk. The `:3000` shorthand normalizes to `127.0.0.1:3000`. Defaults to
unprivileged ports `8080` / `8443` so nothing needs root.

```bash
./zion auto --upstream 10.0.0.5:8000 \
            --hostname dev.example.com \
            --https-port 8443
```

Single command, full TLS pipeline (rustls + hardware crypto), full WAF
default profile available, full live calibration in the boot ceremony.

### 🤖 `zion bootstrap` — JSON output for CI / automation

```bash
./zion bootstrap | jq '.tier, .aes_kops_per_core, .has_aes_ni'
```

Detect the platform (incl. live AES-GCM calibration unless
`ZION_BOOT_FAST=1`) and dump the result as JSON to stdout. Schema mirrors
the `platform` field of `/_zion/snapshot.json` so an Ansible / Terraform
playbook can use the same parser for boot-time provisioning and live
runtime polling.

## CLI

```
zion              # daemon (unchanged, default)
zion auto         # one-shot dev mode (NEW — requires --features init)
zion top          # live TUI dashboard
zion init         # interactive config wizard
zion doctor       # environment diagnostic
zion bootstrap    # platform JSON dump (NEW)
zion --version
zion --help
```

## Compatibility

- ✅ Backward compatible — the proxy hot path, `/metrics` Prometheus
  output, JSON log format, snapshot schema, systemd / Docker / k8s /
  Helm invocations all unchanged.
- ✅ New `waf_shadow` field is `#[serde(default)]` — existing
  `zion.toml` files load unchanged.
- ➕ New Prometheus counter `zion_waf_shadow_would_block` (always
  emitted, value 0 when no shadow routes are configured).
- ➕ `ZION_BOOT_FAST=1` (already shipped in v0.1.5) now skips the AES
  calibration in `zion bootstrap` too.

## Internals

- New module entry points: `init::run_auto()`, `bootstrap::dump_platform_json()`.
- `metrics::Metrics` gains `waf_shadow_would_block: ShardedCounter`.
- `RouteConfig` and `ResolvedRoute` gain `waf_shadow: bool`.
- 3 deny sites in `dispatch.rs` (URI, body, headers) now branch on
  `rule.waf_shadow`: shadow logs + counts, enforce returns 400.
- Test count: **268 → 277** (+9 tests in this release).
- Zero new dependencies. All new functionality compiles into the same
  feature-gated modules introduced in v0.1.5 (`init`, `tui`).

## No perf-path changes

The proxy hot path is **byte-identical** to v0.1.5. The WAF shadow
branch adds one boolean check per request when the route has WAF
attached — well below benchmark noise. Existing benchmark numbers from
v0.1.4 in the README remain accurate; the shipped
`Zion-v0.1.0-Scientific-Report.pdf` link points to the historical v0.1.0
baseline. Re-run `bash benchmarks/bench-scientific.sh` if you want a
fresh PDF for v0.1.6 — no code path warrants it.

## Quick start

```bash
cargo build --release --features init,tui

# Fastest path: dev TLS in 1 command
./target/release/zion auto --upstream :3000

# Full setup
./target/release/zion init        # generate zion.toml + cert
./target/release/zion doctor      # check environment
./target/release/zion bootstrap | jq .tier   # what platform tier am I?
ZION_CONFIG=zion.toml ./target/release/zion  # run daemon
./target/release/zion top         # live dashboard
```
