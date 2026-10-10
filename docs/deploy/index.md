# Deployment

## Build

```bash
cargo build --release
```

The release profile is optimized for maximum performance:

| Setting | Value | Effect |
|---|---|---|
| `opt-level` | 3 | Maximum optimization |
| `lto` | fat | Full link-time optimization across all crates |
| `codegen-units` | 1 | Single codegen unit for best optimization |
| `strip` | true | Strip debug symbols (~5 MB binary) |
| `panic` | abort | No unwinding overhead |

### Which processors a build runs on

A binary compiled for a newer processor than the one it meets stops with an illegal
instruction before it prints a word. So a default build, the release tarballs and the
image assume the baseline of their target and nothing later:

| Binary | Assumes | Checked at every release |
|---|---|---|
| Linux x86_64 tarballs (gnu, musl, `-pgo`), the amd64 image | x86-64 baseline (SSE2): any 64-bit Intel or AMD processor | declared by the binary, and run under an emulated SSE2-only processor |
| Windows x86_64 | the compiler's default (SSE3) | declared by the binary |
| macOS, Intel | the compiler's default (SSE4.1): any Intel Mac since 2008 | declared by the binary |
| macOS, Apple Silicon | Apple M1 | declared by the binary |
| Linux aarch64 tarballs (gnu, musl), the arm64 image | ARMv8.2 (`neoverse-n1`): under emulation they run on Cortex-A76 and Neoverse N1 (Graviton 2) and stop with an illegal instruction on Cortex-A53 and Cortex-A72 (Raspberry Pi 3 and 4, Graviton 1), [#666](https://github.com/fabriziosalmi/zion/issues/666) | not checked |

"Declared" is `zion bootstrap`: `build_target_features` lists what the compiler was
allowed to assume, and the release fails if that is more than the compiler's default for
the target. "Run under an emulated processor" is
[`scripts/cpu-baseline-smoke.sh`](https://github.com/fabriziosalmi/zion/blob/master/scripts/cpu-baseline-smoke.sh):
the binary serves TLS, HTTP/1.1 and HTTP/2, files, proxied and cached responses and WAF
verdicts under `qemu` with a processor model that has SSE2 and nothing later. macOS and
Windows binaries cannot be run that way, so for them it is the declaration alone.

Up to v0.12.0 the Linux x86_64 builds, the Windows build and the amd64 image were compiled
for `x86-64-v3` (AVX2, BMI2, FMA: Haswell, 2013, or newer) and did not start on an older
Xeon or on an Atom-class Celeron or Pentium. What that flag bought, measured on v0.12.0 as
CPU per request of a baseline build against the `x86-64-v3` one (two runs of five
interleaved trials each; positive = the baseline build costs more):

| Workload | Baseline against `x86-64-v3` |
|---|---|
| cached 5 KB document | −1.3 % / +3.6 % |
| the same, access log on | +1.7 % / +3.3 % |
| the same over HTTP/2 | +1.1 % / +0.7 % |
| proxied, no cache | −0.3 % / +1.8 % |
| example-site mix | +0.3 % / +0.7 % |
| files from disk | −1.0 % / −0.8 % |
| full TLS handshake | +0.2 % / +0.2 % |

Only the access-log row is on the same side of zero in every trial of both runs. The TLS
library and the byte-search code choose their AES-NI and AVX2 paths when the process
starts, whatever the build flags say.

To build for the machine you are on:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

That binary runs on that processor family and newer, and `zion bootstrap` says so.

## systemd

Copy the binary and config:

```bash
sudo cp target/release/zion /usr/local/bin/zion
sudo mkdir -p /etc/zion
sudo cp zion.toml /etc/zion/zion.toml
```

Install the service unit:

```ini
[Unit]
Description=Zion Edge Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=zion
Group=zion
ExecStart=/usr/local/bin/zion
Environment=ZION_CONFIG=/etc/zion/zion.toml
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/zion
PrivateTmp=true

# Writable runtime state. ProtectSystem=strict makes the FS read-only, so
# without this the ACME subsystem (account key + renewed cert/key under
# /var/lib/zion) and the panic last-gasp file cannot be written. StateDirectory
# creates /var/lib/zion owned by the service user and grants write access.
StateDirectory=zion
Environment=ZION_LAST_GASP_PATH=/var/lib/zion/last_panic.jsonl

# Allow binding to privileged ports (80, 443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /sbin/nologin zion
sudo cp deploy/zion.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zion
```

## Docker

::: tip Use the official image for production
This is a **minimal illustrative** Dockerfile — it runs as **root** on a
`debian-slim` base and is not the hardened image. For production pull the
official image, which is **distroless, non-root (UID 65532)**, multi-arch, and
cosign-signed with SLSA provenance:
`docker pull ghcr.io/fabriziosalmi/zion:latest`. Build it from the repo
[`Dockerfile`](https://github.com/fabriziosalmi/zion/blob/master/Dockerfile) if
you need to build locally.
:::

```dockerfile
FROM rust:1.82-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/zion /usr/local/bin/zion
COPY zion.toml /etc/zion/zion.toml
EXPOSE 80 443
CMD ["zion"]
ENV ZION_CONFIG=/etc/zion/zion.toml
```

```bash
docker build -t zion .
docker run -d \
  -p 80:80 -p 443:443 \
  -v /etc/ssl/zion:/etc/ssl/zion:ro \
  -v /path/to/zion.toml:/etc/zion/zion.toml:ro \
  --name zion zion
```

## Config validation

Zion validates the entire configuration at startup. Checked items:

- Server addresses are valid socket addresses
- TLS cert and key files exist on disk
- All SNI cert/key files exist
- At least one route is defined
- Every route references a known upstream
- Every `waf_profile` and `cache_profile` reference exists
- All upstream URLs are valid URIs

## Exit codes

The daemon's exit code encodes the **failure category**, so a supervisor
(systemd `Restart=`, Kubernetes `restartPolicy`) can branch — a config error
should not drive a restart loop, a transient bind failure can. The contract is
covered by `tests/exit_codes.rs`:

| Code | Category | Meaning |
|------|----------|---------|
| `0`  | success  | Clean shutdown (e.g. after `SIGTERM`) |
| `2`  | config   | Config unreadable, unparseable, or failed validation (bad address, dangling upstream, unknown profile reference, …) |
| `3`  | tls      | TLS material bad — cert/key missing, malformed, or mismatched |
| `4`  | listener | Binding a listen socket failed (port in use, permission denied) |
| `5`  | runtime  | A runtime subsystem failed to start — ACME, auth, or audit |
| `1`  | other    | Any other fatal error |

There is no dedicated `--check` mode: starting the daemon **is** the validation.
On a bad config it exits fast with the matching category code above (before
binding any port); on a good config it keeps running and serving. So a quick
pre-flight is "did it fail fast?", not `&& echo OK` (which would only fire once
the server later shuts down):

```bash
# Exits 0 only if the config loaded AND TLS came up within the window; a
# non-zero code is the failure category from the table above.
ZION_CONFIG=./zion.toml timeout 2s ./zion; code=$?
[ "$code" = 124 ] && echo "config + TLS OK (still serving)" || echo "failed: exit $code"
```

## Graceful shutdown

Zion handles `SIGINT` (Ctrl+C) and `SIGTERM`:

1. Stop accepting new connections, and tell every open connection to wind down: an **idle**
   keep-alive connection is closed at once, an HTTP/1 connection closes after the response in
   flight (`Connection: close`), and an HTTP/2 connection gets `GOAWAY`, finishes its open
   streams and closes. A request already being served is never cut. (Before 0.9.5 an idle
   keep-alive connection held the drain until its own idle timeout, so a deploy could wait up
   to the full 30 s.)
2. Wait up to **30 seconds** for in-flight connections to complete
3. If drain timeout expires, force exit with a warning log
4. Stop the audit-log writer (when `[audit]` is enabled): it writes everything still queued, flushes and `fsync`s; Zion waits up to **5 seconds** for it (`audit writer did not finish within 5s` if it takes longer)

This works by acquiring all semaphore permits (connection limit). When all active connections release their permits, the drain is complete.

**Panics bypass the drain.** Release builds compile with `panic = "abort"`, so a
reachable panic anywhere (request/WAF/proxy/reload path, or unsafe FFI)
`SIGABRT`s the whole process immediately — the 30 s drain does **not** run and
every in-flight connection is severed. This is a deliberate trade-off (the code
holds a no-reachable-panic doctrine, so a panic signals a bug, not expected
load): keep Zion under a supervisor that restarts on non-zero/abnormal exit
(systemd `Restart=on-failure`, Kubernetes `restartPolicy`), and rely on multiple
replicas + a load balancer to absorb the loss of one instance.

## State that does not survive a restart

Some enforcement state is deliberately process-local and starts empty after every
restart, including a supervisor-driven crash-loop recovery:

- **`[tls.fingerprint]` bans** (a rejected-unknown JA4 fingerprint is refused for a
  while): the ban set is in memory, so a restarted instance admits a previously
  banned fingerprint again until it is re-detected. Enforcement therefore resets at
  exactly the moment the service is unstable. Run more than one replica so a
  restart of one does not reset the fleet, and treat a restart as clearing the ban
  list when you reason about an incident.
- **Per-IP rate-limit and connection counters** restart from zero.
- **The mesh identity** (`[sovereign_aimp]`) is persisted, but claims the mesh has
  not yet re-gossiped are not.

## Certificate renewal

With `hot_reload = true` (default), certificate renewal requires no restart:

1. Renew certificates (e.g., via certbot)
2. Write new files to the watched directory
3. Zion detects the change, debounces 2 seconds, reloads
4. New connections use new certs; in-flight connections are unaffected

## Scaling & limits

**Per-node connection ceiling.** The global concurrent-connection limit is
derived from memory (25% of it ÷ 256 KB per connection), between 1,000 and
100,000. The memory is the cgroup limit when the process runs under one (a
container, a pod, a systemd unit with `MemoryMax=`), the machine's RAM
otherwise. The connection over the ceiling is shed at accept. To go above
100,000 on a large box, or below the derived value in a small container, set
`[server] max_connections` (read at start). See
[Hardening](/security/hardening#connection-limit) for what a connection costs.

**Per-replica enforcement (multi-replica).** Rate limiting
(`rate_limit_rps`), the per-IP connection cap (`max_connections_per_ip`), and
JA4 fingerprint bans are **process-local, in-memory** state. They are enforced
**per replica**, not fleet-wide. Behind an L4 load balancer with N replicas, a
single client's effective allowance is the configured value **× N**: e.g.
`max_connections_per_ip = 100` across 10 replicas lets one source IP hold ~1,000
concurrent connections, and a JA4 fingerprint banned on one replica is not
banned on the others until it independently crosses the threshold there. Despite
the "global" wording in some config docs, these limits are per-process. To size
them:

- divide the intended fleet-wide limit by the replica count, **or**
- front the fleet with source-IP-hash affinity so a client is pinned to one
  replica, **or**
- accept per-replica semantics for a defence-in-depth (not exact) bound.

The shipped Helm chart defaults to 2 replicas and autoscales to 10 — plan the
limit values accordingly.

## Kubernetes (Helm)

The chart is in [`deploy/helm/zion`](https://github.com/fabriziosalmi/zion/tree/master/deploy/helm/zion).
Zion needs a serving certificate, so the chart requires a `kubernetes.io/tls`
Secret (for example issued by cert-manager) and refuses to render without one:

```bash
kubectl create secret tls zion-tls --cert=tls.crt --key=tls.key
helm install zion deploy/helm/zion -f my-values.yaml   # with tls.existingSecret: zion-tls
```

- Probes go to `/healthz` and `/readyz` over HTTPS (kubelet does not verify the
  certificate); the plain-HTTP port answers everything with a redirect.
- `autoscaling.enabled` (default) renders a HorizontalPodAutoscaler; the
  PodDisruptionBudget is only rendered when more than one replica can run.
- `terminationGracePeriodSeconds: 45` covers the drain.
- `preserve_host` upstreams that refuse unknown hosts need `health_host` too, or
  their probes fail (see the [upstream settings](/config/#forward-the-client-s-host-preserve-host-opt-in)).

Every values file in `deploy/helm/zion/ci/` is rendered in CI and the resulting
`zion.toml` checked with `zion doctor`.

## Rollback

Zion's config parser is fail-closed (`deny_unknown_fields`): an older binary
rejects a `zion.toml` that contains a key added by a **newer** release and exits
`2` (config category). So the **binary and its config are one unit** — roll them
back together.

- **Kubernetes / Helm:** `helm rollback <release> <revision>` reverts the chart
  (image tag **and** the ConfigMap) atomically. Do not pin only `image.tag`
  back while keeping a newer `values.yaml`.
- **Bare metal / systemd:** keep the previous `(binary, /etc/zion/zion.toml)`
  pair together. To roll back, restore both, then `systemctl restart zion`.
  Reverting only the binary onto a config that gained a new key will fail to
  boot with a `config validation failed` message naming the unknown key.

**Compatibility contract:** within a release the config schema is exact (no
unknown keys). Across releases, a config authored for version *N* may not load
on version *N−1* if it uses keys introduced in *N*.

There is a schema-version handshake, with one limit to know about. A config may
declare `schema_version` (omitted = `1`); a file that declares a version newer
than the binary supports is refused with a message that says to upgrade zion,
and `0` is refused. But the version has been `1` since the handshake was added:
keys introduced since then did not bump it, so it does not yet tell an older
binary that a config is too new. The unknown-key error above is what you get.
So still treat a downgrade as "restore the matching config too", and read the
CHANGELOG for any config or forwarded-header contract changes before upgrading
or rolling back.
