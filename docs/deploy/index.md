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

1. Stop accepting new connections
2. Wait up to **30 seconds** for in-flight connections to complete
3. If drain timeout expires, force exit with a warning log

This works by acquiring all semaphore permits (connection limit). When all active connections release their permits, the drain is complete.

**Panics bypass the drain.** Release builds compile with `panic = "abort"`, so a
reachable panic anywhere (request/WAF/proxy/reload path, or unsafe FFI)
`SIGABRT`s the whole process immediately — the 30 s drain does **not** run and
every in-flight connection is severed. This is a deliberate trade-off (the code
holds a no-reachable-panic doctrine, so a panic signals a bug, not expected
load): keep Zion under a supervisor that restarts on non-zero/abnormal exit
(systemd `Restart=on-failure`, Kubernetes `restartPolicy`), and rely on multiple
replicas + a load balancer to absorb the loss of one instance.

## Certificate renewal

With `hot_reload = true` (default), certificate renewal requires no restart:

1. Renew certificates (e.g., via certbot)
2. Write new files to the watched directory
3. Zion detects the change, debounces 2 seconds, reloads
4. New connections use new certs; in-flight connections are unaffected

## Scaling & limits

**Per-node connection ceiling.** The global concurrent-connection limit is
derived from RAM (25% of RAM ÷ 256 KB per connection) but **hard-capped at
100,000** per node. This is a deliberate design limit, not just a RAM guard: on
a large box the formula would allow far more, but the admission semaphore caps
at 100k and the 100,001st concurrent connection is shed. Raise it only by
changing the clamp in `compute_conn_limit` and rebuilding.

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
on version *N−1* if it uses keys introduced in *N*. There is no schema-version
handshake yet, so treat a downgrade as "restore the matching config too", and
read the CHANGELOG for any config or forwarded-header contract changes before
upgrading or rolling back.
