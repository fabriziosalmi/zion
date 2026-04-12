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

## Config Validation

Zion validates the entire configuration at startup and exits with code 1 on any error. Checked items:

- Server addresses are valid socket addresses
- TLS cert and key files exist on disk
- All SNI cert/key files exist
- At least one route is defined
- Every route references a known upstream
- Every `waf_profile` and `cache_profile` reference exists
- All upstream URLs are valid URIs

Run a dry validation by starting Zion and checking exit code:

```bash
ZION_CONFIG=./zion.toml ./zion && echo "Config OK"
```

## Graceful Shutdown

Zion handles `SIGINT` (Ctrl+C) and `SIGTERM`:

1. Stop accepting new connections
2. Wait up to **30 seconds** for in-flight connections to complete
3. If drain timeout expires, force exit with a warning log

This works by acquiring all semaphore permits (connection limit). When all active connections release their permits, the drain is complete.

## Certificate Renewal

With `hot_reload = true` (default), certificate renewal requires no restart:

1. Renew certificates (e.g., via certbot)
2. Write new files to the watched directory
3. Zion detects the change, debounces 2 seconds, reloads
4. New connections use new certs; in-flight connections are unaffected
