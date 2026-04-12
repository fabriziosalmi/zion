# Quick Start

## Prerequisites

- Rust 1.75+ (`rustup install stable`)
- A TLS certificate and key (PEM format)
- An upstream HTTP service to proxy to

## Build from Source

```bash
git clone https://github.com/fabriziosalmi/zion.git
cd zion
cargo build --release
```

The binary is at `target/release/zion` (~5 MB).

## Minimal Configuration

Create `zion.toml`:

```toml
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"
key_path = "/etc/ssl/zion/tls.key"

[upstreams]
backend = "http://127.0.0.1:8000"

[[route]]
path = "/api/{*rest}"
upstream = "backend"
waf = true

[[route]]
path = "/{*rest}"
upstream = "backend"
```

## Generate a Self-Signed Certificate (dev only)

```bash
mkdir -p /etc/ssl/zion
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /etc/ssl/zion/tls.key \
  -out /etc/ssl/zion/tls.crt \
  -days 365 -subj "/CN=localhost"
```

## Run

```bash
# Default config path: ./zion.toml
./target/release/zion

# Custom config path
ZION_CONFIG=/etc/zion/zion.toml ./target/release/zion
```

On startup, Zion prints a platform detection matrix and route table:

```
ZION EDGE GATEWAY -- initializing...
  ┌────────────────────────────────────────────┐
  │ PLATFORM DETECTION                         │
  ├────────────────────────────────────────────┤
  │ OS:    linux      Arch: x86_64             │
  │ CPUs:  4          RAM:  8192 MB            │
  └────────────────────────────────────────────┘
  route /api/{*rest} -> backend [waf=legacy, cache=off]
  route /{*rest} -> backend [waf=off, cache=off]
ZION ONLINE.
```

## Verify

```bash
# Health check
curl -k https://localhost/healthz
# => ok

# Readiness
curl -k https://localhost/readyz
# => ready

# Proxy a request
curl -k https://localhost/api/v1/users

# HTTP -> HTTPS redirect
curl -I http://localhost/
# => 301 Moved Permanently, Location: https://...
```

## Next Steps

- [Configuration Reference](/config/) -- all TOML sections
- [WAF Configuration](/config/waf) -- profiles and tuning
- [TLS & SNI](/config/tls) -- multi-domain, hot-reload
- [Deployment](/deploy/) -- systemd, Docker
