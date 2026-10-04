# Quick Start

## Prerequisites

- Rust 1.82+ for the default build (`rustup install stable`).
  Opt-in features `acme`, `auth`, `init`, `http3` need 1.88+ because
  of transitive dependencies that bumped their own MSRV.
- A TLS certificate and key (PEM format)
- An upstream HTTP service to proxy to

## Build from source

```bash
git clone https://github.com/fabriziosalmi/zion.git
cd zion
cargo build --release
```

The binary is at `target/release/zion` (~5 MB).

## Minimal configuration

Create `zion.toml`:

```toml
[server]
listen_http = "0.0.0.0:8080"
listen_https = "0.0.0.0:8443"

[tls]
cert_path = "certs/tls.crt"
key_path = "certs/tls.key"

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

## Generate a self-signed certificate (dev only)

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/tls.key \
  -out certs/tls.crt \
  -days 365 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"
```

(The `-addext` matters: without an extension some OpenSSL builds, LibreSSL on macOS among
them, write an X.509 v1 certificate, which zion refuses with `UnsupportedCertVersion`.)

The ports and paths above need no privileges, so the quick start runs as your own user.
For the real ports (`80` / `443`) and a system path such as `/etc/ssl/zion`, run zion as
root or, better, give the binary the one capability it needs and keep it unprivileged:

```bash
sudo setcap cap_net_bind_service=+ep ./target/release/zion
```

## Run

```bash
# Default config path: ./zion.toml
./target/release/zion

# Custom config path
ZION_CONFIG=/etc/zion/zion.toml ./target/release/zion
```

On startup, Zion prints a platform detection matrix and route table:

```text
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
curl -k https://localhost:8443/healthz
# => ok

# Readiness
curl -k https://localhost:8443/readyz
# => ready

# Proxy a request
curl -k https://localhost:8443/api/v1/users

# HTTP -> HTTPS redirect
curl -I http://localhost:8080/
# => 301 Moved Permanently, Location: https://...
```

## Next steps

- [Configuration Reference](/config/) -- all TOML sections
- [WAF Configuration](/config/waf) -- profiles and tuning
- [TLS & SNI](/config/tls) -- multi-domain, hot-reload
- [Deployment](/deploy/) -- systemd, Docker
