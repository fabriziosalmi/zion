# HTTP/3 (QUIC)

::: tip Feature-gated
Build with `--features http3` to enable HTTP/3 QUIC support.
:::

Zion supports HTTP/3 over QUIC alongside HTTP/1.1 and HTTP/2 on the same port. QUIC provides zero-RTT connection establishment, built-in encryption (TLS 1.3), and connection migration for mobile clients.

## How It Works

When `--features http3` is enabled:

1. Zion binds a **UDP socket** on the same HTTPS port (default `:443`)
2. QUIC connections are handled via the `quinn` library
3. HTTP/3 semantics via the `h3` library
4. The `Alt-Svc` header is automatically injected on HTTP/1.1 and HTTP/2 responses to advertise HTTP/3 availability

```
Alt-Svc: h3=":443"; ma=86400
```

Clients that support HTTP/3 (Chrome, Firefox, Safari, curl 8+) will upgrade automatically.

## Build

```bash
cargo build --release --features http3

# Combined with other features:
cargo build --release --features "http3,acme,auth"
```

## Architecture

```
Client (UDP)  ─── QUIC ───  Zion (:443 UDP)  ─── HTTP/1.1 ───  Upstream
Client (TCP)  ─── TLS  ───  Zion (:443 TCP)  ─── HTTP/1.1 ───  Upstream
```

Both TCP (HTTP/1.1 + HTTP/2) and UDP (HTTP/3) listeners share:
- The same TLS certificate
- The same routing table
- The same WAF pipeline
- The same security headers

## TLS Certificate Hot-Reload

When certificates are hot-reloaded, both the TCP TLS acceptor **and** the QUIC configuration are updated simultaneously via a `tokio::sync::watch` channel. Zero downtime for both protocols.

## Limitations

- HTTP/3 uses the same upstream connection pool (HTTP/1.1 to backend)
- WebSocket upgrade is not supported over HTTP/3 (protocol limitation)
- `io_uring` single-shot accept applies to TCP only (QUIC uses standard UDP recv)

## Dependencies

When `http3` feature is enabled:

| Crate | Purpose |
|-------|---------|
| `quinn` | QUIC transport implementation |
| `h3` | HTTP/3 protocol semantics |
| `h3-quinn` | Glue between h3 and quinn |

## Verification

```bash
# Check Alt-Svc header (HTTP/2)
curl -sI https://localhost:443 | grep alt-svc

# Test with HTTP/3 directly (curl 8+)
curl --http3-only https://localhost:443/healthz
```
