# Hardening

Zion applies multiple layers of security by default, with zero measurable latency impact.

## Response Headers

Every HTTPS response includes these security headers (pre-compiled as static constants):

| Header | Value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Force HTTPS for 2 years |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Block iframe embedding |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Disable browser APIs |
| `Server` | *(removed)* | Zero information leakage |

Cost: ~25ns total (5 pre-compiled header insertions + 1 removal).

## Method Whitelist

Only these HTTP methods are accepted. All others return `405 Method Not Allowed`:

```
GET  POST  PUT  PATCH  DELETE  HEAD  OPTIONS
```

This blocks `TRACE` (cross-site tracing), `CONNECT` (proxy tunneling), and non-standard methods before any processing occurs.

## URI Length Limit

Requests with URI paths exceeding **8,192 bytes** return `414 URI Too Long`. This prevents:

- Buffer overflow probes
- Log pollution with oversized URIs
- Memory exhaustion from pathological paths

## Header Limits

Hyper is configured with tightened header limits:

| Parameter | Zion | Hyper Default |
|---|---|---|
| Max header count | 64 | 100 |
| Max header buffer | 32 KB | 400 KB |

This prevents header bomb attacks that exhaust memory by sending hundreds of large headers.

## Rate Limiting

Per-IP rate limiting using a lock-free `DashMap`:

```toml
[server]
rate_limit_rps = 100          # Max requests per IP per window
rate_limit_window_secs = 1    # Window duration
```

When `rate_limit_rps = 0` (default), rate limiting is completely disabled with zero overhead (early return before any map access). Over-limit requests return `429 Too Many Requests`.

## Timeouts

| Timeout | Duration | Purpose |
|---|---|---|
| TLS handshake | 10 seconds | Prevent TLS slowloris |
| HTTP request | 60 seconds | Kill stalled connections |
| Upstream connect | 3 seconds (configurable) | Fail fast on dead upstreams |
| Connection pool idle | 30 seconds | Reclaim unused upstream connections |

## Connection Limit

Maximum concurrent connections are bounded by a `Semaphore` sized to available RAM:

```
conn_limit = (RAM_MB / 4) * 1024 / 50    # ~50KB per TLS connection
```

Clamped to 1,000 - 100,000. Connections beyond the limit are silently dropped at the TCP level.

## HTTP to HTTPS Redirect

Port 80 serves only two purposes:

1. **ACME challenges**: `/.well-known/acme-challenge/*` is proxied to the configured upstream
2. **Everything else**: `301 Moved Permanently` redirect to `https://`

The `Host` header is validated before use in the redirect URL to prevent header injection:
- Must be non-empty and <= 253 characters
- Must not contain `/`, `\`, `@`, newlines, or spaces

## Internal-Only Routes

Routes marked with `internal_only = true` are restricted to private IPs:

```
127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 169.254.0.0/16, ::1
```

External requests receive `403 Forbidden`.

## Linux-Specific Hardening

On Linux, Zion enables additional kernel-level protections:

- `TCP_DEFER_ACCEPT`: Kernel holds connections until client sends data (scanner/probe protection)
- `TCP_FASTOPEN`: 0-RTT TCP for returning clients
- `SO_REUSEPORT`: Kernel-level connection distribution across listeners

## 0-RTT Replay Protection

TLS 1.3 0-RTT is enabled but gated by HTTP method. Non-idempotent methods (`POST`, `PUT`, `PATCH`, `DELETE`) on early data receive `425 Too Early` (RFC 8470). Only `GET` and `HEAD` are allowed on 0-RTT data.

See [TLS Configuration → 0-RTT Replay Protection](../config/tls.md#_0-rtt-replay-protection) for details.

## Hop-by-Hop Header Stripping

Zion strips the following hop-by-hop headers from upstream responses before forwarding to clients (RFC 7230 §6.1):

```
Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization,
TE, Trailer, Transfer-Encoding, Upgrade
```

This prevents information leakage about the internal proxy chain.

## Content-Security-Policy

Per-route CSP headers can be configured to enforce browser-side content restrictions. See [Routing → Content-Security-Policy](../config/routing.md#content-security-policy-per-route).
