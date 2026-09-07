# Hardening

Zion applies security defaults that can be overridden via configuration.

## Response headers

Every HTTPS response includes these security headers (stored as static `HeaderValue` constants):

| Header | Value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Force HTTPS for 2 years |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Block iframe embedding |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Disable browser APIs |
| `Server` | *(removed)* | No server identification |

## Method whitelist

Only these HTTP methods are accepted. All others return `405 Method Not Allowed`:

```http
GET  POST  PUT  PATCH  DELETE  HEAD  OPTIONS
```

This blocks `TRACE` (cross-site tracing), `CONNECT` (proxy tunneling), and non-standard methods before any processing occurs.

## URI length limit

Requests with URI paths exceeding **8,192 bytes** return `414 URI Too Long`.

## Header limits

Hyper is configured with reduced header limits compared to defaults:

| Parameter | Zion | Hyper Default |
|---|---|---|
| Max header count | 64 | 100 |
| Max header buffer | 16 KB | 400 KB |

## Rate limiting

Per-IP rate limiting using `DashMap` with atomic counters:

```toml
[server]
rate_limit_rps = 100          # Max requests per IP per window
rate_limit_window_secs = 1    # Window duration
```

When `rate_limit_rps = 0` (default), rate limiting is disabled — the code returns before accessing any map. Over-limit requests return `429 Too Many Requests`.

## Timeouts

| Timeout | Duration | Purpose |
|---|---|---|
| TLS handshake | 10 seconds | Prevent TLS slowloris |
| HTTP request | 60 seconds | Kill stalled connections |
| Upstream connect | 3 seconds (configurable) | Fail fast on dead upstreams |
| Connection pool idle | 30 seconds | Reclaim unused upstream connections |

## Connection limit

Maximum concurrent connections are bounded by a `Semaphore` sized to available RAM:

```text
conn_limit = (RAM_MB / 4) * 1024 / 50    # ~50KB per TLS connection estimate
```

Clamped to 1,000–100,000. Connections beyond the limit are silently dropped at the TCP level.

## HTTP to HTTPS redirect

Port 80 serves only two purposes:

1. **ACME challenges**: `/.well-known/acme-challenge/*` is proxied to the configured upstream
2. **Everything else**: `301 Moved Permanently` redirect to `https://`

The `Host` header is validated before use in the redirect URL:
- Must be non-empty and <= 253 characters
- Must not contain `/`, `\`, `@`, newlines, or spaces

## Internal-only routes

Routes marked with `internal_only = true` are restricted to private IPs:

```text
127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 169.254.0.0/16, ::1
```

External requests receive `403 Forbidden`.

## Linux-specific options

On Linux, Zion enables additional socket options when the kernel supports them:

- `TCP_DEFER_ACCEPT`: Kernel holds connections until client sends data
- `TCP_FASTOPEN`: TFO for returning clients (requires kernel support)
- `SO_REUSEPORT`: Kernel-level connection distribution across listeners

## 0-RTT replay protection

TLS 1.3 0-RTT is enabled but gated by HTTP method. Non-idempotent methods (`POST`, `PUT`, `PATCH`, `DELETE`) on early data receive `425 Too Early` (RFC 8470). Only `GET` and `HEAD` are allowed on 0-RTT data.

See [TLS Configuration → 0-RTT Replay Protection](../config/tls.md#_0-rtt-replay-protection) for details.

## Hop-by-hop header stripping

Zion strips the following hop-by-hop headers from upstream responses before forwarding to clients (RFC 7230 §6.1):

```text
Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization,
TE, Trailer, Transfer-Encoding, Upgrade
```

## X-Forwarded-For policy (`xff_mode`)

Outbound XFF behaviour is configured at `[server]` level. The default (`append`) preserves the prior behaviour and is correct when Zion sits behind a sanitising edge (CDN/ALB) that has already vetted the inbound chain. When Zion is the **front edge**, the default is unsafe: a client can send `X-Forwarded-For: 1.2.3.4` and the leftmost entry in the chain forwarded to your upstream will be that attacker-controlled value. Downstream apps that read `XFF[0]` for ACL or audit will be tricked.

```toml
[server]
xff_mode = "rewrite"   # one of: "append" | "rewrite" | "drop"
```

| Mode | Inbound XFF | Outbound XFF | Use when |
|---|---|---|---|
| `append` (default) | preserved | inbound chain + resolved client IP appended | Zion is behind a trusted edge that already strips/normalises XFF |
| `rewrite` | dropped | single entry: the resolved client IP | Zion is the front edge — guarantees a clean one-hop chain regardless of what the client sent |
| `drop` | dropped | not emitted | Upstreams must not learn the client IP at all |

`X-Real-IP` is **always** set from the resolved client IP and never trusted from inbound headers, regardless of `xff_mode`. The "resolved client IP" is the output of `TrustedProxies::resolve_client_ip`: the rightmost X-Forwarded-For entry that is not a trusted-proxy CIDR, or the TCP peer IP when no proxies are configured.

## mTLS client certificate forwarding

When the TLS listener is configured with client-certificate verification (`client_ca_path` set, `client_auth = "required"` or `"optional"`), Zion extracts a stable identifier from the leaf peer certificate and forwards it to upstreams as:

```http
X-Client-Cert-Fingerprint: sha256:<64 hex chars>
```

The value is the SHA-256 of the leaf DER, hex-encoded with a `sha256:` prefix — Zion's pinned wire format for this header (the prefix names the algorithm so it can never be ambiguous). (nginx's `$ssl_client_fingerprint` is a similar idea but a **SHA-1** digest — do not compare the two values directly.) It is collision-resistant and stable across re-issuance only when the cert bytes themselves are stable; rotating a cert produces a new fingerprint.

Earlier Zion versions emitted `X-Client-Cert-DN`, computed as a 64-bit XOR-fold of the first 64 DER bytes. That value was advertised as a "DN" but was neither a Distinguished Name nor collision-resistant; it was **removed in v0.1.7** and replaced by `X-Client-Cert-Fingerprint` with no coexistence window. If your upstream still expects the old header, map it at the upstream side from `X-Client-Cert-Fingerprint` (note: the new value is a fingerprint, not a DN, and downstream identity mapping must be done via your roster).

### Injected request-header contract

Zion's contract for the headers it sets or strips on the way to the upstream. Anything an upstream trusts for identity is Zion-owned: any inbound copy from the client is stripped before Zion re-injects the verified value, so these cannot be forged by a client.

| Header | Direction | Meaning | Since |
|--------|-----------|---------|-------|
| `X-Forwarded-For` | set per `xff_mode` | client IP chain (see table above) | 0.1 |
| `X-Real-IP` | set (inbound never trusted) | resolved client IP | 0.1 |
| `X-Forwarded-Proto` / `X-Forwarded-Host` | set | original scheme / Host | 0.1 |
| `X-Request-ID` | set if absent, else echoed | request correlation id | 0.1 |
| `X-Client-Cert-Fingerprint` | set on mTLS routes (inbound stripped) | `sha256:<hex>` of the leaf DER | **0.1.7** (replaced `X-Client-Cert-DN`) |
| `X-Client-TLS-JA4` / `X-Client-TLS-*` | set on TLS-fingerprint routes (inbound stripped) | verified JA4 identity | 0.7.5 |
| `X-Auth-Subject` / `X-Auth-Email` | set from validated claims (inbound **always** stripped) | authenticated `sub` / `email` | requires `--features auth` |

Breaking changes to this contract are called out in the [CHANGELOG](https://github.com/fabriziosalmi/zion/blob/master/CHANGELOG.md); pin the header names you consume and re-check them on a major upgrade.

## Hot-reload

Zion applies changes to `zion.toml` and to the certificate files referenced by `[tls]` without restarting the process. An invalid config is rejected and the previous snapshot keeps serving traffic, so the only way a config edit can break production is if it is a *valid* config that does the wrong thing.

The full contract — what reloads, what is left to a restart, how to verify a reload landed — is in [Operations → Hot-reload](../deploy/hot-reload.md).

## Content-Security-Policy

Per-route CSP headers can be configured. See [Routing → Content-Security-Policy](../config/routing.md#content-security-policy-per-route).
