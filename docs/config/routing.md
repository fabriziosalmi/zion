# Routing

Zion routes requests using a radix tree (via the [`matchit`](https://crates.io/crates/matchit) crate -- the same engine used by Axum). Route lookup is ~15ns regardless of route count.

## Route Patterns

Routes are defined as `[[route]]` entries in `zion.toml`. Order does not matter -- the radix tree handles priority automatically.

```toml
[[route]]
path = "/api/v1/events/stream"
upstream = "api"
mode = "sse_stream"

[[route]]
path = "/api/{*rest}"
upstream = "api"
waf_profile = "strict"

[[route]]
path = "/_next/static/{*rest}"
upstream = "frontend"
cache_profile = "immutable"

[[route]]
path = "/{*rest}"
upstream = "frontend"
```

### Path Syntax

| Pattern | Matches | Example |
|---|---|---|
| `/exact` | Exact path only | `/metrics` |
| `/prefix/{*rest}` | Prefix + any suffix | `/api/{*rest}` matches `/api/v1/users` |
| `/{param}` | Single path segment | `/{id}` matches `/123` but not `/a/b` |

More specific routes take priority over wildcards. `/api/v1/events/stream` matches before `/api/{*rest}`.

## Route Modes

| Mode | Behavior |
|---|---|
| `standard` | Standard reverse proxy with connection pooling |
| `sse_stream` | Adds `Cache-Control: no-cache` and `X-Accel-Buffering: no` to response |
| `static_cache` | Serves from in-memory cache on hit; fetches and caches on miss |
| `websocket` | Explicit WebSocket mode (also auto-detected via `Upgrade: websocket` header on any route) |

## Upstream Resolution

Routes reference upstreams by name. Two formats are supported:

```toml
# Named upstream (recommended) -- with connection tuning
[upstream.api]
url = "http://127.0.0.1:8000"
connect_timeout_ms = 3000
keepalive = 64

# Legacy flat format -- URL only
[upstreams]
api = "http://127.0.0.1:8000"
```

If both formats define the same name, the `[upstream.<name>]` format takes precedence.

At startup, all upstream URLs are pre-parsed into `Scheme` + `Authority`. No URI parsing occurs on the hot path.

## Internal-Only Routes

```toml
[[route]]
path = "/metrics"
upstream = "internal"
internal_only = true
```

When `internal_only = true`, requests from non-private IPs receive `403 Forbidden`. Private IPs include:

- `127.0.0.0/8` (loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
- `169.254.0.0/16` (link-local)
- `::1` (IPv6 loopback)

## Content-Security-Policy (Per-Route)

You can set a per-route `Content-Security-Policy` header:

```toml
[[route]]
path = "/admin/{*rest}"
upstream = "api"
csp = "default-src 'self'; script-src 'self'"

[[route]]
path = "/{*rest}"
upstream = "frontend"
# No csp — frontend controls its own CSP via response headers
```

| Behavior | Description |
|---|---|
| `csp` set | Zion injects the `Content-Security-Policy` header, overriding any upstream CSP |
| `csp` not set | Upstream's CSP header (if any) passes through unchanged |

The CSP string is **pre-parsed** into a `HeaderValue` at startup — zero cost on the hot path (just a header clone).

### When to Use

- **Admin panels / internal tools**: Lock down with a strict CSP (`default-src 'self'`)
- **SPA frontends**: Leave unset and let the frontend's own CSP pass through
- **APIs**: Usually not needed (no HTML rendering)

## Startup Validation

Zion validates all routes at boot:

- Every route must reference a defined upstream
- Every `waf_profile` reference must point to an existing `[waf_profile.<name>]`
- Every `cache_profile` reference must point to an existing `[cache_profile.<name>]`
- All upstream URLs must be valid URIs
- Path patterns must be valid radix tree patterns

If validation fails, Zion prints all errors and exits with code 1.
