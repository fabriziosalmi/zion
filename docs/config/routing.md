# Routing

Zion routes requests using a radix tree (via the [`matchit`](https://crates.io/crates/matchit) crate -- the same engine used by Axum). Route lookup is ~15ns regardless of route count.

## Route patterns

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

### Path syntax

| Pattern | Matches | Example |
|---|---|---|
| `/exact` | Exact path only | `/metrics` |
| `/prefix/{*rest}` | Prefix + any suffix | `/api/{*rest}` matches `/api/v1/users` |
| `/{param}` | Single path segment | `/{id}` matches `/123` but not `/a/b` |

More specific routes take priority over wildcards. `/api/v1/events/stream` matches before `/api/{*rest}`.

## Host-based routing (virtual hosting)

Bind a route to one or more `hosts` to serve different backends for different domains on the same listener — the `Host` header (HTTP/1) or `:authority` (HTTP/2) selects the route. A route **without** `hosts` is *shared*: it matches every host and acts as a fallback.

```toml
# api.example.com → API backend
[[route]]
hosts = ["api.example.com"]
path = "/{*rest}"
upstream = "api"

# app.example.com and any *.example.com subdomain → frontend
[[route]]
hosts = ["app.example.com", "*.example.com"]
path = "/{*rest}"
upstream = "frontend"

# Shared: no `hosts`, reachable on every domain
[[route]]
path = "/healthz"
upstream = "api"
internal_only = true
```

The same path now serves different backends per host — `api.example.com/` and `app.example.com/` route independently, which a path-only router cannot express.

### Matching precedence

For a request authority, Zion resolves in this order:

1. **Exact host** — matches a route bound to exactly that host.
2. **Wildcard** — `*.example.com` matches any subdomain (`foo.example.com`, `a.b.example.com`) but **not** the apex `example.com`. The most specific wildcard wins (`*.api.example.com` before `*.example.com`).
3. **Shared** — routes with no `hosts`; also the fallback when the selected host tree has no matching path.

An exact host beats a wildcard, and a matched host never falls through to *another* host's routes — only to the shared layer.

### Host normalization

Authorities are normalized before matching: lowercased, port stripped (`api.example.com:8443` → `api.example.com`), and a trailing FQDN dot removed. Config `hosts` entries must be canonical bare hostnames — no scheme, path, port, or trailing dot (uppercase is folded). Only leading-label wildcards (`*.example.com`) are supported.

### Relationship to TLS SNI

`hosts` (L7 routing) is independent of [`[[tls.sni]]`](./tls) (which certificate to present). SNI picks the cert during the TLS handshake; `hosts` picks the backend from the decrypted request. A direct-IP or unknown-SNI client still routes via `hosts` (or the shared layer) using the `Host` header.

### Performance

Host routing is **opt-in and zero-cost when unused**: with no `hosts` anywhere, lookups skip authority extraction and behave exactly as the path-only router. When active, a lookup adds one hash-map probe plus authority normalization, and the thread-local route cache is keyed on `(host, path)` so different domains never share a cache slot.

## Route modes

| Mode | Behavior |
|---|---|
| `standard` | Standard reverse proxy with connection pooling |
| `sse_stream` | Adds `Cache-Control: no-cache` and `X-Accel-Buffering: no` to response |
| `static_cache` | Serves from in-memory cache on hit; fetches and caches on miss |
| `static` | Serves files from disk under `serve_dir` (no upstream) behind a hardened path-safety core; GET/HEAD only. Emits a weak `ETag` + `Last-Modified` and answers `If-None-Match` / `If-Modified-Since` with **304 Not Modified**; supports byte-range requests (`206 Partial Content` + `Accept-Ranges: bytes`, `416` when unsatisfiable); files above 64 MiB stream frame-by-frame with bounded memory (no size limit). `spa_fallback = true` serves `index.html` for an unmatched path; `precompressed = true` serves a `.br`/`.gz` sidecar (Brotli preferred) when the client's `Accept-Encoding` allows it, with `Vary: Accept-Encoding`. See [ADR-0015](/adr/0015-route-mode-static) / [ADR-0019](/adr/0019-static-conditional-get) / [ADR-0020](/adr/0020-static-range-requests) / [ADR-0021](/adr/0021-static-file-streaming) / [ADR-0022](/adr/0022-static-precompressed-sidecars). |
| `websocket` | Explicit WebSocket mode (also auto-detected via `Upgrade: websocket` header on any route) |

## Upstream resolution

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

## Internal-only routes

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

## Content-Security-Policy (per-route)

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

### When to use

- **Admin panels / internal tools**: Lock down with a strict CSP (`default-src 'self'`)
- **SPA frontends**: Leave unset and let the frontend's own CSP pass through
- **APIs**: Usually not needed (no HTML rendering)

## Startup validation

Zion validates all routes at boot:

- Every route must reference a defined upstream
- Every `waf_profile` reference must point to an existing `[waf_profile.<name>]`
- Every `cache_profile` reference must point to an existing `[cache_profile.<name>]`
- All upstream URLs must be valid URIs
- Path patterns must be valid radix tree patterns
- Every `hosts` entry must be a canonical bare hostname or a `*.<domain>` wildcard

If validation fails, Zion prints all errors and exits with code 1.
