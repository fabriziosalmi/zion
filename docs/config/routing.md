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

## Path normalization

The request path is normalized **before** anything decides from it (RFC 3986 §6.2.2), and
the normalized form is what is routed, checked against `internal_only` / WAF / auth
profiles, used as the cache key, and sent upstream:

- `%2e%2e` and the like: percent-encodings of unreserved characters
  (`A-Z a-z 0-9 - . _ ~`) are decoded; every other escape keeps its bytes with upper-case
  hex (`%2f` → `%2F`). An encoded slash stays data, never a separator.
- Dot segments are removed, never climbing above the root (`/a/b/../c` → `/a/c`).
- Runs of `/` collapse to one (`//a///b` → `/a/b`). A trailing slash is kept.
- The query string is left exactly as written.
- A path that one pass of this does not bring to a canonical form is refused with `400`
  instead of being routed: the upstream decodes the path once more, and zion must not
  route one reading while the upstream serves another. Nothing a client writes
  correctly is affected.

Without this, `/open/../internal/x` matches `/open/{*rest}` while an upstream that
resolves `..` serves `/internal/x`, and `//admin` or `/%61dmin` slip past a `/admin` route.
Every spelling of a path now meets the same route and the same policy, on :443 and on the
plaintext :80 listener (whose ACME-challenge fallback routes on its own).

### Bytes servers disagree on

Some bytes in a path are read one way by zion and another by the upstream, so they are
refused with `400` instead of being forwarded:

| In the path | Why | Answer |
|---|---|---|
| `\`, `%5C` | Windows servers read a backslash as a separator: `/..%5C..%5Cwin.ini` | always `400` |
| `%00` | a C string ends there: `/shell.php%00.jpg` | always `400` |
| `;` | Tomcat and Jetty strip path parameters before they read the path: `/admin;x` is `/admin` to them, and `/app/..;/admin` is `/admin` | `400` unless the route sets `allow_path_params` |
| `%2F` | some upstreams decode it into a separator | `400` only where the route sets `refuse_encoded_slash` |

The query string is not affected, and neither is an encoded `;` (`%3B`), which is data.

A route whose application needs path parameters (`;jsessionid=`) sets
`allow_path_params = true`. Even then, zion matches the route a second time on the path with
the parameters stripped (`/app/admin;x/secret` → `/app/admin/secret`) and refuses the
request with `400` unless both match this same route, and with `403` when the stripped path
is one of the route's `deny_paths`. The parameters cannot carry a request into another
route's `internal_only`, auth or WAF policy:

```toml
[[route]]
path = "/shop/{*rest}"
upstream = "tomcat"
allow_path_params = true     # /shop/cart.jsp;jsessionid=… is passed on as written

[[route]]
path = "/shop/admin/{*rest}"
upstream = "tomcat"
internal_only = true         # /shop/admin;x/users and /shop/..;/shop/admin/users: 400
```

## Headers that are not passed on from clients

Some request headers tell an application or a cache where a request "really" goes or came
from. Frameworks that honour them (IIS and Symfony take the path from `X-Original-URL` /
`X-Rewrite-URL`; others take the host, scheme or prefix from the rest) can be steered behind
zion's routing, `internal_only`, WAF and auth, and a cache keyed on the real request can be
poisoned. Zion drops these from any client that is not a configured trusted proxy: by a gate
before routing on `:443`, and just before forwarding on the plaintext `:80` listener's ACME
fallback (which picks its route first and forwards on its own):

`X-Original-URL`, `X-Rewrite-URL`, `Forwarded` (zion sends `X-Forwarded-*`, never `Forwarded`),
`X-Forwarded-Server`, `X-Forwarded-Scheme`, `X-Forwarded-Prefix`, `X-Host`,
`X-HTTP-Host-Override`, `X-Original-Host`.

A peer listed in `[server] trusted_proxies` (a CDN or load balancer in front of zion) keeps
its values, as it does for `X-Forwarded-For`.

### Headers only zion may set

An upstream reads some headers as zion's word about the request. A copy sent by anyone
else, a trusted proxy included, is dropped; zion then sets the real value, or none:

| Header | What it states | Set by |
|---|---|---|
| `X-Client-Cert-Fingerprint`, `X-Client-Cert-DN` | the client certificate the TLS handshake verified | the HTTPS listener |
| `X-Client-TLS-JA4`, `X-Client-TLS-Allowlisted` | the client's TLS fingerprint and whether it is on the allowlist | the HTTPS listener |
| `X-Auth-Subject`, `X-Auth-Email` | the identity an `auth_profile` verified | the auth gate |
| `X-Zion-Mesh-Score` | the mesh's reputation for the client IP | the mesh gate |

All of these and the list above come from one table in the code
(`src/reserved_headers.rs`), and one test walks that table through the real HTTPS listener. `X-Forwarded-Host` is always overwritten with
the request's own host (the `Host` header, or the URI authority for HTTP/2), and dropped when there
is none. The upstream's `Host` is its own authority, or the client's host when the upstream
sets [`preserve_host`](/config/#forward-the-client-s-host-preserve-host-opt-in).

### Headers and cookies you strip or refuse

Three lists name request headers and cookies by name, in `[server]` for every route and in a
`[[route]]` for that route (a route's lists add to the global ones):

| Key | What it does |
|---|---|
| `strip_headers` | removes the header before the request is forwarded |
| `deny_headers` | refuses a request that carries the header, with `400` |
| `deny_cookies` | refuses a request that carries a cookie of that name, with `400` |

```toml
[server]
deny_cookies = ["CacheWarmer"]        # Mirasvit Cache Warmer, CVE-2026-45247

[[route]]
path = "/{*rest}"
upstream = "app"
strip_headers = ["X-Debug"]
deny_headers = ["X-Forwarded-Debug"]
```

Header names are compared without case and with `_` and `-` as the same character, because
a CGI or PHP upstream reads `X_Debug` as `X-Debug`. Cookie names are compared as written
(they are case-sensitive) and also percent-decoded, because PHP reads `%43acheWarmer` as
`CacheWarmer`. A name that is not a header name or a cookie name is a config error.

Some are built in, on every route, with no configuration:

| Header | Answer | Why |
|---|---|---|
| `X-Middleware-Subrequest` | stripped | Next.js marks its own middleware subrequests with it; a client that sends it skips the middleware (CVE-2025-29927) |
| `Upgrade` | stripped, except on a WebSocket handshake | zion already removes `Connection`; an upstream that acts on `Upgrade: h2c` anyway would take the connection past zion's routing |
| `HTTP2-Settings` | stripped | it only means something with an `h2c` upgrade |
| `__proto__`, `constructor` | `400` | an upstream that copies the headers into a JavaScript object pollutes its prototype |

The `:80` ACME fallback applies the same lists before it forwards.

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
path = "/status"
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
path = "/internal/{*rest}"
upstream = "internal"
internal_only = true
```

When `internal_only = true`, requests from non-private IPs receive `403 Forbidden`. Private IPs include:

- `127.0.0.0/8` (loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
- `169.254.0.0/16` (link-local)
- `::1` (IPv6 loopback)

## Request restrictions (per-route)

Three keys narrow what a route accepts. None needs a WAF profile, and a route that sets none of
them is unchanged.

```toml
[[route]]
path = "/wp-json/{*rest}"
upstream = "wordpress"
methods = ["GET", "POST"]
content_types = ["application/json"]
deny_paths = ["/wp-json/batch/{*rest}"]
```

| Key | Refuses | With |
|---|---|---|
| `deny_paths` | a request whose path matches one of these patterns | `403 Forbidden` |
| `methods` | a method not in the list | `405 Method Not Allowed`, with an `Allow` header |
| `content_types` | a request body whose `Content-Type` is not one of these media types | `415 Unsupported Media Type` |

- **`deny_paths`** uses the `path` syntax above, written in full from the root: `"/wp-json/batch/{*rest}"`
  denies `/wp-json/batch`, `/wp-json/batch/` and everything under it. The pattern is matched
  against the normalized path, like the route itself.
- **`methods`** lists methods in capitals, from those zion accepts at all: `GET`, `HEAD`, `POST`,
  `PUT`, `PATCH`, `DELETE`, `OPTIONS`. `GET` brings `HEAD` with it (RFC 9110 §9.3.2). A CORS
  preflight is answered before this check, so a route with `cors` does not need to list `OPTIONS`.
- **`content_types`** lists bare media types (`"application/json"`, no parameters, no wildcards).
  The match ignores case and parameters (`application/json; charset=utf-8` is
  `application/json`), and `application/jsonp` is not `application/json`. Only a request that
  carries a body is checked: a `GET`, or a `POST` with an empty body, needs no `Content-Type`. A
  body with no `Content-Type` is refused.

The checks run in that order, once the route is known: after CORS and `internal_only`, before an
upstream is chosen, authentication and the WAF. A refused request costs no upstream work.
An empty list (`methods = []`) is a config error, as is an unknown method or a malformed media
type or pattern. The keys apply on reload, to the next request.

## Request body (per-route)

Two keys bound the request body on a route without a WAF. A route that sets neither streams the
body to the upstream as it arrives, at any size.

```toml
[[route]]
path = "/upload/{*rest}"
upstream = "app"
max_body_mb = 50
require_content_length = true
```

- **`max_body_mb`** caps the body. A body that declares a larger length (`Content-Length`) is
  answered `413 Payload Too Large` before any of it is read, and nothing reaches the upstream. A
  body without a declared length (chunked HTTP/1.1, HTTP/2 or HTTP/3 without `Content-Length`) is
  streamed to the upstream and counted: at the byte that goes past the cap, zion aborts the
  request to the upstream, which sees a broken body and never a short one that looks complete,
  and answers `413`. On a route with a WAF, the cap is the WAF's (`max_body_mb` with `waf = true`,
  or the profile's own); `max_body_mb` next to a `waf_profile` is a config error.
- **`require_content_length`** sends every body to the upstream with `Content-Length`, never
  chunked. A body without a declared length is read whole first, within `max_body_mb` (10 MB when
  the route sets none) and 60 seconds, then forwarded with the length it turned out to have:
  `413` past the cap, `408` past the time. A body that declares its length is streamed as it is.
  It is for an upstream that mishandles chunked bodies. Each body it reads is held in memory, up to
  the cap, while the request lasts.

A client that is still sending when zion answers `413` gets the answer. Over HTTP/1.1, after
answering a request whose body it did not read to the end, zion reads and drops what the client
still sends until the client closes, for at most 10 seconds (2 seconds without a byte), then
closes the connection; nginx calls this a lingering close. Over HTTP/2 only that request's stream
is closed.

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

If validation fails, Zion prints all errors and exits with code `2` (the
config-error category — see [Exit codes](/deploy/#exit-codes)).
