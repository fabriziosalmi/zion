# CORS

CORS is disabled by default and is configured **per route** — there is no
top-level `[cors]` table (the config parser rejects unknown top-level keys, so a
`[cors]` section fails to load). Add a `cors = { … }` inline table to any
`[[route]]` with at least one origin.

## Configuration

```toml
[[route]]
path     = "/api/{*rest}"
upstream = "backend"
cors     = { allowed_origins = ["https://app.example.com", "https://admin.example.com"], allowed_headers = ["Content-Type", "Authorization", "X-Requested-With"], max_age = 86400 }
```

### Wildcard Origin

```toml
[[route]]
path     = "/public/{*rest}"
upstream = "backend"
cors     = { allowed_origins = ["*"] }
```

When `*` is present, `Access-Control-Allow-Origin: *` is returned for all requests. This is suitable for public APIs but not recommended for authenticated endpoints.

## Parameters

| Key | Type | Default | Description |
|---|---|---|---|
| `allowed_origins` | string[] | `[]` (disabled) | Origins permitted to make cross-origin requests |
| `allowed_headers` | string[] | `["Content-Type", "Authorization", "X-Requested-With"]` | Headers allowed in requests |
| `max_age` | u64 | `86400` (24 hours) | Seconds the browser may cache pre-flight results |

## Allowed Methods

The following methods are always permitted when CORS is enabled:

```
GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
```

This list is not configurable -- it matches Zion's method whitelist.

## Pre-flight Handling

When CORS is enabled and the request is `OPTIONS` with a matching `Origin` header:

1. Zion responds immediately with `204 No Content`
2. Response includes `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, and `Access-Control-Max-Age`
3. Security headers (HSTS, X-Frame-Options, etc.) are also injected
4. The request is **not** forwarded to the upstream

For non-OPTIONS requests with a matching origin, Zion adds `Access-Control-Allow-Origin` to the proxied response.

## Origin Matching

- Origins are compared as exact string matches against the `Origin` request header
- If the origin is not in the allowed list, no CORS headers are added (browser enforces the restriction)
- If `allowed_origins` is empty, CORS processing is completely skipped (zero overhead)

## Performance

CORS headers are pre-compiled at boot into `HeaderValue` objects. Per-request cost is limited to:

- One `Origin` header extraction
- One string comparison per allowed origin
- Zero-allocation header insertion (pre-compiled values)
