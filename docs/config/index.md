# Configuration Reference

Zion is configured via a single TOML file. Default path: `./zion.toml`. Override with `ZION_CONFIG` env var.

All configuration is validated at startup. Invalid config produces actionable error messages and exits immediately.

## Schema version

An optional top-level `schema_version` (integer) declares which config schema the
file targets:

```toml
schema_version = 1
```

It is read **before** the strict parse. If the file targets a schema **newer**
than the running binary understands, Zion exits with targeted upgrade guidance
instead of a generic "unknown field" error. Omit it (the default) and the file is read as
**schema 1**, the schema every config written before the handshake used. That is a
fixed meaning, not "whatever is current": when a later schema ships, an unversioned
file is still read as schema 1 and migrated. `0` is rejected. The current schema
version is `1`; it is bumped only when a breaking config change lands (documented
in the CHANGELOG), together with a reader for the version it replaces.

## `[server]`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen_http` | string | **required** | HTTP bind address (e.g. `"0.0.0.0:80"`) |
| `listen_https` | string | **required** | HTTPS bind address (e.g. `"0.0.0.0:443"`) |
| `rate_limit_rps` | u32 | `0` (disabled) | Max requests per IP per window |
| `rate_limit_window_secs` | u64 | `1` | Rate limit window in seconds |
| `rate_limit_max_tracked_ips` | usize | `100000` | Distinct client IPs the per-IP limiter tracks; at the cap stale entries are evicted, and if all are live a new IP is denied (fail-closed) |
| `max_connections_per_ip` | u32? | none | Per-IP concurrent-connection cap, enforced at accept (before the TLS handshake) |
| `trusted_proxies` | string[] | `[]` | CIDRs of the proxies in front of zion. Their inbound `X-Forwarded-For` is trusted for client-IP resolution, **and** their routing/host override headers (`X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, `X-Forwarded-Server/-Scheme/-Prefix`, `X-Host`, `X-HTTP-Host-Override`, `X-Original-Host`) are passed upstream instead of dropped. List only proxies you control |
| `require_route_auth` | bool | `false` | Refuse a config in which a `[[route]]` has none of `auth_profile`, `public = true` or `internal_only = true`, so a route added without an auth decision fails at load instead of serving unauthenticated |
| `internal_networks` | string[] | `[]` | CIDRs (or bare IPs) allowed to use the internal-only endpoints (`/metrics`, `/_zion/snapshot.json`, `/_zion/cache/purge`) and `internal_only` routes. Empty keeps the built-in rule: any loopback / private-range / link-local / ULA peer. That rule tests network position, not identity: behind a private-range load balancer, Kubernetes SNAT or a Docker bridge every client looks internal. Set this (and `trusted_proxies`) to name the hosts that really are. Zion warns at boot when neither is set on a non-loopback listener |
| `tcp_keepalive_secs` | u64 | `60` | Seconds of silence before the kernel probes a client connection (then every 10 s, dead after 3 unanswered), so a peer that vanished without a FIN frees its fd and connection slot in this + 30 s. `0` = off. Retuned on reload for new connections; pooled upstream sockets and WebSocket dials use 60 |
| `xff_mode` | string | `"append"` | Outbound XFF policy: `"append"`, `"rewrite"` (strip inbound, emit one trusted entry), or `"drop"` |
| `log_format` | string | `"text"` | `"text"` or `"json"` (structured) |

### `Via` and loop detection

Every request zion forwards carries `Via: <protocol> zion-XXXXXXXX` (RFC 9110 §7.6.3),
appended after any `Via` an earlier hop wrote; the protocol is the one the request
arrived over (`1.1`, `2`, …). The pseudonym is random **per process**, so two Zion tiers
in a chain (an edge in front of an origin) are different hops. A request whose `Via`
already names this process has gone round a loop, typically an upstream that points back at
zion, and is refused with **`508 Loop Detected`** before any rate limit, route lookup or
built-in endpoint (`zion_loops_detected` counts them). `Via` is not added to responses.
There is no `Max-Forwards` handling: it only applies to `TRACE`/`OPTIONS`, and `TRACE` is
refused.

## `[tls]`

| Key | Type | Default | Description |
|---|---|---|---|
| `cert_path` | string | **required** | Path to PEM certificate chain |
| `key_path` | string | **required** | Path to PEM private key |
| `hot_reload` | bool | `true` | Watch cert directory for changes |
| `min_version` | string | `"1.3"` | Minimum TLS version (`"1.2"` or `"1.3"`) |
| `alpn` | string[] | `["h2", "http/1.1"]` | ALPN protocol negotiation list |
| `sni` | SniCert[] | `[]` | Per-domain certificate mappings |
| `acme` | table | none | Automatic HTTPS via Let's Encrypt — see [ACME](./acme) |
| `client_ca_path` | string? | none | CA bundle used to verify client certs (mTLS) |
| `client_auth` | string | `"none"` | mTLS client-auth mode (`"none"` disables mTLS) |

## `[upstream.<name>]`

| Key | Type | Default | Description |
|---|---|---|---|
| `url` | string | `url` **or** `urls` required | Single upstream URL (e.g. `"http://127.0.0.1:8000"`). An upstream with neither is a load-time error. If both are written they are merged, `urls` first then `url` |
| `urls` | string[] | `[]` | Multiple upstream URLs (latency-routed); use instead of `url` |
| `connect_timeout_ms` | u64 | `3000` | TCP connect deadline in milliseconds, applied to the connector of the client that serves this upstream: a black-holed member (packets dropped, no RST) is abandoned after this long and the next HA member is tried. `0` = none. Covers the TCP connect only; the TLS handshake and the response are bounded by the 30 s request timeout |
| `keepalive` | usize | `64` | Max idle keepalive connections |
| `tls` | bool | `false` | Use HTTPS to connect to upstream |
| `client_cert_path` / `client_key_path` | string? | none | Client cert + key for mTLS from Zion to the upstream |

Legacy format `[upstreams]` (flat key-value map of name to URL) is also supported.

### Pools: load balancing and outlier detection

An upstream with several endpoints (`urls = [...]`) assigns each request to a member with
`load_balancing` (default `"p2c"`, or `"lowest_latency"`, the behaviour before 0.9.4):

- **`p2c`** (power of two choices): two members are drawn at random and the request goes to the
  one with the lower `(in-flight requests + 1) × peak-EWMA latency`. The latency is measured on
  **real requests** (time to response headers) and rises at once on a slow response but is
  forgotten slowly. Load spreads in proportion to speed, a busy member is never piled on, and a
  member that just got slower stops receiving most traffic within a few responses instead of
  after the next 30 s probe. Members that are down, in gray failure (probe latency over 2 s) or
  ejected are skipped unless that would leave none (the pool still answers rather than 503).
- **`lowest_latency`**: every request to the member with the lowest *probe* latency (refreshed
  every 30 s), as before. It sends everything to one member until the next probe.

```toml
[upstream.api]
urls = ["http://10.0.0.5:8000", "http://10.0.0.6:8000", "http://10.0.0.7:8000"]
outlier_detection = { error_rate_pct = 50, min_requests = 20, window_secs = 10, eject_secs = 30, max_ejected_pct = 50 }
```

**`outlier_detection`** (opt-in, pools only) ejects a member whose own failure rate over a sliding
window is at or above `error_rate_pct` (with at least `min_requests` in it) **and** that is an
outlier: some other member must be clearly healthier. It never acts on a pool-wide outage (a
failing database behind all members is not one member's fault), and at most `max_ejected_pct` of
the pool is out at once. An ejected member is out for `eject_secs`, multiplied by its consecutive
ejections (up to 10x), then rejoins. A failure is a `502`, `503` or `504` or a transport error.
Metrics: `zion_upstream_inflight`, `zion_upstream_peak_ewma_seconds`, `zion_upstream_ejected`,
`zion_upstream_ejections_total` (per member). A URL that belongs to several pools uses the first
route's `outlier_detection`.

### Circuit breaker (`circuit_breaker`, opt-in)

```toml
[upstream.api]
url = "http://10.0.0.5:8000"
circuit_breaker = { error_rate_pct = 50, min_requests = 20, window_secs = 10, open_secs = 30 }
```

The health prober notices a dead upstream on its own schedule (every 30 s while healthy);
until it does, every request to a failing route waits for the origin and then fails. With
`circuit_breaker`, zion watches the outcomes of **real requests** over a sliding window and,
when at least `error_rate_pct` % of the last `window_secs` seconds' requests failed (and
there were at least `min_requests` of them), **opens the circuit**: for `open_secs` seconds
requests are answered `503` at once with `Retry-After` and `X-Zion-Circuit: open`, and the
upstream is left alone. Then **one** probe request is let through; its success closes the
circuit, its failure re-opens it. Values shown are the defaults.

- A failure is a `502`, `503` or `504` (what a refused connection, a timeout or an overloaded
  origin become). A `500` is the application's own error on one endpoint, and 4xx are the
  client's: neither counts.
- It applies to a route whose upstream has a **single** endpoint. A pool of several already
  fails over between its members.
- It is consulted after auth and the WAF, so an unauthenticated or hostile request can neither
  learn that the circuit is open nor use up its probe.
- On a **cached** route, an open circuit serves the stale copy of a requested entry (unless the
  origin forbade stale responses with `must-revalidate` / `proxy-revalidate` / `s-maxage`)
  instead of the 503, and background refreshes are not sent while it is open. A fresh hit never
  contacts the origin, so it is not affected.
- State survives a config reload; changing the thresholds on a reload starts the counters clean.
- Upstreams that name the same URL share one health entry, and so one breaker: such
  definitions must agree about it (same `circuit_breaker`, or none), otherwise the config is
  refused at load. A `[upstreams]` shorthand entry counts as "none".
- WebSocket handshakes, writes (`POST`/`PUT`/...) to a cached route, and requests that bypass the
  cache all contact the upstream, so they are gated and counted like any other request.
- Only one request is let through as the half-open probe, and only its own outcome closes or
  re-opens the circuit: a request admitted before the circuit opened that finishes late, or an
  abandoned probe answering after a replacement was issued, is ignored. Background cache
  refreshes never take the probe; they are simply not sent while the circuit is not closed.
- Metrics: `zion_upstream_circuit_open{upstream}`, `zion_upstream_circuit_trips_total{upstream}`,
  `zion_upstream_circuit_rejected_total{upstream}`.

## `[waf_profile.<name>]`

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"balanced"` | Pattern set: `"balanced"` (~100, high-precision) or `"aggressive"` (~240, broad-recall) |
| `max_body_mb` | u64 | `10` | Maximum request body size in MB |
| `max_depth` | usize | `10` | Maximum JSON nesting depth |
| `max_string_len` | usize | `1048576` | Maximum JSON string length (bytes) |
| `deny_unknown_content_types` | bool | `true` | Reject content types not in allowed list |
| `allowed_content_types` | string[] | `["application/json", "multipart/form-data"]` | Permitted content types |
| `entropy_check` | bool | `true` | Enable the Shannon-entropy gate on request bodies ≥256 bytes (restricted to JSON string values for `application/json`; whole-body for other content types) |
| `entropy_threshold` | f64 | `6.5` | Bits/byte above which a body's entropy is flagged |
| `streaming` | bool | `false` | Scan request bodies chunk-by-chunk as they stream (fail-fast on first hit) |

## `[cache_profile.<name>]`

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"memory"` | Cache mode (`"memory"` or `"none"`) |
| `max_entries` | usize | `10000` | Maximum cached entries; the LRU evicts at this cap. `0` caches nothing (every insert evicts first) — it is not "unlimited". |
| `ttl_seconds` | u64 | `3600` | Time-to-live in seconds (default: 1 hour — a header-less origin response must not be frozen for a year; RFC 9111 §4.2.2 heuristic freshness). |
| `max_object_mb` | u64 | `50` | Largest response body (MiB) the profile will store; must be >= 1. A bigger one is streamed to the client whole and never cached, so one large object cannot push thousands of small ones out. A declared `Content-Length` over the limit skips buffering altogether. `zion_cache_too_large` counts the refusals |
| `normalize_query` | bool | `false` | Sort the query parameters in the **cache key**, so `?b=2&a=1` and `?a=1&b=2` share one entry. Opt-in: only safe when the origin does not care about parameter order. Parameters with the same name keep their relative order (`?x=1&x=2` is not `?x=2&x=1`), names are compared exactly, and the upstream is always sent the query as the client wrote it |

## `[[route]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `path` | string | **required** | URL path pattern (radix tree, supports `{*rest}`) |
| `upstream` | string | **required** | Name of upstream to forward to |
| `mode` | string | `"standard"` | `standard`, `sse_stream`, `static_cache`, `websocket` |
| `internal_only` | bool | `false` | Restrict to private/loopback IPs |
| `public` | bool | `false` | Declare the route deliberately unauthenticated; the explicit opt-out under `require_route_auth`. Cannot be combined with `auth_profile` |
| `waf_profile` | string | none | Name of WAF profile to apply |
| `cache_profile` | string | none | Name of cache profile to apply |
| `waf` | bool | `false` | Legacy: enable WAF with defaults |
| `max_body_mb` | u64 | `10` | Legacy: override body limit when `waf = true` |

## `[[route]]` → `cors`

CORS is a **per-route** inline table (`cors = { … }` under `[[route]]`), not a
top-level `[cors]` section — see [CORS](./cors). Keys:

| Key | Type | Default | Description |
|---|---|---|---|
| `allowed_origins` | string[] | `[]` (disabled) | Allowed origins. `["*"]` for any. |
| `allowed_headers` | string[] | `["Content-Type", "Authorization", "X-Requested-With"]` | Additional allowed headers |
| `max_age` | u64 | `86400` | Pre-flight cache duration in seconds |

## Environment variables

| Variable | Description |
|---|---|
| `ZION_CONFIG` | Config file path (default: `./zion.toml`) |
