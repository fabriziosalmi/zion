# Caching

Zion has a built-in **shared response cache** — a two-level (thread-local L1 +
shared L2), in-memory store that serves cacheable upstream responses without a
round-trip. It is **per-route**, opt-in, and implements the parts of RFC 9111
(HTTP Caching) and RFC 9110 (Conditional Requests) that a correct shared cache
must — so it never serves a stale, wrong-variant, or cross-user response.

## Enabling it

Caching is enabled on a route by setting its mode to `static_cache` and pointing
it at a `[cache_profile]`:

```toml
[cache_profile.assets]
mode = "memory"          # in-memory store (the only mode today)
max_entries = 10000      # LRU cap; oldest evicted past this
ttl_seconds = 31536000   # freshness ceiling (see Freshness below)

[[route]]
path = "/static/{*rest}"
upstream = "frontend"
mode = "static_cache"
cache_profile = "assets"
```

A `static_cache` route with no explicit profile uses a conservative **1-hour**
default TTL (never a 1-year freeze).

## What gets cached

A response is stored only if **all** of these hold (otherwise it streams through
uncached, marked `X-Zion-Cache: BYPASS`):

| Condition | Rule |
|---|---|
| Method | **`GET` only.** HEAD/POST/etc. bypass — the key is method-agnostic, so caching a non-GET body under it would poison a later GET. |
| Status | **`200 OK` only.** |
| Response `Cache-Control` | Not `private`, `no-store`, or `no-cache` (RFC 9111 §3.2 / §5.2.2). |
| Authenticated request (§3.5) | A response to a request carrying `Authorization` is stored **only** if the origin explicitly opts in with `public`, `s-maxage`, or `must-revalidate` — otherwise one user's response could be served to another. |
| `Vary` | Absent, or **solely `Accept-Encoding`** (which is folded into the key). Any other varied header (`Accept`, `Cookie`, `Accept-Language`, `User-Agent`, `*`) → not cached, since the key can't distinguish those variants (§4.1). |
| Freshness | A positive effective TTL (see below); an object that arrives already older than its lifetime isn't stored. |

## Cache key

The key is the **full path + query** plus the **canonical `Accept-Encoding` set**:

- `/a?user=alice` and `/a?user=bob` never share an entry (query is part of the key).
- A `gzip`-accepting client and an `identity`-only client get **separate** entries,
  so a client is never served a coding it can't decode (RFC 9111 §4.1). The
  Accept-Encoding set is lowercased, `q=0` dropped, deduplicated and sorted, so
  header ordering doesn't fragment the cache.

## Freshness

The freshness lifetime is **origin-driven, clamped to the profile**:

1. The origin's `s-maxage` (shared-cache directive) wins, else `max-age`.
2. That value is capped by the profile's `ttl_seconds`.
3. If the origin gives neither, the profile `ttl_seconds` applies.

Every hit carries an **`Age`** header (RFC 9111 §4.2.3) — seeded from the upstream
`Age` at insert plus time lived in zion's cache — and a `Cache-Control: max-age`
so downstream caches compute the same expiry.

## Origin-side revalidation (RFC 9111 §4.3)

A stale entry is **revalidated**, not blindly re-fetched. When a stored entry is
past its freshness and carries a validator, zion sends a **conditional GET** to
the origin (`If-None-Match` from the stored `ETag`, `If-Modified-Since` from
`Last-Modified`):

- **`304 Not Modified`** → the stored entry is still good: zion revives its
  freshness in place and serves the **cached body**, marked
  `X-Zion-Cache: REVALIDATED` — no re-download. `zion_cache_revalidations`
  counts these.
- **`200 OK`** → the content changed: the new response replaces the stale entry
  and is served + cached as a normal fetch.
- **Origin error** (unreachable / 5xx during revalidation) → **stale-if-error**
  (§4.2.4): zion serves the stale body (`X-Zion-Cache: STALE`) rather than
  failing, so a flapping origin doesn't take cached content down.

A stale entry with **no validator** can't be revalidated, so it is re-fetched in
full (a normal miss). The stale body is kept in cache until it is revalidated or
evicted by capacity — it is never served without one of the checks above.

## Request `Cache-Control` (RFC 9111 §5.2.1)

The client can steer the cache per request:

| Directive | Effect |
|---|---|
| `no-cache` / `max-age=0` | Don't serve a stored response — fetch fresh from the origin (the fresh response is still cacheable). |
| `no-store` | Bypass the cache entirely — don't serve from it and don't store the response. |
| `only-if-cached` | Serve from cache if present, else **`504 Gateway Timeout`** — never contact the origin (§5.2.1.7). |

## Conditional requests → `304` (RFC 9110 §13)

The cache preserves each entry's `ETag` and `Last-Modified`. On a fresh hit:

- **`If-None-Match`** is matched against the stored `ETag` (weak comparison; a
  comma-list and `*` are supported);
- failing that, **`If-Modified-Since`** is matched against the stored
  `Last-Modified`.

A match returns a bodyless **`304 Not Modified`** with the validators and
freshness — saving the transfer on the common browser-revalidation path.

```console
$ curl -I -H 'If-None-Match: "v1-abc"' https://host/static/app.js
HTTP/2 304
etag: "v1-abc"
x-zion-cache: HIT
```

## Observability

- **`X-Zion-Cache`** response header on every cacheable route: `HIT` (served from
  cache), `MISS` (fetched + stored), `BYPASS` (not cacheable / `no-store`).
- **Metrics** (`/metrics`): `zion_cache_hits` / `zion_cache_misses`.
- **Purge** (internal-IP gated): `POST /_zion/cache/purge` clears everything;
  `POST /_zion/cache/purge?prefix=/static/` clears one path prefix (variants
  share the prefix, so this clears all encodings of a path). Returns
  `{"purged":N,"scope":...}`.

```console
$ curl -sX POST 'http://127.0.0.1/_zion/cache/purge?prefix=/static/app.js'
{"purged":2,"scope":"/static/app.js"}
```

## RFC conformance at a glance

| Behaviour | RFC | Status |
|---|---|---|
| `private` / `no-store` / `no-cache` response directives | 9111 §3.2, §5.2.2 | Yes |
| Authenticated-request storage opt-in | 9111 §3.5 | Yes |
| `Vary` matching (Accept-Encoding) | 9111 §4.1 | Yes (Accept-Encoding; others → uncached) |
| Origin-driven freshness (`max-age` / `s-maxage`) + `Age` | 9111 §4.2 | Yes |
| Request `Cache-Control` (no-cache/no-store/max-age=0/only-if-cached) | 9111 §5.2.1 | Yes |
| Client conditional → `304` (If-None-Match / If-Modified-Since) | 9110 §13 | Yes |
| Origin-side revalidation (stale → conditional GET → 304) | 9111 §4.3 | Yes (`REVALIDATED`; stale-if-error §4.2.4) |

See also [Hot-reload](/deploy/hot-reload) (cache survives config reloads) and the
[two-level-cache ADR](/adr/0003-two-level-cache-with-generation).
