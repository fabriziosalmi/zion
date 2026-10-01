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
| `Vary` | Absent, or naming request headers zion can key on (see [Vary and secondary keys](#vary-and-secondary-keys)). **Not cached:** `Vary: *`, any varied credential header (`Cookie`, `Authorization`, `Proxy-Authorization`, `Set-Cookie`), more than 8 varied headers, or a variant over the per-key cap. |
| `Set-Cookie` | The response must **not** set a cookie (any `Set-Cookie` header, whatever its `Cache-Control`). It starts or changes a session, so its body is for one client; it is streamed to that client and never stored. |
| Freshness | A positive effective TTL (see below); an object that arrives already older than its lifetime isn't stored. |

## Vary and secondary keys

When the origin answers with `Vary: Accept-Language` (or `Accept`, `Origin`, `X-Foo`, …)
the response is only valid for requests that send the same value of those headers.
zion remembers, per cache key, which request headers the origin varies on, and stores
each variant under its own **secondary key** built from the values of those headers:

- Two requests share a variant only when the varied header values are **identical**
  (trimmed; repeated header lines are joined in order). `de` and `DE` are different
  variants, and an **absent** header is a different variant from an **empty** one.
- `Accept-Encoding` is part of the primary key already and is ignored here.
- **Bounded:** at most 16 variants per key (`zion_cache_vary_uncached` counts
  responses refused for that or another Vary reason; they are served, not stored), a
  varied request value over 256 bytes bypasses the cache, and the rule index is bounded
  by the route's `max_entries`.
- **Never keyed, never stored:** `Vary: *` and varied credential headers. A response
  that varies on `Cookie` is per-user; a shared cache must not keep a copy per session.
- If the origin changes the set of headers it varies on, or stops varying, the key
  follows on the next fetch; entries filed under the old key are no longer reachable.
- A background [stale-while-revalidate](#stale-while-revalidate-rfc-5861) refresh
  fetches the **same variant** it refreshes, and is discarded if the origin's `Vary`
  no longer matches the key it was filed under.

## Cache key

The key is the **full path + query** plus the **canonical `Accept-Encoding` set**:

- `/a?user=alice` and `/a?user=bob` never share an entry (query is part of the key).
- The query is part of the key **as written**, so `?b=2&a=1` and `?a=1&b=2` are two entries.
  A profile can opt in to `normalize_query = true` to sort the parameters by name in the
  key (stable, so repeated names keep their order; nothing that differs is merged). The
  upstream is still sent the original query.
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
- **Origin error** (unreachable, or a `500`/`502`/`503`/`504` answer during
  revalidation) → **stale-if-error** (§4.2.4): zion serves the stale body
  (`X-Zion-Cache: STALE`, counted in `zion_cache_stale_if_error`) rather than
  failing, so a flapping origin doesn't take cached content down.
- **When stale must not be served.** If the origin's response carried
  `must-revalidate`, `proxy-revalidate` or `s-maxage` (which has the proxy-revalidate
  meaning for a shared cache), zion never answers from that entry once it is stale:
  neither stale-if-error nor stale-while-revalidate applies, and a failing origin
  gives the client the error (RFC 9111 §4.2.4, §5.2.2).

### Invalidation by unsafe requests (RFC 9111 §4.4)

When a `POST`, `PUT`, `PATCH` or `DELETE` to a cached route gets a non-error answer
(below 400), zion drops the cached responses for that URI: the path itself, its query
variants and every `Accept-Encoding` / `Vary` variant, but not longer paths that merely
start the same (`/items/1` does not touch `/items/10` or `/items/1/child`). URIs named
in the answer's `Location` / `Content-Location` are invalidated too when they are on the
same origin (a relative reference, or the request's own host); a reference to another
host is ignored. `zion_cache_invalidations` counts the entries dropped. A failed
mutation changes nothing, so it evicts nothing. This is per zion instance: with several
replicas, each one invalidates only what it served the mutation for (use
`/_zion/cache/purge` or short TTLs for the rest).

### stale-while-revalidate (RFC 5861)

When the origin sends `Cache-Control: max-age=N, stale-while-revalidate=M`, an entry
that is at most `M` seconds past its freshness lifetime is **served immediately**
(`X-Zion-Cache: STALE-WHILE-REVALIDATE`, with its real `Age`) and refreshed in the
background, so the client does not wait for the origin round trip. `M` is capped at
24 hours. Outside the window the behaviour is the synchronous revalidation above.

- **One refresh per key**: it goes through the same singleflight as a cache fill, so
  any number of requests for a stale key cause one refresh; at most 64 run at once
  across all keys, and each is abandoned after 30 s. When the cap is reached the
  stale copy is still served and `zion_cache_swr_refresh_skipped` counts it.
- **Not on the caller's behalf**: the refresh is a `GET` to the same target with the
  same content negotiation, but without the caller's `Authorization`, `Cookie`,
  `Proxy-Authorization`, conditional or `Range` headers. It is conditional on the
  stored `ETag` / `Last-Modified`: a `304` revives the stored body, a cacheable `200`
  replaces it. Anything else leaves the stale entry in place; once outside its window
  it is no longer served stale.
- Metrics: `zion_cache_swr_served`, `zion_cache_swr_refreshes`,
  `zion_cache_swr_refresh_failures`, `zion_cache_swr_refresh_skipped`.
- A client request with `Cache-Control: no-cache` / `max-age=0` still forces a fresh
  fetch; `only-if-cached` never contacts the origin.

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
| `Vary` matching (secondary keys) | 9111 §4.1 | Yes (exact match on the varied headers, bounded; `*` and credential headers → uncached) |
| Origin-driven freshness (`max-age` / `s-maxage`) + `Age` | 9111 §4.2 | Yes |
| Request `Cache-Control` (no-cache/no-store/max-age=0/only-if-cached) | 9111 §5.2.1 | Yes |
| Client conditional → `304` (If-None-Match / If-Modified-Since) | 9110 §13 | Yes |
| Origin-side revalidation (stale → conditional GET → 304) | 9111 §4.3 | Yes (`REVALIDATED`; stale-if-error §4.2.4) |
| `stale-while-revalidate` (serve stale, refresh in the background) | 5861 §3 | Yes (`STALE-WHILE-REVALIDATE`) |

See also [Hot-reload](/deploy/hot-reload) (cache survives config reloads) and the
[two-level-cache ADR](/adr/0003-two-level-cache-with-generation).
