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
mode = "memory"          # in-memory store (the default); "none" stores nothing
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

A profile with `mode = "none"` stores nothing: a route that points at it is a plain
proxied route (every request goes to the upstream, no `X-Zion-Cache` header, and the
bulkhead and circuit breaker apply as on any uncached route), even when its mode is
`static_cache`. It is a switch for turning a route's caching off without editing the route,
for instance in a profile that an environment overrides.

## What gets cached

A response is stored only if **all** of these hold (otherwise it streams through
uncached, marked `X-Zion-Cache: BYPASS`):

| Condition | Rule |
|---|---|
| Method | **`GET` only.** HEAD/POST/etc. bypass — the key is method-agnostic, so caching a non-GET body under it would poison a later GET. |
| Status | **`200 OK` only.** |
| Response `Cache-Control` | Not `private`, `no-store`, or `no-cache` (RFC 9111 §3.2 / §5.2.2), on **any** of its lines: `Cache-Control: max-age=300` followed by `Cache-Control: private` is one list, `max-age=300, private` (RFC 9110 §5.3), which is what nginx sends for `expires 5m;` plus `add_header Cache-Control private;`. The three words are matched anywhere in the list, so an unusual spelling still refuses. |
| Authenticated request (§3.5) | A response to a request carrying `Authorization` is stored **only** if the origin explicitly opts in with a `public`, `s-maxage`, or `must-revalidate` directive (a whole directive: `x-public-ish` is not one). Otherwise one user's response could be served to another. |
| `Vary` | Absent, or naming request headers zion can key on (see [Vary and secondary keys](#vary-and-secondary-keys)). **Not cached:** `Vary: *`, any varied credential header (`Cookie`, `Authorization`, `Proxy-Authorization`, `Set-Cookie`), more than 8 varied headers, or a variant over the per-key cap. |
| `Set-Cookie` | The response must **not** set a cookie (any `Set-Cookie` header, whatever its `Cache-Control`). It starts or changes a session, so its body is for one client; it is streamed to that client and never stored. |
| Headers | At most 32 KiB of origin headers to keep ([What a hit carries](#what-a-hit-carries); each field counts as its name, its value and 32 bytes). A response with more is streamed through, marked `BYPASS`, and counted in `zion_cache_too_large`. |
| Freshness | A positive effective TTL (see below); an object that arrives already older than its lifetime isn't stored. |
| Upstream progress | The body keeps coming: a gap longer than the upstream's `request_timeout_ms` between two body frames gives the fill up (counted in `zion_cache_fill_stalled`). The client that triggered the fetch keeps receiving whatever the upstream sends; nothing is stored, and the requests that were waiting for that fill fetch for themselves instead of waiting on a hung upstream. |

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

The key is the **host** and the **full path + query**, plus the **canonical `Accept-Encoding` set** when
the stored response is encoded:

- The **host** is part of the key, normalised as host routing sees it (lowercased,
  port and trailing dot dropped; the HTTP/2 `:authority` or the HTTP/1 `Host`): two
  hosts with the same path never share an entry, whether their routes go to two
  origins or one route serves several hosts from one multi-tenant origin. Path
  invalidation and prefix purges still reach the path on every host.
- `/a?user=alice` and `/a?user=bob` never share an entry (query is part of the key).
- The query is part of the key **as written**, so `?b=2&a=1` and `?a=1&b=2` are two entries.
  A profile can opt in to `normalize_query = true` to sort the parameters by name in the
  key (stable, so repeated names keep their order; nothing that differs is merged). The
  upstream is still sent the original query. Keys built this way carry an internal mode marker, so switching the option on a reload
  never lets a raw-query request be served an entry filed under a sorted key (or the reverse).
- A response with **no `Content-Encoding`** and no `Vary: Accept-Encoding` is the same
  bytes for every client, so it is stored **once** and served to every
  `Accept-Encoding` (Chrome, Safari, curl and a bot share one entry and one origin
  fetch; concurrent cold requests with different encodings coalesce into one fetch).
  A client that refuses an unencoded body (`identity;q=0`, or `*;q=0` without
  `identity`) is not served it.
- An **encoded** response (`Content-Encoding: gzip`), or one the origin marks
  `Vary: Accept-Encoding` (it may compress for other clients, as nginx `gzip_vary`
  does), is stored per **Accept-Encoding set**: a `gzip`-accepting client and an
  `identity`-only client get **separate** entries, so a client is never served a coding
  it can't decode, and a client without gzip coming first does not make browsers get
  the uncompressed body (RFC 9111 §4.1). The set is lowercased, `q=0` dropped,
  deduplicated and sorted, so header ordering doesn't fragment the cache.
- Measured with 4 client profiles × 1,000 objects (each requested twice) against an
  origin that does not compress: 4,002 origin fetches and a 50 % hit ratio before,
  1,002 and 87.5 % (the maximum for that mix) after.

## Freshness

The freshness lifetime is **origin-driven, clamped to the profile**:

1. The origin's `s-maxage` (shared-cache directive) wins, else `max-age`, read from every
   `Cache-Control` line (`public` on one line and `max-age=0` on the next is a lifetime of 0).
   A directive given twice with different values makes the response stale (lifetime 0, one of
   the two readings RFC 9111 §4.2.1 allows), so it is not stored.
2. That value is capped by the profile's `ttl_seconds`.
3. If the origin gives neither, the profile `ttl_seconds` applies (`Expires` is not read).

## What a hit carries

An answer from the cache carries the origin's response headers, as the miss did. An entry
keeps every end-to-end header of the response it stores (`Cache-Control`, `Vary`,
`Content-Security-Policy`, `Content-Disposition`, `Link`, `Expires`, the origin's own `X-*`
headers, ...) and replays each of them, every value once and in the origin's order, on a hit,
a ranged hit (`206` / `416`), a stale answer (`STALE`, `STALE-WHILE-REVALIDATE`) and a
revalidated one (`REVALIDATED`). The answer then goes through the same steps as the miss
(security headers, the route's `csp`, CORS, compression), so a hit leaves with the headers of
the miss plus `Age` and `Accept-Ranges`. An upload served with `Content-Disposition:
attachment` and `Content-Security-Policy: sandbox` stays inert on every hit.

- **Not kept:** hop-by-hop headers (`Connection` and the fields any `Connection` line names,
  `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`,
  `Proxy-Authenticate`, `Proxy-Authentication-Info`), `Content-Length`, `Content-Range`, `Date`
  and `Age` (set again for each answer), `Set-Cookie` (a response that sets one is never
  stored), and what zion sets or removes on every response (`X-Zion-Cache`, `X-Request-ID`,
  `Alt-Svc`, `Server`, `Surrogate-Key`, the security headers). `Content-Type`,
  `Content-Encoding`, `ETag` and `Last-Modified` are kept in fields of their own and set once.
- **`Cache-Control`** is the origin's, as on the miss. When the origin sent none, a hit carries
  `public, max-age=<lifetime>` (`immutable` for a lifetime of a year or more), which is what the
  miss carried too. Every hit carries an **`Age`** header (RFC 9111 §4.2.3), seeded from the
  upstream `Age` at insert plus the time lived in zion's cache, so a downstream cache does not
  restart the origin's lifetime.
- **A `304`** to a client's conditional request carries the validators and, of the stored
  headers, those RFC 9110 §15.4.5 lists for it: `Cache-Control`, `Content-Location`, `Expires`
  and `Vary`. The client keeps the rest from the `200` it stored.
- **A revalidation that ends in `304`** updates the entry (RFC 9111 §4.3.4): each header the
  304 carries replaces the stored values of that name, the others stay. The body's
  `Content-Type` and `Content-Encoding` and the validators stay as stored, and a `Set-Cookie` on
  the 304 is not kept.
- **Bounded:** at most 32 KiB of headers per entry (a response with more is not stored, an
  update that would go over it is served and the entry left stale); the stored headers count
  against `cache_max_memory_mb`.

## Origin-side revalidation (RFC 9111 §4.3)

A stale entry is **revalidated**, not blindly re-fetched. When a stored entry is
past its freshness and carries a validator, zion sends a **conditional GET** to
the origin (`If-None-Match` from the stored `ETag`, `If-Modified-Since` from
`Last-Modified`):

- **`304 Not Modified`** → the stored entry is still good: zion revives its
  freshness in place and serves the **cached body**, marked
  `X-Zion-Cache: REVALIDATED`, without a re-download, and with the stored headers the
  304 updated ([What a hit carries](#what-a-hit-carries)). `zion_cache_revalidations`
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

## Range requests (RFC 9110 §14)

A fresh cached `200` answers `Range` from RAM, so a client can seek in a cached video or resume a
download without a trip to the origin (and without pulling the whole object):

```console
$ curl -sk -r 100-199 -D- -o /dev/null https://zion/media/clip.mp4
HTTP/2 206
content-range: bytes 100-199/3600
x-zion-cache: HIT
accept-ranges: bytes
```

- One byte range per request: `bytes=a-b`, `bytes=a-` and the suffix form `bytes=-n`. The slice
  is taken from the stored body without copying it. A range starting at or past the end is a
  `416` with `Content-Range: bytes */<size>`.
- Anything else is answered with the whole object (RFC 9110 §14.2 allows ignoring a `Range`):
  several ranges, another unit, a malformed value, a non-`GET`, a stored status other than `200`,
  and any response that is not a **fresh** hit (a stale-while-revalidate / stale-if-error copy,
  a revalidation).
- `If-Range` is honoured with strong comparison: a strong ETag must be identical to the stored
  one, a date must equal the stored `Last-Modified`; a weak validator never matches, and a
  non-matching `If-Range` gets the whole object, as the RFC says.
- Preconditions run first: a matching `If-None-Match` / `If-Modified-Since` answers `304`, not a
  slice.
- A `206` or `416` from the cache carries the stored origin headers like a whole hit
  ([What a hit carries](#what-a-hit-carries)), `ETag` and `Last-Modified` included, and a fresh
  hit says `Accept-Ranges: bytes`. Ranges apply to the stored representation, so a compressed
  variant is sliced in its compressed form (`Content-Encoding` is kept).
- A `Range` request for an object that is **not cached yet** goes to the origin as before; the
  object is stored only when the origin answers with the whole `200`, so seeking does not fill
  the cache by itself.

## Request `Cache-Control` (RFC 9111 §5.2.1)

The client can steer the cache per request (every `Cache-Control` line of the request counts):

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

A match returns a bodyless **`304 Not Modified`** with the validators and the
stored `Cache-Control`, `Content-Location`, `Expires` and `Vary` (RFC 9110 §15.4.5),
which saves the transfer on the common browser-revalidation path.

```console
$ curl -I -H 'If-None-Match: "v1-abc"' https://host/static/app.js
HTTP/2 304
cache-control: public, max-age=3600
x-zion-cache: HIT
age: 12
etag: "v1-abc"
```

## Observability

- **`X-Zion-Cache`** response header on every cacheable route: `HIT` (served from
  cache), `MISS` (fetched + stored), `BYPASS` (not cacheable / `no-store`).
- **Metrics** (`/metrics`): `zion_cache_hits` / `zion_cache_misses`; `zion_cache_fill_stalled`
  counts fills given up because the upstream stopped sending the body.
- **Purge** (loopback only, or the hosts in `[server] internal_networks` when it is
  set): `POST /_zion/cache/purge` clears everything;
  `POST /_zion/cache/purge?prefix=/static/` clears one path prefix (variants
  share the prefix, so this clears all encodings of a path). Returns
  `{"purged":N,"scope":...}`.

```console
$ curl -skX POST 'https://127.0.0.1/_zion/cache/purge?prefix=/static/app.js'
{"purged":2,"scope":"/static/app.js"}
```

### Purge by tag (`Surrogate-Key`)

An origin can label what it renders with a `Surrogate-Key` response header: tags separated
by spaces or commas (the header may repeat), e.g. `Surrogate-Key: post-42 section:news`.
Zion indexes the entry under each tag, and one call drops everything that carries a tag,
however many URLs and variants that is:

```console
$ curl -skX POST 'https://127.0.0.1/_zion/cache/purge?tag=post-42'
{"purged":3,"scope":{"tags":["post-42"]}}
```

`tag=` repeats and takes commas (`?tag=a&tag=b,c`; percent-encode anything unusual). An empty
`?tag=` is rejected with `400` (it never falls back to flushing everything). It is internal-IP
gated and POST-only like the rest of the endpoint.

- `Surrogate-Key` is for the cache: it is **not** sent to clients.
- Limits: 32 tags per response, 128 bytes per tag, plain visible ASCII; the index holds
  10,000 distinct tags and 200,000 (tag, key) pairs. A response whose tags cannot be tracked is
  **not stored**, because an entry a purge could not reach would be worse than a miss: too many /
  too long / invalid tags answer `X-Zion-Cache: BYPASS`; a full index is only found out while the
  body is being stored, after the response has gone out as `MISS`, and is counted in
  `zion_cache_tag_uncached` (so are the other cases). The previous entry under that URL is dropped
  too.
- A response whose fetch began before a tag purge is not stored once the purge has run (it may
  predate it), so a purge cannot be undone by a slow in-flight fetch.
- A new response for a URL **replaces** the tags the entry had (an old tag no longer purges
  it, and a response with no tags leaves the index). A revalidation that ends in `304` keeps the
  entry's tags, and is skipped if a tag purge ran while it was in flight, so it cannot bring back
  an entry the purge removed.

## RFC conformance at a glance

| Behaviour | RFC | Status |
|---|---|---|
| `private` / `no-store` / `no-cache` response directives | 9111 §3.2, §5.2.2 | Yes |
| Several `Cache-Control` lines read as one list (response and request) | 9110 §5.3 | Yes |
| Stored header fields replayed on every answer from the cache; hop-by-hop ones not stored | 9111 §3.1, §4 | Yes (32 KiB per entry) |
| A `304` revalidation updates the stored header fields | 9111 §3.2, §4.3.4 | Yes (not `Content-Type`, `Content-Encoding`, validators) |
| Authenticated-request storage opt-in | 9111 §3.5 | Yes |
| `Vary` matching (secondary keys) | 9111 §4.1 | Yes (exact match on the varied headers, bounded; `*` and credential headers → uncached) |
| Origin-driven freshness (`max-age` / `s-maxage`) + `Age` | 9111 §4.2 | Yes |
| Request `Cache-Control` (no-cache/no-store/max-age=0/only-if-cached) | 9111 §5.2.1 | Yes |
| Client conditional → `304` (If-None-Match / If-Modified-Since) | 9110 §13 | Yes |
| Origin-side revalidation (stale → conditional GET → 304) | 9111 §4.3 | Yes (`REVALIDATED`; stale-if-error §4.2.4) |
| `stale-while-revalidate` (serve stale, refresh in the background) | 5861 §3 | Yes (`STALE-WHILE-REVALIDATE`) |

See also [Hot-reload](/deploy/hot-reload) (cache survives config reloads) and the
[two-level-cache ADR](/adr/0003-two-level-cache-with-generation).
