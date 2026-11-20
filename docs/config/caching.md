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
| `Vary` | Absent, or naming request headers zion can key on (see [Vary and secondary keys](#vary-and-secondary-keys)). **Not cached:** `Vary: *`, any varied credential header (`Cookie`, `Authorization`, `Proxy-Authorization`, `Set-Cookie`), any varied header zion sets or rewrites for the origin with a value that differs between clients (`X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Host`, `Forwarded`, `Via`), more than 8 varied headers, or a variant over the per-key cap. |
| `Set-Cookie` | The response must **not** set a cookie (any `Set-Cookie` header, whatever its `Cache-Control`). It starts or changes a session, so its body is for one client; it is streamed to that client and never stored. |
| Headers | At most 32 KiB of origin headers to keep ([What a hit carries](#what-a-hit-carries); each field counts as its name, its value and 32 bytes, `Content-Type`, `Content-Encoding`, `ETag` and `Last-Modified` included). A response with more is streamed through, marked `BYPASS`, and counted in `zion_cache_too_large`, as is a background refresh or a `304` update that would go over it; it takes no `Vary` variant slot. The count is of what the bound (or `max_object_mb`) alone kept out: a response that may not be stored anyway (the rules above, a request's `no-store`) or a `304` that may not renew the entry is not counted, however large. |
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
  Nor a response that varies on a header zion sets or rewrites on the way to the origin
  with a value that differs between clients (`X-Real-IP`, `X-Forwarded-For`,
  `X-Forwarded-Host`, `Forwarded`, `Via`): the origin chose it by what zion sent, while the
  key would be built from what the client sent. A browser sends no `X-Real-IP`, so every
  browser would share the first one's variant. `Vary: X-Forwarded-Proto` is keyed like any
  other header: zion sends `X-Forwarded-Proto: https` on every request it caches, so the
  origin chose by a value every client shares.
- If the origin changes the set of headers it varies on, or stops varying, the key
  follows: the next `200` is filed under the new `Vary`, and entries filed under the old key
  are no longer reachable. A revalidation is held to the key the entry was filed under: a
  `304` whose `Vary` is not that one (a header more or less) does not renew the entry, in the
  foreground or from a background refresh; a `304` that sends no `Vary` keeps the entry's. In
  the foreground, the client it answered gets it for itself alone
  ([What a hit carries](#what-a-hit-carries)); either way the stale entry is removed, so that the
  next request is a miss whose `200` is filed under the new `Vary`. Renewed under the old key, one user's `304` from an origin that now varies on
  `X-Auth-Subject` would be every user's entry, with that user's headers. The `Vary` an entry
  was filed under is the one the request found it under, read when it looked the entry up: a
  `200` that another request files under a new `Vary` while this revalidation is on its way (or
  while this request waits on another one's fetch) does not make the new `Vary` the entry's, so
  a `304` with the new `Vary` does not renew it either.
- A background [stale-while-revalidate](#stale-while-revalidate-rfc-5861) refresh
  fetches the **same variant** it refreshes. An answer to it, `200` or `304`, whose `Vary` no
  longer matches the key the entry was filed under is discarded, and the stale entry is
  removed as above.

## Cache key

The key is the **host** and the **full path + query**, plus the **canonical `Accept-Encoding` set** when
the stored response is encoded:

- The **host** is part of the key, normalised as host routing sees it (lowercased,
  port and trailing dot dropped; the target's authority when it has one, an HTTP/2
  `:authority` or an absolute-form `GET http://host/path`, else the HTTP/1 `Host`): two
  hosts with the same path never share an entry, whether their routes go to two
  origins or one route serves several hosts from one multi-tenant origin. Path
  invalidation and prefix purges still reach the path on every host. The origin is told
  the host from the same field, as received (case and port kept), in `X-Forwarded-Host`
  (and as `Host` with `preserve_host`), so an absolute-form target sent with another
  `Host` cannot have the answer for that other host filed under the target's key.
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
headers, ...) and replays each of them, each field's values once and in the origin's order, on
a hit, a ranged hit (`206` / `416`), a stale answer (`STALE`, `STALE-WHILE-REVALIDATE`) and a
revalidated one (`REVALIDATED`). The answer then goes through the same steps as the miss
(security headers, the route's `csp`, CORS, compression), so a hit leaves with the headers of
the miss plus `Age` and `Accept-Ranges`. An upload served with `Content-Disposition:
attachment` and `Content-Security-Policy: sandbox` stays inert on every hit.

- **Not kept:** hop-by-hop headers (`Connection` and the fields any `Connection` line names,
  `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`,
  `Proxy-Authenticate`, `Proxy-Authentication-Info`; the proxy removes them from every upstream
  response, so the miss does not carry them either), `Content-Length`, `Content-Range` and
  `Age` (set again for each answer), `Set-Cookie` (a response that sets one is never
  stored), and what zion sets or removes on every response (`X-Zion-Cache`, `X-Request-ID`,
  `Alt-Svc`, which is zion's own with `--features http3` and removed without it, `Server`,
  `Surrogate-Key`, the security headers). `Content-Type`, `Content-Encoding`, `ETag` and
  `Last-Modified` are kept in fields of their own and set once; a `Content-Type` or
  `Content-Encoding` the origin sent on several lines is set once with the lines joined
  (`Content-Encoding: gzip, br`), which RFC 9110 §5.3 makes the same field.
- **`Date`** is the origin's, as on the miss: with `Expires`, it states the lifetime the origin
  gave, and with `Age`, how old the response is. (A hit dated when it is sent, beside its
  `Age`, had a downstream cache count the time spent in zion twice.)
- **A ranged answer** (`206` / `416`) does not carry `Content-Digest` or `Content-MD5`: they
  are digests of the whole stored body, not of the part. `Repr-Digest` stays. A compressed
  answer (a `compress` route) carries none of the three: they are of the bytes the origin sent.
- **`Cache-Control`** is the origin's, as on the miss. When the origin sent none, a hit carries
  `public, max-age=<lifetime>` (`immutable` for a lifetime of a year or more), which is what the
  miss carried too. Every hit carries an **`Age`** header (RFC 9111 §4.2.3), seeded from the
  upstream `Age` at insert plus the time lived in zion's cache, so a downstream cache does not
  restart the origin's lifetime.
- **A `304`** to a client's conditional request carries the validators and, of the stored
  headers, those RFC 9110 §15.4.5 lists for it: `Cache-Control`, `Content-Location`, `Date`,
  `Expires` and `Vary`. The client keeps the rest from the `200` it stored.
- **A revalidation that ends in `304`** updates the entry (RFC 9111 §4.3.4): each header the
  304 carries replaces the stored values of that name, the others stay. The body's
  `Content-Type` and `Content-Encoding` and the validators stay as stored, and a `Set-Cookie` on
  the 304 is not kept. The 304 answers the request that was sent, the client's `Cookie` and
  `Authorization` included, so it renews the shared entry only when it could have been stored
  itself, as a `200` is: no `Set-Cookie`, no `private`, `no-store` or `no-cache`, and a
  `public`, `s-maxage` or `must-revalidate` on the 304 when the request carried
  `Authorization`; and only when its `Vary` is the one the entry was filed under (the 304's own,
  or the entry's when the 304 sends none; see [Vary and secondary keys](#vary-and-secondary-keys)).
  Otherwise this client is answered with it and the entry stays as it was, stale, or, when the
  `Vary` is what differs, is removed. That answer is for this client alone, whatever the 304 or
  the entry said: its `Cache-Control` is `private`, followed by those of the entry's directives a
  private cache obeys that only hold it back or give the origin's own lifetime (`no-store`,
  `no-cache`, `must-revalidate`, `no-transform`, `max-age`), never `public` or `s-maxage` (they
  would let a shared cache downstream keep one client's answer for every client); and it carries
  the 304's `Set-Cookie`, which the entry does not keep. It carries none of the cache fields a
  CDN or cache in front of zion obeys in place of `Cache-Control`, which the entry keeps and a
  shared answer from it (a hit, a renewing `REVALIDATED`) still carries: every field whose name
  ends in `-Cache-Control`, the RFC 9213 targeted fields and the vendor fields named the same way
  (`CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control`, `Vercel-CDN-Cache-Control`,
  `Netlify-CDN-Cache-Control`, `Akamai-Cache-Control`, and any other CDN's), `Surrogate-Control`,
  Akamai's `Edge-Control` and nginx's `X-Accel-Expires`. The name pattern is deliberate: each
  CDN names its own targeted field, and a cache that reads one ignores `Cache-Control` (RFC 9213
  §2.2), so a field missing from a list of names would let it keep this client's answer for every
  client. The renewed lifetime is that of the updated response:
  the 304's `Cache-Control` or, when it sends none, the stored one (a bare `304` does not
  stretch a `max-age=60` entry to the profile TTL). The 304's `Date` replaces the stored one; a
  304 without a `Date` leaves none, and the answer is dated when it is sent.
- **Bounded:** at most 32 KiB of headers per entry, `Content-Type`, `Content-Encoding`, `ETag`
  and `Last-Modified` included (a response with more is not stored, an update that would go
  over it is served and the entry left stale). The stored headers count against
  `cache_max_memory_mb` at their size in memory (each field's name and value, its slot in the
  entry and the reference counts of its buffers; for those four, the value and the reference
  count of its buffer), and with the body toward the per-thread L1 limits.

## Origin-side revalidation (RFC 9111 §4.3)

A stale entry is **revalidated**, not blindly re-fetched. When a stored entry is
past its freshness and carries a validator, zion sends a **conditional GET** to
the origin (`If-None-Match` from the stored `ETag`, `If-Modified-Since` from
`Last-Modified`). Those are its only preconditions: the client's own `If-None-Match`,
`If-Modified-Since`, `If-Match`, `If-Unmodified-Since` and `If-Range` are not sent, and neither
is its `Range` (without its `If-Range` it would ask for a part of whatever the origin now has).
A client's `If-None-Match: *` beside zion's `If-Modified-Since` used to reach the origin, which
evaluates `If-None-Match` first (RFC 9110 §13.2.2): for an entry with no `ETag`, its `304`
renewed a version the origin had since replaced. The validators go on the request to the
origin only: a request that waits for this revalidation is answered from the renewed entry as
the request it is (a plain `GET` gets the body, not a `304`).

- **`304 Not Modified`** → the stored entry is still good: zion revives its
  freshness in place and serves the **cached body**, marked
  `X-Zion-Cache: REVALIDATED`, without a re-download, and with the stored headers the
  304 updated ([What a hit carries](#what-a-hit-carries)), with the 304's `Age`. A 304 that
  could not have been stored itself answers this client and leaves the entry stale, and one
  whose `Vary` is not the entry's removes it (same section). `zion_cache_revalidations` counts
  these.
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
  `Proxy-Authorization`, conditional or `Range` headers, and without what zion asserts about
  the caller (the auth gate's `X-Auth-Subject` / `X-Auth-Email`, the mesh score, the verified
  client certificate's `X-Client-Cert-*` and the TLS fingerprint's `X-Client-TLS-*`, the JA4
  and the allowlist entry it matched). It is conditional on the
  stored `ETag` / `Last-Modified`: a `304` revives the stored body and updates its headers,
  under the same rules as the synchronous revalidation ([What a hit carries](#what-a-hit-carries)),
  and a cacheable `200` replaces it, headers included. When the request that found the entry
  stale carried `Authorization`, the refresh's answer needs the same `public`, `s-maxage` or
  `must-revalidate` opt-in (RFC 9111 §3.5) as the foreground one: the origin may still have
  answered for that client. A `200` or `304` whose `Vary` is not the one the entry was filed
  under renews nothing and removes the stale entry ([Vary and secondary keys](#vary-and-secondary-keys)).
- **A refresh the origin refuses ends the window**: any other answer that renews or replaces
  nothing (a `401` or `403` from an origin that requires the headers above, a `304` that sets a
  cookie, as an origin that gives every request without a `Cookie` a session does, or that lacks
  the opt-in, a `200` that may not be stored or is over `max_object_mb`, any status but `200`,
  `304`, a 5xx, `429` and `408`) takes the entry out of its window. The entry stays, and the next request
  revalidates it in the foreground with its own headers, as an entry without the window is (or
  fetches it again when it has no validator); a renewal or a new `200` makes an entry with the
  window again. The next refresh would go out the same way and get the same answer: left in its
  window, the entry was served stale until the window closed, whatever the origin had since, and
  every request after the previous refresh ended started another one. A refresh that cannot reach
  the origin, gets no answer in time or not the whole body, or gets a 5xx, a `429 Too Many
  Requests` or a `408 Request Timeout` leaves the entry in its window: the origin, or a rate
  limiter in front of it, is failing or shedding load for every client, the next refresh can get
  another answer, and the stale copy served at once is what the window is for. Once outside its
  window an entry is no longer served stale.
- **Not for a variant keyed on what the refresh leaves out**: an entry whose `Vary` names one of
  the headers above (`Vary: X-Auth-Subject` behind an auth gate, `Vary: X-Client-TLS-JA4`) is
  not served stale while it revalidates. A refresh without that header would get the
  representation for a request without it and store it under this variant's key. Such an entry
  is answered as one without the window is: revalidated in the foreground with the client's own
  request, or fetched again when it has no validator.
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
stored `Cache-Control`, `Content-Location`, `Date`, `Expires` and `Vary` (RFC 9110 §15.4.5),
which saves the transfer on the common browser-revalidation path. Only a `GET` is answered
from the cache: a `HEAD` (what `curl -I` sends) goes to the origin, conditional or not.

```console
$ curl -sk -o /dev/null -D- -H 'If-None-Match: "v1-abc"' https://host/static/app.js \
    | grep -iE '^(HTTP/|cache-control:|x-zion-cache:|age:|etag:)'
HTTP/2 304
cache-control: public, max-age=3600
x-zion-cache: HIT
age: 3
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
| `Vary` matching (secondary keys) | 9111 §4.1 | Yes (exact match on the varied headers, bounded; `*`, credential headers and the headers zion writes for the origin → uncached) |
| Origin-driven freshness (`max-age` / `s-maxage`) + `Age` | 9111 §4.2 | Yes |
| Request `Cache-Control` (no-cache/no-store/max-age=0/only-if-cached) | 9111 §5.2.1 | Yes |
| Client conditional → `304` (If-None-Match / If-Modified-Since) | 9110 §13 | Yes |
| Origin-side revalidation (stale → conditional GET → 304) | 9111 §4.3 | Yes (`REVALIDATED`; stale-if-error §4.2.4) |
| `stale-while-revalidate` (serve stale, refresh in the background) | 5861 §3 | Yes (`STALE-WHILE-REVALIDATE`) |

See also [Hot-reload](/deploy/hot-reload) (cache survives config reloads) and the
[two-level-cache ADR](/adr/0003-two-level-cache-with-generation).
