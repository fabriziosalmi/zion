# HTTP/HTTPS conformance

What Zion does with each shape of request: forward it unchanged, refuse it, or
re-frame it. Every row below is asserted on the real TLS listener against a real
origin by [`tests/http_conformance.rs`](https://github.com/fabriziosalmi/zion/blob/master/tests/http_conformance.rs)
(issue #741), so this page is the HTTP contract and a behaviour change fails the
suite. It is the positive counterpart to the request-smuggling corpus
([`tests/http1_smuggling_corpus.rs`](https://github.com/fabriziosalmi/zion/blob/master/tests/http1_smuggling_corpus.rs),
#697), which proves the negative: no desync form reaches the upstream.

The suite boots the binary with a proxy route to a recording origin, a
`preserve_host` route, a static route, a compress-enabled route, a cached route and
a WebSocket route, and drives them with a raw TLS client (`openssl s_client`, byte
for byte) and an HTTP/2 client (`curl --http2`).

## Methods (HTTP/1.1)

| Method | Behaviour |
|---|---|
| GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS | forwarded to the upstream; the upstream's status is returned |
| TRACE | refused with `405` at the edge, never forwarded |
| An unknown method | refused with `405` at the edge, never forwarded |

## Request body framing

| Request | Upstream |
|---|---|
| `Content-Length` body | forwarded with `Content-Length` |
| `Transfer-Encoding: chunked` body | parsed and re-framed by Zion's client (re-chunked); the client's raw framing never passes through |

## Hop-by-hop headers

`Connection`, `Keep-Alive`, `Upgrade`, and any header named in a `Connection`
token are stripped before the upstream. Ordinary end-to-end headers are forwarded.

## Request-target forms

| Form | Behaviour |
|---|---|
| origin-form (`/path`) | forwarded |
| absolute-form (`http://host/path`) | accepted and re-framed to origin-form upstream; the absolute URI and its authority never reach the upstream |
| asterisk-form (`OPTIONS *`) | refused (`404`), never forwarded |
| authority-form (`CONNECT host:port`) | refused (`405`), never forwarded |

## Host and `preserve_host`

| Route | `Host` sent upstream |
|---|---|
| default | rewritten to the upstream authority; the client's original `Host` is carried in `X-Forwarded-Host` |
| `preserve_host = true` | the client's `Host` is forwarded as-is (HTTP/1.1 only) |

## Expect: 100-continue

A request carrying `Expect: 100-continue` draws a `100 Continue` interim response
from Zion, then the request is forwarded.

## Conditional requests

| Request | Behaviour |
|---|---|
| `If-None-Match` matching the ETag (weak compare) | `304 Not Modified` |
| `If-None-Match: *` | `304` when a representation exists |
| `If-Modified-Since` at or after `Last-Modified` | `304` (RFC 9110 date comparison, #744) |
| `If-Modified-Since` before `Last-Modified` | `200` with the body |

`If-None-Match` takes precedence over `If-Modified-Since`.

## Range requests (static files)

| Request | Behaviour |
|---|---|
| `Range: bytes=0-9` | `206 Partial Content` with `Content-Range` |
| an unsatisfiable range | `416 Range Not Satisfiable` |
| a range on a compressible route | `206` served as identity (a partial representation is never compressed) |

## Response compression (`compress` feature, per-route opt-in)

| Request | Behaviour |
|---|---|
| `Accept-Encoding: br` on a `compress` route | `Content-Encoding: br`, `Vary: Accept-Encoding`, `Content-Length` dropped |
| `Accept-Encoding: gzip` | `Content-Encoding: gzip` |
| no `Accept-Encoding` | identity |
| a secret-bearing response (`Set-Cookie` / `Cache-Control: private`) | identity unless the route sets `allow_cookied` (BREACH guard, [ADR-0025](https://github.com/fabriziosalmi/zion/blob/master/docs/adr/0025-response-compression.md)) |

Built without the feature, a `compress` route serves identity.

## HTTP/2

GET, HEAD and POST over HTTP/2 reach the HTTP/1.1 upstream and return its response,
served back to the client as HTTP/2 (Zion translates h2 and h1). The upstream's
status is passed through unchanged on both HTTP/1.1 and HTTP/2 for 2xx, 3xx, 4xx and
5xx (an origin `5xx` is forwarded, not rewritten to `502`, which is reserved for a
dead upstream).

## Caching and `Vary`

A `cache_profile` route caches a `GET 200`. When the upstream marks a response
`Vary: Accept-Encoding`, Zion keys the cache by that variant: a repeated request
with the same `Accept-Encoding` is served from the cache (the upstream is not asked
again), while a different `Accept-Encoding` is a separate variant. An upstream's
`Vary` header is forwarded to the client.

## WebSocket upgrade

A `mode = "websocket"` route relays the upstream's `101 Switching Protocols` to the
client, upgrading the connection.

## Not yet pinned

`1xx` interim responses other than `100 Continue` (for example `103 Early Hints`),
multi-range requests, and HTTP/3 parity are not yet covered by the suite.
