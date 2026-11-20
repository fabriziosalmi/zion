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
| absolute-form (`http://host/path`) naming the same authority as `Host` | accepted and re-framed to origin-form upstream; the absolute URI never reaches the upstream |
| absolute-form naming another authority than `Host` | refused (`400`), never forwarded (pinned in the smuggling corpus, case 8) |
| absolute-form whose authority is not `host[:port]` (`http://host:x/path`) | refused (`400`), never forwarded (smuggling corpus, case 8d) |
| asterisk-form (`OPTIONS *`) | refused (`404`), never forwarded |
| authority-form (`CONNECT host:port`) | refused (`405`), never forwarded |

## Host and `preserve_host`

| Route | `Host` sent upstream |
|---|---|
| default | rewritten to the upstream authority; the client's original `Host` is carried in `X-Forwarded-Host` |
| `preserve_host = true` | the client's `Host` is forwarded as-is, port included (for an HTTP/2 client, its `:authority`); zion speaks HTTP/1.1 to that upstream, since HTTP/2 cannot carry a `Host` that differs from `:authority` |

A `Host` that names another authority than the request target (an absolute-form target, or
an HTTP/2 `:authority`) is refused with `400` before routing, on every route. So is a target or
`Host` authority that is not `host[:port]`: userinfo, or a port that is not a port number
(`a.example:x`, `a.example:+443`, `a.example:99999`). An upstream reads the host before the `:`
whatever follows it, where routing keyed `a.example:x` by its whole text. An empty port
(`a.example:`) is the scheme's default (RFC 3986 §6.2.3). The `Host` forwarded therefore names the host the request was
routed, checked and cache-keyed as (in the client's spelling: case, port, trailing dot). Over
HTTP/3 the `h3` crate already resets a request stream (`H3_MESSAGE_ERROR`) whose `:authority`
and `host` differ by a byte, before zion sees it, so that disagreement gets a stream reset
rather than a `400`. With the real binary the `400`s are asserted for HTTP/1.1 on the TLS
listener (smuggling corpus, cases 8 and 8d), for HTTP/2 over h2c on `:80`
(`tests/h2c_redirect_panic.rs`) and for an HTTP/3 `:authority` (`tests/h3_request_body.rs`). The
in-process pipeline tests (`src/vary_tests.rs`) send requests with a URI authority, a `Host`
header or both, at the default HTTP/1.1 version, through the gate every protocol runs.

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
client, upgrading the connection. The client's `101` carries `Upgrade: websocket`,
`Connection: Upgrade` and the upstream's `Sec-WebSocket-Accept`, which RFC 6455 §4.1
requires before a client (a browser) completes the handshake.

## Not yet pinned

`1xx` interim responses other than `100 Continue` (for example `103 Early Hints`),
multi-range requests, and HTTP/3 parity are not yet covered by the suite.
