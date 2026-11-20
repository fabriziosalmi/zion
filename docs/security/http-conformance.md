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

| HTTP/2 request | Behaviour |
|---|---|
| `content-length` lines that do not declare one valid length (`0` then `1000`, `5` then `1000`, `5` then `five`) | malformed (RFC 9113 §8.1.1): refused with `400` before routing, never forwarded, on the TLS listener and in h2c on the plaintext one (whose ACME fallback forwards) |
| a first `content-length` line that is not a number (`five`, `5, 5`) | refused by h2 itself: the stream is reset (`PROTOCOL_ERROR`), no status is sent, never forwarded |
| one valid length, on one line or repeated (`5`, or `5` and `5`) | forwarded with one `Content-Length`: the length of the body Zion sends |

The `Content-Length` Zion sends upstream always comes from the body it sends, on every
protocol; the client's lines are never copied. h2 checks only the first `content-length`
line against the DATA frames, so a second line used to reach the upstream as written.

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
multi-range requests, and HTTP/3 parity are not yet covered by the suite. HTTP/3 request
bodies are pinned apart, by
[`tests/h3_request_body.rs`](https://github.com/fabriziosalmi/zion/blob/master/tests/h3_request_body.rs)
(needs `--features http3`). `content-length` lines that do not declare one length are
refused with `400` before routing. A body shorter or longer than its `Content-Length` is
refused with `400` and never reaches the upstream as a whole body, on a streamed route, a
WAF route and a `require_content_length` route alike: a route that reads it first (a WAF,
`require_content_length`) forwards nothing, and a streamed one aborts the upstream request
(RFC 9114 §4.1.2; h3 checks neither). The upstream request reads a body no further than its
declared length, so the DATA that completes the length is held back until the stream shows
whether more follows, and a body declared `0` is read to its end before the request goes on
(DATA after it is refused before anything is forwarded). h3 0.0.8 reports a zero-length DATA
frame as the end of the body ([hyperium/h3#372](https://github.com/hyperium/h3/issues/372)), so
Zion asks again before it takes a body as ended, and a run of up to 15 empty DATA frames is
read through: a body with empty frames inside reaches the upstream whole, and DATA past the
length after them is refused. Not covered: a 16th empty DATA frame in a row still ends the body
there, so a body past its length then goes upstream cut at the length, and a body without a
`Content-Length` cut at that run. h3 reports a trailer section the same way, so DATA after one
(malformed, RFC 9114 §4.1) is read as more of the body. The WAF, a buffer and the upstream
request read the body from the same place, so a cut body is the same cut body for all of them.
