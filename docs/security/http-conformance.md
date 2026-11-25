# HTTP/HTTPS conformance

What Zion does with each shape of request: forward it unchanged, refuse it, or
re-frame it. Every row below is asserted on the real TLS listener against a real
origin by [`tests/http_conformance.rs`](https://github.com/fabriziosalmi/zion/blob/master/tests/http_conformance.rs)
(issue #741), or by the test file its row or section names, so this page is the HTTP
contract and a behaviour change fails the suite. It is the positive counterpart to the request-smuggling corpus
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

The upstream's response is treated the same way before it reaches the client or the cache:
the hop-by-hop set (with `Proxy-Authenticate` and `Proxy-Authentication-Info`, which are for
zion) and every field named on any of its `Connection` lines, read as bytes, are removed. The
origin's `Alt-Svc` is not passed on either: zion sends its own with `--features http3`, and none
without it.

## Request-target forms

| Form | Behaviour |
|---|---|
| origin-form (`/path`) | forwarded |
| absolute-form (`http://host/path`) naming the same authority as `Host` | accepted and re-framed to origin-form upstream; the absolute URI never reaches the upstream. Its authority, not a `Host` sent with it, is the request's host (RFC 9112 §3.2.2): zion routes and caches on it and tells the upstream that one in `X-Forwarded-Host` (and as `Host` with `preserve_host`) |
| absolute-form naming another authority than `Host` | refused (`400`), never forwarded (pinned in the smuggling corpus, case 8) |
| absolute-form whose authority is not `host[:port]` (`http://host:x/path`, `http://host,x/path`) | refused (`400`), never forwarded (smuggling corpus, case 8d) |
| absolute-form with userinfo (`http://user:pass@host/path`, `http://host@other.example/path`) | refused (`400`) before routing, on the TLS listener (its `/healthz` and `/readyz` fast path included) and on `:80` (the ACME fallback included), never forwarded. The same for an HTTP/2 or HTTP/3 `:authority` with userinfo. RFC 9110 §4.2.4 has a recipient treat userinfo in an `http(s)` URI as an error (it hides the real host), RFC 9113 §8.3.1 and RFC 9114 §4.3.1 forbid it in `:authority`. Asserted on each listener and protocol by `tests/authority_userinfo.rs` |
| asterisk-form (`OPTIONS *`) | refused (`404`), never forwarded |
| authority-form (`CONNECT host:port`) | refused (`405`), never forwarded |

## Host and `preserve_host`

| Route | `Host` sent upstream |
|---|---|
| default | rewritten to the upstream authority; the request's host (the target's authority when it has one, else the client's `Host`) is carried in `X-Forwarded-Host` |
| `preserve_host = true` | the request's host is forwarded as-is, port included (the target's authority when it has one: for an HTTP/2 client, its `:authority`); zion speaks HTTP/1.1 to that upstream, since HTTP/2 cannot carry a `Host` that differs from `:authority` |

A `Host` that names another authority than the request target (an absolute-form target, or
an HTTP/2 `:authority`) is refused with `400` before routing, on every route. So is a target or
`Host` authority that is not `host[:port]`: userinfo, a host that is neither a DNS-style name
or IPv4 address (ASCII letters, digits, `-`, `.`, `_`) nor an IPv6 address in brackets
(`a.example,x`, `a.example;x`, a tab), or a port that is not a port number (`a.example:x`,
`a.example:+443`, `a.example:99999`). An upstream reads the host before the `:` whatever
follows it, and can read `X-Forwarded-Host` as a list (Express 5 keeps the part before the
first `,`), where routing keyed `a.example:x` and `a.example,x` by their whole text. An empty
port (`a.example:`) is the scheme's default (RFC 3986 §6.2.3). The `Host` forwarded therefore
names the host the request was routed, checked and cache-keyed as (in the client's spelling:
case, port, trailing dot). Over HTTP/2 and HTTP/3 an `:authority` that the `http` crate does
not parse (a second `:` outside brackets, a tab) gets a stream reset from `h2`
(`PROTOCOL_ERROR`) or `h3` (`H3_MESSAGE_ERROR`) rather than a `400`, and over HTTP/3 the `h3`
crate also resets a request stream whose `:authority` and `host` differ by a byte, before zion
sees it. With the real binary the `400`s are asserted for HTTP/1.1 on the TLS listener
(smuggling corpus, cases 8 and 8d), for HTTP/2 over h2c on `:80`, and the `h2` resets with
them (`tests/h2c_redirect_panic.rs`), and for an HTTP/3 `:authority` (`tests/h3_request_body.rs`). The
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
| a secret-bearing response (`Set-Cookie`, or `private` on any `Cache-Control` line) | identity unless the route sets `allow_cookied` (BREACH guard, [ADR-0025](https://github.com/fabriziosalmi/zion/blob/master/docs/adr/0025-response-compression.md)) |

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
`Vary` header is forwarded to the client, on a cache hit as on the miss (with the
origin's other end-to-end headers; `tests/cache_hit_origin_headers.rs`).

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
refused with `400` before routing. A body shorter or longer than its `Content-Length` never
reaches the upstream as a whole body, on a streamed route, a WAF route and a
`require_content_length` route alike (RFC 9114 §4.1.2; h3 checks neither). A route that reads
it first (a WAF, `require_content_length`) refuses it with `400` and forwards nothing. A
streamed route aborts the upstream request: the client gets `400`, unless the upstream
answered before it read the body, in which case the client gets that response, status
included. The upstream request reads a body no further than its
declared length, so the DATA that completes the length is held back until the stream shows
whether more follows, and a body declared `0` is read to its end before the request goes on
(DATA after it is refused before anything is forwarded). h3 0.0.8 reports a zero-length DATA
frame as the end of the body ([hyperium/h3#372](https://github.com/hyperium/h3/issues/372)), so
Zion asks again before it takes a body as ended, and a run of up to 15 empty DATA frames is
read through: a body with empty frames inside reaches the upstream whole, and DATA past the
length after them is refused. Not covered: a 16th empty DATA frame in a row still ends the body
there, so a body past its length then goes upstream cut at the length, and a body without a
`Content-Length` cut at that run. h3 reports a trailer section the same way, so DATA after one,
an invalid frame sequence that RFC 9114 §4.1 makes a connection error (`H3_FRAME_UNEXPECTED`),
is read as more of the body. The WAF, a buffer and the upstream
request read the body from the same place, so a cut body is the same cut body for all of them.
