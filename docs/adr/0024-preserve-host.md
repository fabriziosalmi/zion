# ADR-0024: `preserve_host` — forward the client's Host over HTTP/1.1 only

- **Status**: accepted
- **Date**: 2026-10-02
- **Deciders**: fabriziosalmi
- **Tags**: proxy, upstream, http2, websocket, import

## Context

Zion always rewrites the upstream request's `Host` to the upstream's own authority and
re-surfaces the client's host in `X-Forwarded-Host` (`apply_forwarding_hygiene`,
`src/proxy.rs`). nginx configs almost always ask for the opposite
(`proxy_set_header Host $host;`): it is in every real nginx config imported during the
2026-10-02 analysis and is the most frequent directive `zion import nginx` cannot convert.
Traefik (`passHostHeader`, default `true`) and Caddy forward the client's `Host` by
default, so their imports lose it silently. Applications that read `Host` break behind
Zion: Django `ALLOWED_HOSTS`, Rails host authorization, absolute URLs and redirects, CSRF
origin checks, multi-tenant routing, virtual hosts on the upstream itself (#485).

How the outbound request is built today, measured rather than read:

- The request URI carries the upstream `scheme://authority`; hyper-util derives `Host`
  (HTTP/1) or `:authority` (HTTP/2) from it, connects to it, and hyper-rustls takes the
  TLS server name (SNI and certificate check) from it.
- **HTTP/1:** hyper-util only adds `Host` when it is absent. A probe sending
  `Host: client.test` to a Go backend arrived as `r.Host = "client.test"`.
- **HTTP/2:** hyper sends `:authority` from the URI *and* the `host` header as given. With
  `Host: client.test` against a Go h2c backend the stream was **reset with
  `PROTOCOL_ERROR`** (RFC 9113 §8.3.1: `Host` and `:authority` must not differ). The
  client's host cannot be expressed over HTTP/2 without changing `:authority`, which is
  also what the pool and TLS key on.
- **WebSocket (existing bug, found in this spike):** `proxy_websocket` removes `Host` and
  sends the handshake over hyper's low-level HTTP/1 connection, which adds nothing, with
  the target in absolute form (`GET http://127.0.0.1:29401/ws HTTP/1.1`, no `Host`).
  Through Zion 0.9.6 a Go `net/http` backend answers the upgrade **400**; directly it
  answers 101. Plain requests are unaffected.
- **Cache:** since 0.9.6 the response-cache key carries the request host
  (GHSA-xwm8-fqm7-8m5r), so forwarding the client's host cannot make one host's response
  reach another.

## Decision

### A per-upstream switch, off by default

`[upstream.<name>] preserve_host = true` sends the client's host to that upstream. The
default (`false`) is today's behaviour. It is per upstream, like Traefik's per-service
`passHostHeader`, because the transport choice below is per upstream too; an nginx
config that sets `Host` in some locations of an upstream and not in others is imported as
two upstreams (or reported).

### The value forwarded is the client's, as received

The inbound `Host` header, or the HTTP/2 `:authority` when the client spoke HTTP/2, byte
for byte (port included), like nginx `$http_host` and Traefik. It is already a valid
header value and, when host routing is on, the authority the route matched. A request
with neither (HTTP/1.0) falls back to the upstream's authority. `X-Forwarded-Host` keeps
being set as today, and client-supplied override headers stay scrubbed (#461).

### Those upstreams are spoken to over HTTP/1.1 only

An upstream with `preserve_host` gets a client built with HTTP/1 only (ALPN `http/1.1`),
from the same per-settings client cache as `connect_timeout_ms`. HTTP/2 cannot carry a
`Host` that differs from `:authority` (measured above), and nginx proxies over HTTP/1.1
anyway. The cost is losing HTTP/2 multiplexing to a TLS upstream that offers it, only for
upstreams that opt in.

### TLS verification stays on the upstream's name

The URI, and so the connection, pool key, SNI and certificate check, keep the upstream's
authority. `preserve_host` changes one request header, never which certificate is
accepted.

### Every path that talks HTTP to an upstream honours it

Standard and pooled proxying (including failover attempts), `sse_stream`, cached-route
origin fetches **and** their background refreshes (which build their own request),
WebSocket upgrades, and the `:80` ACME fallback.

### Health probes send `health_host` (amended while implementing)

The first version of this record said health probes keep the upstream's own name. Measured
against a backend that refuses unknown hosts (as Django `ALLOWED_HOSTS` does): the probe
(`Host` = the upstream's address) got 400, the upstream was marked down, and **every**
request answered 503, with or without `preserve_host`. So `[upstream.x] health_host` sets
the `Host` the probe sends; such a probe goes over the HTTP/1.1-only client for the same
reason as above. It is re-applied on every reload. An upstream with `preserve_host` and no
`health_host` gets a startup warning. Importers set it from the source's server name when
they turn `preserve_host` on.

### WebSocket upgrades send a valid request first

Independently of `preserve_host`, and shipped first as a bug fix: the upgrade request
carries `Host` (the upstream's authority, or the client's with `preserve_host`) and an
origin-form target (`/path?query`).

### Importers

- nginx: `proxy_set_header Host $host` / `$http_host` → `preserve_host = true`, finding
  **convert** (`$host` drops the port and lowercases; Zion forwards the header as sent:
  noted in the finding). A literal (`proxy_set_header Host example.com`) stays
  unsupported: overriding to a fixed host is a different feature.
- Traefik: `passHostHeader` absent or `true` → `preserve_host = true`; `false` → off.
- Caddy: `reverse_proxy` forwards the client's host by default → `preserve_host = true`;
  `header_up Host {upstream_hostport}` → off.

## Consequences

- Applications behind Zion that check `Host` work when migrated from nginx, Traefik or
  Caddy; imports of those three now keep their behaviour instead of losing it.
- WebSocket upgrades work against strict HTTP/1.1 backends (Go `net/http`, and any server
  that enforces RFC 9112 §3.2) — a fix for every version so far.
- An opted-in upstream is HTTP/1.1 only; a TLS upstream that offered HTTP/2 loses
  multiplexing, and each concurrent request needs its own pooled connection.
- One more client per distinct (connect timeout, HTTP/1-only) setting; clients are cheap
  and cached.
- A backend that refuses unknown hosts needs `health_host` too, or its probes fail and it is
  marked down; the warning at startup says so.
- Two hosts sharing one upstream with `preserve_host` reach the upstream as themselves;
  the response cache already separates them.

## Alternatives considered

- **Send `Host` over HTTP/2 anyway.** Measured: the backend resets the stream with
  `PROTOCOL_ERROR`. Rejected.
- **Put the client's host in the request URI and connect through a resolver override.**
  Keeps HTTP/2, but the URI host is also the pool key and, in hyper-rustls, the TLS server
  name: certificate verification would move to the client's name, against the rule above,
  and every client host would get its own upstream pool. Rejected.
- **Per-route instead of per-upstream.** Matches nginx's per-location granularity, but
  the transport (HTTP/1-only client) belongs to the upstream; per-route would mean two
  clients for the same upstream depending on the route. The importer splits upstreams
  instead.
- **Normalise the forwarded value** (lowercase, strip the port, like nginx `$host`).
  Rejected: backends compare against what the browser sent (ports included in
  development and non-default deployments), and Traefik and Caddy forward it unchanged.
- **Make it the default.** It would change the `Host` every existing upstream receives
  and silently drop HTTP/2 to TLS upstreams. Off by default; importers turn it on where
  the source config had it.

## References

- Issue #485; spike probes: hyper-util HTTP/1 vs HTTP/2 client against a Go h2c backend,
  WebSocket upgrade through 0.9.6 against Go `net/http`.
- RFC 9110 §7.2 (Host and :authority), RFC 9112 §3.2 (Host required in HTTP/1.1, 400
  otherwise), RFC 9113 §8.3.1 (`Host` must not differ from `:authority`).
- [ADR-0010](0010-host-based-l7-routing.md) host routing;
  [GHSA-xwm8-fqm7-8m5r](https://github.com/fabriziosalmi/zion/security/advisories/GHSA-xwm8-fqm7-8m5r)
  (cache key per host).
