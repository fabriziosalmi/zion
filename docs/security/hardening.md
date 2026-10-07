# Hardening

Zion applies security defaults that can be overridden via configuration.

## Response headers

Every HTTPS response includes these security headers (stored as static `HeaderValue` constants):

| Header | Value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Force HTTPS for 2 years |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Block iframe embedding |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Disable browser APIs |
| `Server` | *(removed)* | No server identification |

## Method whitelist

Only these HTTP methods are accepted. All others return `405 Method Not Allowed`:

```http
GET  POST  PUT  PATCH  DELETE  HEAD  OPTIONS
```

This blocks `TRACE` (cross-site tracing), `CONNECT` (proxy tunneling), and non-standard methods before any processing occurs.

## URI length limit

Requests with URI paths exceeding **8,192 bytes** return `414 URI Too Long`.

## Header limits

Hyper is configured with reduced header limits compared to defaults:

| Parameter | Zion | Hyper Default |
|---|---|---|
| Max header count | 64 | 100 |
| Max header buffer | 16 KB | 400 KB |

## Rate limiting

Per-IP rate limiting using `DashMap` with atomic counters:

```toml
[server]
rate_limit_rps = 100          # Max requests per IP per window
rate_limit_window_secs = 1    # Window duration
```

When `rate_limit_rps = 0` (default), rate limiting is disabled — the code returns before accessing any map. Over-limit requests return `429 Too Many Requests`.

## Timeouts

| Timeout | Duration | Purpose |
|---|---|---|
| TLS handshake | 10 seconds | Prevent TLS slowloris |
| HTTP request | 60 seconds | Kill stalled connections |
| Upstream connect | 3 seconds (configurable) | Fail fast on dead upstreams |
| Connection pool idle | 30 seconds | Reclaim unused upstream connections |
| TCP keepalive (clients) | `tcp_keepalive_secs`, 60 s | Free the slot of a peer that vanished while the connection was *idle* |
| `TCP_USER_TIMEOUT` (clients) | `tcp_user_timeout_secs`, off (opt-in, Linux) | Free the slot of a client that vanished *while a response was in flight*; also drops a client that stops reading for longer than the value |
| Upstream DNS lookup | `dns_timeout_ms`, 2000 ms | A resolver outage or hang falls back to the last good answer instead of stalling connections |

## Connection limit

The number of client connections held open at once, on both listeners together, is bounded by a
semaphore. The connection that would exceed it is closed at accept, before the TLS handshake, and
counted in `zion_connections_rejected_global`.

By default the ceiling is derived from memory:

```text
conn_limit = (memory_MB / 4) * 1024 / 256    # a quarter of the memory, 256 KB per connection
```

clamped to 1,000–100,000. The memory is the machine's RAM, or the **cgroup limit** when one is set
below it (`memory.max` or `memory.high` of the cgroup or any of its ancestors; `memory.limit_in_bytes`
on cgroup v1): a container, a Kubernetes pod, a systemd unit with `MemoryMax=`. Before v0.10 the
limit was ignored, so a pod limited to 512 MiB on a 32 GiB node admitted 31,980 connections and
would be killed by the kernel long before it shed one; it now admits 1,000. The boot report shows
which figure was used (`ram  512 MB (cgroup limit; the host has 32.0 GB)`).

`[server] max_connections` sets the ceiling explicitly, to go above 100,000 on a large machine or
below the derived value where memory is tight. It is read at start; a reload that changes it is
refused.

What a connection costs, measured on Linux (release build, 2,000 connections in each state):

| State of the connection | Memory |
|---|---|
| TLS handshake done, no request yet | 14 KB |
| HTTP/1.1 keep-alive, idle after a request | 46 KB |
| HTTP/2, idle after a request | 49 KB |
| HTTP/1.1, a large static file being sent to a client that is not reading | 829 KB |
| HTTP/2, the same on one stream (a connection carries up to 128 streams) | 903 KB |

The 256 KB of the formula is a budget between the idle and the busy figures, not a bound: 1,000
connections that are all stuck mid-download hold about 900 MB. Where that matters (a small
container that serves large files), set `max_connections` from the busy figure, and
`max_connections_per_ip` (an eighth of the ceiling by default) so that one address cannot take
the whole of it.

## HTTP/2 control-frame floods

HTTP/2 has frames that carry no request and that a server must still read, and often answer:
`PING`, `SETTINGS`, `WINDOW_UPDATE`, `PRIORITY`, `RST_STREAM`. One connection can send them as fast
as the network takes them. The HTTP/2 library bounds streams reset as soon as they are opened
(Rapid Reset, CVE-2023-44487) and nothing else, so such a connection was served to its last frame
and never closed. The cost per frame is small (two million `PING`s cost about 0.13 s of one core),
which makes this a way to keep a core busy per connection, not an outage; the per-IP connection
limit was the only bound.

`[server] h2_control_frames_per_sec` closes a connection that sends more than that many control
frames in one second, with `GOAWAY(ENHANCE_YOUR_CALM)`:

```toml
[server]
h2_control_frames_per_sec = 1000
```

It is **off by default** (`0`): a limit that is wrong for your clients closes their connections,
and Zion has not measured every client. With no limit the frames are still counted, and
`zion_h2_control_frames_peak` reports the most any one connection sent in a second: read it on
your traffic, then set the limit well above it.

What counts, and what does not:

| Frame | Counted |
|---|---|
| `PING`, `SETTINGS` (and their acks), `PRIORITY`, `GOAWAY` | yes |
| A frame type the server does not know (it reads and drops it) | yes, or it would be the way around the limit |
| `DATA` with no payload that does not end its stream | yes |
| `RST_STREAM` | only beyond the streams the connection opened: cancelling a request is free |
| `WINDOW_UPDATE` | separately: 1,000 a second, plus one per 256 bytes of response written to the client in that second |
| `HEADERS`, `CONTINUATION`, `DATA` with a payload | no: that is a request, bounded by the stream, header-size and rate limits |

Measured on one connection:

| Client | Control frames per second | Response bytes per `WINDOW_UPDATE` (300 MB download) |
|---|---|---|
| curl 8.7 (`--http2`) | 2 | 5 MB |
| nghttp 1.69, default and 64 KiB windows | 2 | 18 KB |
| h2load 1.69, 100 streams per connection | 2 | over 100 MB |
| Chrome 154 | 2 to 3 | 2.2 MB |
| Chrome 154 cancelling 100 downloads in flight, three times in a second | 2 (and 302 `RST_STREAM`s, not counted) | 5 MB |

So `1000` is over 300 times what these clients send, and their `WINDOW_UPDATE`s are 70 times or
more under the allowance of one per 256 bytes.

**grpc-go is different.** It sends a `PING` with the data it receives, to estimate bandwidth, so its
rate follows the round-trip time. Measured through zion (the rig is in
[`benchmarks/h2-control/`](https://github.com/fabriziosalmi/zion/tree/master/benchmarks/h2-control)):

| Client-to-zion RTT | One 500 MiB download | 20,000 unary calls, 8 callers | One bidirectional stream |
|---|---|---|---|
| loopback | 726 | 2,019 | 5,003 |
| 0.2 ms | 712 | 1,411 | 1,700 |
| 1 ms | 412 | 616 | 380 |
| 5 ms | 169 | 166 | 90 |

On macOS loopback a bidirectional stream reached 17,200. A limit of `1000` would close busy grpc-go
connections inside a data centre. **If gRPC goes through zion, read `zion_h2_control_frames_peak` on
real traffic and set the limit well above it (`20000` leaves even loopback grpc-go alone), or leave it
at `0`.** The C-core gRPC clients (Python, Ruby, C#, PHP) measured 6 to 13. Firefox and Safari have not
been measured: `benchmarks/h2-control/rig.sh browser` does it.

The bound applies however the client got to HTTP/2: ALPN `h2`, a TLS connection that negotiated
nothing and opens with the HTTP/2 preface, or the preface on the plaintext listener. A closed
connection is counted in `zion_h2_control_flood_closed_total{reason}` and logged with the client
address (one line a second at most). The `GOAWAY` is sent if the connection takes it at once; a
client that is still sending when the socket closes may see a reset instead.

## Protecting the upstream

Two opt-in, per-upstream limits keep a struggling backend from taking the proxy down with it (see the
[resilience guide](/guide/resilience) for how they combine):

- `max_in_flight`: at most N requests inside the upstream; the next gets `503` + `Retry-After`
  immediately instead of one more connection, buffered body and waiting task. Taken after auth and
  the WAF, so a hostile request cannot use up slots.
- `circuit_breaker`: stops sending traffic to a single-endpoint upstream whose real requests are
  failing, answers `503` at once, and probes it with one request.

## Logs and personal data

The access log, the audit trail and TLS-handshake failure lines carry the client address. `[redact] ip`
writes it as is (default), as its network (`203.0.113.0/24`, `2001:db8:1::/48`), or as a keyed,
irreversible, per-client-stable token (`hmac`, with the key from `ip_hmac_key_env`); header and query-string values are
redacted with `[redact] headers` / `query_params`. See
[Client IP privacy](/guide/observability#client-ip-privacy-redact-ip). Log lines go through a bounded
queue: a stalled log pipe drops the newest lines (counted in `zion_log_lines_dropped_total`) instead of
stalling requests.

## HTTP to HTTPS redirect

Port 80 serves only two purposes:

1. **ACME challenges**: `/.well-known/acme-challenge/*` is proxied to the configured upstream
2. **Everything else**: `301 Moved Permanently` redirect to `https://`

The `Host` header is validated before use in the redirect URL:
- Must be non-empty and <= 253 characters
- Must not contain `/`, `\`, `@`, newlines, or spaces

## Internal-only routes

Routes marked with `internal_only = true` are restricted to private IPs:

```text
127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 169.254.0.0/16, ::1
```

External requests receive `403 Forbidden`.

## Linux-specific options

On Linux, Zion enables additional socket options when the kernel supports them:

- `TCP_DEFER_ACCEPT`: Kernel holds connections until client sends data
- `TCP_FASTOPEN`: TFO for returning clients (requires kernel support)
- `SO_REUSEPORT`: Kernel-level connection distribution across listeners

## 0-RTT replay protection

TLS 1.3 0-RTT is enabled but gated by HTTP method. Non-idempotent methods (`POST`, `PUT`, `PATCH`, `DELETE`) on early data receive `425 Too Early` (RFC 8470). Only `GET` and `HEAD` are allowed on 0-RTT data.

See [TLS Configuration → 0-RTT Replay Protection](../config/tls.md#_0-rtt-replay-protection) for details.

## Hop-by-hop header stripping

Zion strips the following hop-by-hop headers from upstream responses before forwarding to clients (RFC 7230 §6.1):

```text
Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization,
TE, Trailer, Transfer-Encoding, Upgrade
```

## X-Forwarded-For policy (`xff_mode`)

Outbound XFF behaviour is configured at `[server]` level. The default (`append`) preserves the prior behaviour and is correct when Zion sits behind a sanitising edge (CDN/ALB) that has already vetted the inbound chain. When Zion is the **front edge**, the default is unsafe: a client can send `X-Forwarded-For: 1.2.3.4` and the leftmost entry in the chain forwarded to your upstream will be that attacker-controlled value. Downstream apps that read `XFF[0]` for ACL or audit will be tricked.

```toml
[server]
xff_mode = "rewrite"   # one of: "append" | "rewrite" | "drop"
```

| Mode | Inbound XFF | Outbound XFF | Use when |
|---|---|---|---|
| `append` (default) | preserved | inbound chain + resolved client IP appended | Zion is behind a trusted edge that already strips/normalises XFF |
| `rewrite` | dropped | single entry: the resolved client IP | Zion is the front edge — guarantees a clean one-hop chain regardless of what the client sent |
| `drop` | dropped | not emitted | Upstreams must not learn the client IP at all |

`X-Real-IP` is **always** set from the resolved client IP and never trusted from inbound headers, regardless of `xff_mode`. The "resolved client IP" is the output of `TrustedProxies::resolve_client_ip`: the rightmost X-Forwarded-For entry that is not a trusted-proxy CIDR, or the TCP peer IP when no proxies are configured.

## mTLS client certificate forwarding

When the TLS listener is configured with client-certificate verification (`client_ca_path` set, `client_auth = "required"` or `"optional"`), Zion extracts a stable identifier from the leaf peer certificate and forwards it to upstreams as:

```http
X-Client-Cert-Fingerprint: sha256:<64 hex chars>
```

The value is the SHA-256 of the leaf DER, hex-encoded with a `sha256:` prefix — Zion's pinned wire format for this header (the prefix names the algorithm so it can never be ambiguous). (nginx's `$ssl_client_fingerprint` is a similar idea but a **SHA-1** digest — do not compare the two values directly.) It is collision-resistant and stable across re-issuance only when the cert bytes themselves are stable; rotating a cert produces a new fingerprint.

Earlier Zion versions emitted `X-Client-Cert-DN`, computed as a 64-bit XOR-fold of the first 64 DER bytes. That value was advertised as a "DN" but was neither a Distinguished Name nor collision-resistant; it was **removed in v0.1.7** and replaced by `X-Client-Cert-Fingerprint` with no coexistence window. If your upstream still expects the old header, map it at the upstream side from `X-Client-Cert-Fingerprint` (note: the new value is a fingerprint, not a DN, and downstream identity mapping must be done via your roster).

### Injected request-header contract

Zion's contract for the headers it sets or strips on the way to the upstream. Anything an upstream trusts for identity is Zion-owned: any inbound copy from the client is stripped before Zion re-injects the verified value, so these cannot be forged by a client.

| Header | Direction | Meaning | Since |
|--------|-----------|---------|-------|
| `X-Forwarded-For` | set per `xff_mode` | client IP chain (see table above) | 0.1 |
| `X-Real-IP` | set (inbound never trusted) | resolved client IP | 0.1 |
| `X-Forwarded-Proto` / `X-Forwarded-Host` | set | original scheme / Host | 0.1 |
| `X-Request-ID` | set if absent, else echoed | request correlation id | 0.1 |
| `X-Client-Cert-Fingerprint` | set on mTLS routes (inbound stripped) | `sha256:<hex>` of the leaf DER | **0.1.7** (replaced `X-Client-Cert-DN`) |
| `X-Client-TLS-JA4` / `X-Client-TLS-*` | set on TLS-fingerprint routes (inbound stripped) | verified JA4 identity | 0.7.5 |
| `X-Auth-Subject` / `X-Auth-Email` | set from validated claims (inbound **always** stripped) | authenticated `sub` / `email` | requires `--features auth` |

Breaking changes to this contract are called out in the [CHANGELOG](https://github.com/fabriziosalmi/zion/blob/master/CHANGELOG.md); pin the header names you consume and re-check them on a major upgrade.

## Hot-reload

Zion applies changes to `zion.toml` and to the certificate files referenced by `[tls]` without restarting the process. An invalid config is rejected and the previous snapshot keeps serving traffic, so the only way a config edit can break production is if it is a *valid* config that does the wrong thing.

The full contract — what reloads, what is left to a restart, how to verify a reload landed — is in [Operations → Hot-reload](../deploy/hot-reload.md).

## Content-Security-Policy

Per-route CSP headers can be configured. See [Routing → Content-Security-Policy](../config/routing.md#content-security-policy-per-route).
