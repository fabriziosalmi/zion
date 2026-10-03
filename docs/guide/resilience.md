# Resilience

A proxy is the first thing to feel a struggling backend, a resolver outage, a stalled log pipe or a
client that vanished mid-download. Zion has a small set of **independent protections**, each
off or conservative by default, each with its own metric. This page says what each one does, where
it sits on the request path, and how to combine them. The settings themselves are in the
[configuration reference](/config/); this is the map.

## What protects against what

| Problem | Protection | Setting | Default | Metric |
|---|---|---|---|---|
| One backend member is slow or erroring in a pool | Pool balancing on real traffic | `load_balancing` | `p2c` | `zion_upstream_inflight`, `zion_upstream_peak_ewma_seconds` |
| One member keeps failing while the others are fine | Passive outlier ejection | `outlier_detection` | off | `zion_upstream_ejected`, `zion_upstream_ejections_total` |
| A single-endpoint backend is failing | Circuit breaker | `circuit_breaker` | off | `zion_upstream_circuit_open`, `…_trips_total`, `…_rejected_total` |
| A backend is overloaded and requests pile up | Concurrency cap (bulkhead) | `max_in_flight` | off | `zion_bulkhead_in_flight`, `zion_bulkhead_limit`, `zion_bulkhead_shed_total` |
| The DNS resolver fails or hangs | Last good answer, deadline | `dns_stale_secs`, `dns_timeout_ms` | 3600 s, 2000 ms | `zion_dns_lookup_failures_total`, `zion_dns_stale_served_total` |
| The origin is down, the cache holds a copy | Stale serving | `stale-while-revalidate`, `stale-if-error` (from the origin) | origin-driven | `zion_cache_*` |
| A deploy waits for idle connections | Graceful drain | built in | 30 s limit | log lines `shutdown` |
| stderr / the log pipe is slow | Non-blocking log queue | `log_queue_lines` | 8192 | `zion_log_lines_dropped_total` |
| A client vanishes while a response is in flight | `TCP_USER_TIMEOUT` | `tcp_user_timeout_secs` | off | — |

## Where they sit on the request path

```text
request
  → pre-routing gates (scrub, URI, method, rate limit, …)      [security]
  → route lookup → auth → WAF
  → bulkhead        max_in_flight        a full upstream answers 503 at once
  → circuit breaker circuit_breaker      an open circuit answers 503 at once
  → pool pick       p2c / lowest_latency skips members that are down, gray or ejected
  → connect         DNS (last good answer), connect_timeout
  → response        outcome → breaker window, outlier window, latency estimate
```

The order is deliberate. The bulkhead comes **before** the breaker, so a request refused because the
upstream is busy is never counted as an upstream failure and never spends a half-open probe. Both
come **after** auth and the WAF, so a hostile or unauthenticated request cannot use up slots or
learn that a circuit is open.

## Pools: choosing a member

With two or more endpoints (`urls = [...]`) each request goes to one member chosen by *power of two
choices*: two members are drawn at random and the request goes to the one with the lower
`(requests in flight + 1) × latency estimate`. The estimate is the time to response headers measured
on **real requests** (a peak-EWMA): a slow response raises it at once, and it fades with time
(it halves every 5 s without a new sample), so a member that was slow once is tried again, and a
member with no estimate is assumed as fast as the member it is compared with.

- Members that are down, in gray failure (probe latency above 2 s) or ejected are skipped, unless
  that would leave none: the pool still answers rather than returning `503`.
- A transport error fails over to another member for idempotent methods (and for any method when
  the request provably never reached the upstream).
- `load_balancing = "lowest_latency"` keeps the pre-0.9.4 rule (lowest *probe* latency, refreshed
  every 30 s). It sends everything to one member between probes.

## Outlier ejection

`outlier_detection = { error_rate_pct = 50, min_requests = 20, window_secs = 10, eject_secs = 30, max_ejected_pct = 50 }`
takes a member out of rotation when its **own** failure rate (`502`/`503`/`504` or a transport
error) is at or above the threshold **and** another member is clearly doing better. It never acts on
a pool-wide outage, caps how much of the pool can be out at once, lengthens the ejection for repeat
offenders (up to ×10), and drops the member's latency estimate so it is measured afresh when it
returns. An ejected member stays `1` in `zion_upstream_up` (that metric is the active probe's view)
and shows `1` in `zion_upstream_ejected`.

## Circuit breaker and bulkhead: protecting a single backend

Pools fail over between members; a **single** endpoint has nothing to fail over to. Two opt-in
protections cover it, and they answer different questions:

- **`circuit_breaker`**: "is it *failing*?" Opens when the failure rate of real requests crosses a
  threshold, answers `503` + `Retry-After` for `open_secs`, then lets one probe through.
- **`max_in_flight`**: "is it *saturated*?" At most N requests inside the upstream (the whole
  pool); the N+1st gets `503` + `Retry-After: 1` + `X-Zion-Bulkhead: full` immediately. A request
  holds its slot until its response body has been sent, so a slow download counts. Size it from the
  backend (how many concurrent requests it serves at an acceptable latency), not from zion.

Not counted by the bulkhead: cache hits, WebSocket upgrades (long-lived) and static files.

## DNS

Upstream names are resolved by the system resolver. A fresh lookup is **always tried first**, so
address changes still take effect on the next connection; the last good answer is used **only** when
that lookup fails, returns nothing, or exceeds `dns_timeout_ms`, for up to `dns_stale_secs`. At most
one lookup runs per host at a time (a blocked `getaddrinfo` cannot be cancelled, so a deadline only
stops *waiting*), and a late answer is still recorded. `0` turns either off.

## Deploys: draining

On `SIGTERM` zion stops accepting and tells every open connection to wind down: an **idle**
keep-alive connection is closed at once, HTTP/1 closes after the response in flight
(`Connection: close`), HTTP/2 sends `GOAWAY`, finishes its open streams and closes. A request being
served is finished, never cut. The overall limit is 30 s. Before 0.9.5 an idle keep-alive connection
held the drain until its own idle timeout (14 s in a probe with one idle connection).

## Clients that vanish

`tcp_keepalive_secs` (default 60) frees the slot of a peer that disappeared while the connection
was **idle**. A client that vanishes **while a response is in flight** is not idle, so keepalive
never fires; the kernel gives up after about 15 minutes of retransmissions. `tcp_user_timeout_secs`
(Linux, opt-in) bounds that. Note that it also bounds a *zero-window* stall, i.e. it drops a client
that stops reading for longer than the value (a paused player, a very slow reader): pick a value
comfortably above the longest pause you accept, for example `300`.

## Logging under pressure

Log lines go through a bounded queue to one writer thread, so a stalled pipe (journald, a container
log driver) can no longer stall request workers. When the queue is full the newest lines are dropped,
counted in `zion_log_lines_dropped_total` and announced on stderr once it moves again. Any increase
means log lines are missing, not that requests were slowed.

## A combined example

```toml
[server]
tcp_keepalive_secs   = 60
tcp_user_timeout_secs = 300      # free the slots of clients that vanish mid-response
dns_stale_secs       = 3600
dns_timeout_ms       = 2000
log_queue_lines      = 8192

[upstream.api]                   # a pool
urls              = ["http://10.0.0.5:8000", "http://10.0.0.6:8000", "http://10.0.0.7:8000"]
load_balancing    = "p2c"
outlier_detection = { error_rate_pct = 50, min_requests = 20, window_secs = 10, eject_secs = 30, max_ejected_pct = 50 }
max_in_flight     = 600          # whole pool: ~200 per member

[upstream.billing]               # a single endpoint
url             = "http://10.0.1.9:8000"
circuit_breaker = { error_rate_pct = 50, min_requests = 20, window_secs = 10, open_secs = 30 }
max_in_flight   = 100
```

## What to alert on

```text
# A backend is shedding load: requests are being refused with 503 because it is at max_in_flight.
rate(zion_bulkhead_shed_total[5m]) > 0

# A member was ejected, or a circuit opened: something is failing in-band.
zion_upstream_ejected == 1
zion_upstream_circuit_open == 1

# The resolver is failing and zion is running on last-good addresses.
rate(zion_dns_stale_served_total[5m]) > 0

# Log lines are being dropped (the log sink is slower than the log rate).
rate(zion_log_lines_dropped_total[5m]) > 0

# Saturation before it sheds: in flight close to the limit.
zion_bulkhead_in_flight / zion_bulkhead_limit > 0.8

# The active health checker stopped: nothing marks a failed upstream down (or a
# recovered one up) any more. It runs at least once a second.
time() - zion_health_probe_last_round_timestamp_seconds > 30
```

## Trying it

```console
# a pool member that errors: watch it get ejected and the others keep answering
$ curl -sk https://zion.internal/metrics | grep -E 'upstream_(ejected|ejections_total|inflight)'   # from an internal IP

# a full bulkhead: the 503 carries the reason
$ curl -sk -D- -o /dev/null https://zion.example/api/x | grep -iE '^(HTTP|retry-after|x-zion-bulkhead)'

# a deploy: SIGTERM, then watch the connections drain
$ kill -TERM "$(pidof zion)"
```

See also: [Pools, outliers and the breaker](/config/#pools-load-balancing-and-outlier-detection),
[Hardening](/security/hardening), [Metrics](/deploy/observability).
