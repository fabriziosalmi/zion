# Metrics & health endpoints

The operator-facing monitoring surface: health probes, the authoritative
Prometheus metric reference, the scrape config, and the Grafana dashboard. For
tracing, histogram exemplars, and the audit/mesh telemetry internals, see
[Observability internals](../guide/observability).

## Health endpoints

Zion exposes built-in endpoints that bypass routing and upstream forwarding:

| Endpoint | Response | Access | Purpose |
|---|---|---|---|
| `GET /healthz` | `200 ok` | public | Liveness probe (is the process alive?) |
| `GET /readyz` | `200 ready` | public | Readiness probe (is the process ready to serve?) |
| `GET /metrics` | Prometheus text format | **internal IPs only** (`403` otherwise) | Metrics scraping |
| `GET /_zion/snapshot.json` | JSON (metrics + quantiles + platform) | **internal IPs only** | `zion top` / dashboards |
| `POST /_zion/cache/purge` | `{"purged":N,"scope":...}` | **internal IPs only**, POST-only (`405` on GET) | Flush the RAM cache on deploy; `?prefix=/path` for scoped purge |

`/healthz` and `/readyz` are handled before rate limiting and routing, so they
always respond even under load. `/metrics`, `/_zion/snapshot.json`, and
`/_zion/cache/purge` are restricted to internal source IPs (external clients get
`403`).

## Prometheus metrics

`GET /metrics` returns counters in Prometheus text exposition format (`text/plain; version=0.0.4`).

### Counter reference

This table is the authoritative list — every counter `/metrics` emits appears
here. All are lock-free atomic `u64` (a `fetch_add` with `Relaxed` ordering,
~2 ns). Counters marked *(always emitted)* render even when their feature is off
(as a flat `0`), so one dashboard works across builds; the single genuinely
feature-gated series (absent, not zero, without the feature) is called out.

**Traffic & responses**

| Metric | Type | Description |
|---|---|---|
| `zion_requests_total` | counter | Total HTTP requests processed |
| `zion_requests_by_status{class="2xx"/"4xx"/"5xx"}` | counter | Responses by status class |
| `zion_config_generation` | counter | Config hot-reload generation (increments on every atomic swap) |
| `zion_websocket_upgrades` | counter | WebSocket upgrades completed |

**Cache**

| Metric | Type | Description |
|---|---|---|
| `zion_cache_hits` | counter | Responses served from RAM cache |
| `zion_cache_misses` | counter | Cache misses (fetched from upstream) |

**Security — WAF, rate limit, enforcement, tarpit**

| Metric | Type | Description |
|---|---|---|
| `zion_waf_denied` | counter | Requests blocked by the WAF |
| `zion_waf_shadow_would_block` | counter | Requests a shadow-mode WAF *would* have blocked (logged, not blocked) |
| `zion_rate_limited` | counter | Requests denied by the per-IP rate limiter |
| `zion_connections_rejected_per_ip` | counter | Connections rejected by the per-IP concurrent-connection cap (at accept) |
| `zion_enforcement_denied_total{reason="class"/"mesh_score"}` | counter | Sovereign-enforcement `403`s, by trigger |
| `zion_tarpit_active` | gauge | Connections currently held in the L7 tarpit |
| `zion_tarpit_total` | counter | Total requests held by the tarpit before rejection |
| `zion_tarpit_shed_total` | counter | Tarpit holds shed to a plain `403` when the global ceiling was hit |
| `zion_tarpit_held_ms_total` | counter | Cumulative ms connections were held by the tarpit (mean hold = `rate(held_ms)/rate(total)`) |

**Connections & TLS** — histograms below.

| Metric | Type | Description |
|---|---|---|
| `zion_connections_total` | counter | Total TLS connections accepted |
| `zion_tls_handshake_errors` | counter | Failed TLS handshakes |

**ACME** *(always emitted; `0` without `--features acme`)*

| Metric | Type | Description |
|---|---|---|
| `zion_acme_renewals_total` | counter | Certificates renewed |
| `zion_acme_renewal_failures_total` | counter | Renewal attempts that failed (sustained non-zero = certs will expire) |

**Mesh — AIMP** *(always emitted; `0` without `--features sovereign-aimp`)*

| Metric | Type | Description |
|---|---|---|
| `zion_mesh_claims_emitted_total` | counter | Mesh claims published from this node |
| `zion_mesh_claims_received_total` | counter | Claims received and merged into local state |
| `zion_mesh_claims_dropped_total{reason="signature"/"replay"/"rate"/"other"}` | counter | Inbound envelopes rejected, by reason |
| `zion_mesh_score_lookups_total` | counter | Dispatcher hits that found a mesh score for the client IP |
| `zion_mesh_gossip_bytes_in_total` | counter | Bytes received on the gossip socket |
| `zion_mesh_gossip_bytes_out_total` | counter | Bytes sent on the gossip socket |

**Reliability & internals**

| Metric | Type | Description |
|---|---|---|
| `zion_panics_total` | counter | Worker panics caught by the panic hook (must stay `0`) |
| `zion_audit_events_total` | counter | Audit-log events emitted (signed + HMAC-chained) |
| `zion_audit_events_dropped_total` | counter | Audit events dropped because the writer queue was full (alert on any drop) |
| `zion_traces_emitted_total` | counter | Request spans observed (one per request) |
| `zion_traces_invalid_total` | counter | Inbound `traceparent` headers rejected as malformed |
| `zion_admin_rejects_total` | counter | Admin-API requests rejected (auth or rate-limit) |

**Sovereign classification** *(feature-gated — absent without `--features geo-ita`/`geo-eu`)*

| Metric | Type | Description |
|---|---|---|
| `zion_sovereign_classifications_total{class="…"}` | counter | Requests classified by origin (IT/EU/unknown), by class |

### Histograms

Latency is exposed as Prometheus histograms — each emits `_bucket{le="…"}`,
`_sum`, and `_count` series; query with `histogram_quantile()`. In OpenMetrics
output they also carry trace-ID exemplars.

| Metric | Description |
|---|---|
| `zion_request_duration_seconds` | End-to-end request latency (client-facing) |
| `zion_upstream_duration_seconds` | Time spent waiting on the upstream |
| `zion_tls_handshake_duration_seconds` | TLS handshake duration |

### Runtime resource gauges

`/metrics` also exposes process self-introspection gauges, so you can watch the daemon's own footprint live — and catch a slow leak (for example ~1 MB per 1000 connections) by its RSS slope, without restarting under a profiler.

| Metric | Type | Description |
|---|---|---|
| `zion_active_connections` | gauge | Currently active TLS connections |
| `zion_process_resident_memory_bytes` | gauge | Resident set size of the Zion process, in bytes (Linux `/proc/self/status` `VmRSS`; `0` on other platforms) |
| `zion_process_open_fds` | gauge | Open file descriptors held by the process (Linux `/proc/self/fd`; `0` on other platforms) |

The two `process_*` gauges are sampled from `/proc/self` **once per scrape** — the `/metrics` render is cached for one second, so the two small file reads never run on the hot connection path. The same values are surfaced in `/_zion/snapshot.json` and the `zion top` TUI ("rss" / "open fds" rows). They are Linux-only; on macOS/Windows they render as `0` so one dashboard works across hosts. Run `zion doctor` to confirm the host actually exposes `/proc/self/status` — a hardened container runtime that masks `/proc` will report `0` here, and the check warns you up front.

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: zion
    static_configs:
      - targets: ['zion-host:443']
    scheme: https
    tls_config:
      insecure_skip_verify: true  # if using self-signed certs
```

### Grafana dashboard

An importable dashboard covering the whole fleet — golden signals, security,
TLS/upstream, a **leak-watch** row (RSS slope + open FDs per instance), protocols
& tarpit detail, the **AIMP mesh**, and a **reliability & internals** row
(panics / dropped audit events / admin rejects). Every metric `/metrics` exposes
has a panel. It is committed at
[`deploy/grafana/zion-overview.json`](https://github.com/fabriziosalmi/zion/blob/master/deploy/grafana/zion-overview.json).
Grafana → Dashboards → Import → upload the JSON → pick your Prometheus source.
See [`deploy/grafana/README.md`](https://github.com/fabriziosalmi/zion/blob/master/deploy/grafana/README.md).

The raw PromQL, if you'd rather build your own panels or alerts:

```text
# Request rate
rate(zion_requests_total[5m])

# Error rate
rate(zion_requests_by_status{class="5xx"}[5m])

# WAF deny rate
rate(zion_waf_denied[5m])

# Cache hit ratio
zion_cache_hits / (zion_cache_hits + zion_cache_misses)

# TLS handshake failure rate
rate(zion_tls_handshake_errors[5m])

# Memory-leak slope: RSS growth rate over 30m. A sustained positive
# slope under flat request traffic is the silent-leak signal.
deriv(zion_process_resident_memory_bytes[30m])

# File-descriptor leak: open fds climbing without bound (alert if it
# approaches the `zion doctor` fd soft limit).
zion_process_open_fds

# Panics — must stay flat 0; page immediately on any non-zero rate.
rate(zion_panics_total[5m])

# Audit-log gaps — alert on any dropped event (the HMAC chain has holes).
rate(zion_audit_events_dropped_total[5m])

# Tarpit mean hold time (ms) — how long a flooding source is stalled.
rate(zion_tarpit_held_ms_total[5m]) / clamp_min(rate(zion_tarpit_total[5m]), 1)

# Mesh: inbound envelopes dropped by reason (spike in signature/replay = a
# probing peer). Requires --features sovereign-aimp; flat 0 otherwise.
sum by (reason) (rate(zion_mesh_claims_dropped_total[5m]))
```

## X-Request-ID

Every HTTPS response includes an `X-Request-ID` header for request tracing.

**Behavior**:
- If the incoming request contains `X-Request-ID`, Zion preserves it and echoes it back on the response
- If absent, Zion generates a unique ID in the format `{timestamp_hex}-{counter_hex}` (e.g., `191a2b3c4d5e-0042`)
- The ID is forwarded to the upstream in the request headers
- The same ID is added to the response headers for client correlation

The counter is a global atomic `u64`, ensuring uniqueness across all concurrent requests.

## Structured logging

Configure log format in `[server]`:

```toml
[server]
log_format = "json"   # or "text" (default)
```

### Text format (default, development)

```text
config loaded from zion.toml
  route /api/{*rest} -> backend [waf=strict, cache=off]
ZION ONLINE.
```

### JSON format (production)

```json
{"ts":"1712000000","level":"info","event":"config","msg":"loaded from zion.toml"}
{"ts":"1712000000","level":"info","event":"shutdown","msg":"signal received, draining..."}
```

JSON logs are structured for ingestion by Loki, ELK, Datadog, or any log aggregator. Fields:

| Field | Description |
|---|---|
| `ts` | Unix timestamp (seconds) |
| `level` | `info`, `warn`, or `error` |
| `event` | Event category (e.g., `config`, `health`, `shutdown`, `tls`) |
| `msg` | Human-readable message |

## Upstream health monitoring

Zion runs a background health checker that pings all unique upstream URLs every 30 seconds:

- Sends `GET /` to each upstream
- Healthy = 2xx or 3xx response within 5 seconds
- State transitions (UP -> DOWN, DOWN -> UP) are logged
- Health state is stored as an atomic boolean per upstream

The health checker uses a separate HTTP client and does not affect the main proxy connection pool.
