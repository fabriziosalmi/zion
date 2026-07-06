# Observability

## Health Endpoints

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

## Prometheus Metrics

`GET /metrics` returns counters in Prometheus text exposition format (`text/plain; version=0.0.4`).

### Counter Reference

| Metric | Type | Description |
|---|---|---|
| `zion_requests_total` | counter | Total HTTP requests processed |
| `zion_requests_by_status{class="2xx"}` | counter | Successful responses |
| `zion_requests_by_status{class="4xx"}` | counter | Client errors |
| `zion_requests_by_status{class="5xx"}` | counter | Server errors |
| `zion_waf_denied` | counter | Requests denied by WAF |
| `zion_rate_limited` | counter | Requests denied by rate limiter |
| `zion_cache_hits` | counter | Responses served from RAM cache |
| `zion_cache_misses` | counter | Cache misses (fetched from upstream) |
| `zion_websocket_upgrades` | counter | WebSocket upgrades completed |
| `zion_connections_total` | counter | Total TLS connections accepted |
| `zion_tls_handshake_errors` | counter | Failed TLS handshakes |

All counters are lock-free atomic `u64` values. Incrementing a counter costs ~2ns (single `fetch_add` with `Relaxed` ordering).

### Runtime Resource Gauges

`/metrics` also exposes process self-introspection gauges, so you can watch the daemon's own footprint live — and catch a slow leak (for example ~1 MB per 1000 connections) by its RSS slope, without restarting under a profiler.

| Metric | Type | Description |
|---|---|---|
| `zion_active_connections` | gauge | Currently active TLS connections |
| `zion_process_resident_memory_bytes` | gauge | Resident set size of the Zion process, in bytes (Linux `/proc/self/status` `VmRSS`; `0` on other platforms) |
| `zion_process_open_fds` | gauge | Open file descriptors held by the process (Linux `/proc/self/fd`; `0` on other platforms) |

The two `process_*` gauges are sampled from `/proc/self` **once per scrape** — the `/metrics` render is cached for one second, so the two small file reads never run on the hot connection path. The same values are surfaced in `/_zion/snapshot.json` and the `zion top` TUI ("rss" / "open fds" rows). They are Linux-only; on macOS/Windows they render as `0` so one dashboard works across hosts. Run `zion doctor` to confirm the host actually exposes `/proc/self/status` — a hardened container runtime that masks `/proc` will report `0` here, and the check warns you up front.

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: zion
    static_configs:
      - targets: ['zion-host:443']
    scheme: https
    tls_config:
      insecure_skip_verify: true  # if using self-signed certs
```

### Grafana Dashboard

An importable dashboard covering the whole fleet — golden signals, security,
TLS/upstream, and a **leak-watch** row (RSS slope + open FDs per instance) — is
committed at [`deploy/grafana/zion-overview.json`](https://github.com/fabriziosalmi/zion/blob/master/deploy/grafana/zion-overview.json).
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
```

## X-Request-ID

Every HTTPS response includes an `X-Request-ID` header for request tracing.

**Behavior**:
- If the incoming request contains `X-Request-ID`, Zion preserves it and echoes it back on the response
- If absent, Zion generates a unique ID in the format `{timestamp_hex}-{counter_hex}` (e.g., `191a2b3c4d5e-0042`)
- The ID is forwarded to the upstream in the request headers
- The same ID is added to the response headers for client correlation

The counter is a global atomic `u64`, ensuring uniqueness across all concurrent requests.

## Structured Logging

Configure log format in `[server]`:

```toml
[server]
log_format = "json"   # or "text" (default)
```

### Text Format (default, development)

```
config loaded from zion.toml
  route /api/{*rest} -> backend [waf=strict, cache=off]
ZION ONLINE.
```

### JSON Format (production)

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

## Upstream Health Monitoring

Zion runs a background health checker that pings all unique upstream URLs every 30 seconds:

- Sends `GET /` to each upstream
- Healthy = 2xx or 3xx response within 5 seconds
- State transitions (UP -> DOWN, DOWN -> UP) are logged
- Health state is stored as an atomic boolean per upstream

The health checker uses a separate HTTP client and does not affect the main proxy connection pool.
