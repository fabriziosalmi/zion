# Zion — Grafana dashboard

`zion-overview.json` is an importable Grafana dashboard for a Zion fleet. It
answers, at a glance, the question a fleet operator actually asks — *are all my
proxies healthy right now?* — using the metrics Zion already exposes at
`/metrics`. No exporter, no sidecar: point Prometheus at the endpoint and
import the JSON.

## Import

1. Scrape Zion (`docs/deploy/observability.md` has the full snippet):

   ```yaml
   scrape_configs:
     - job_name: zion
       scheme: https
       tls_config: { insecure_skip_verify: true }  # self-signed certs
       static_configs:
         - targets: ['zion-a:443', 'zion-b:443']    # your fleet
   ```

2. Grafana → **Dashboards → New → Import** → upload `zion-overview.json` →
   pick your Prometheus data source.

3. Use the **Instance** variable (top-left) to focus one proxy or watch the
   whole fleet at once.

## What it shows

- **Fleet at a glance** — request rate, 5xx ratio, p99 latency, active
  connections, cache hit ratio, and the config-generation counter (so you can
  see which proxy last hot-reloaded).
- **Traffic** — request rate by instance, response classes (2xx/4xx/5xx),
  latency p50/p95/p99.
- **Security** — WAF denials vs shadow would-block, rate-limit / enforcement /
  per-IP rejects, tarpit activity.
- **Upstream, TLS & connections** — upstream latency quantiles, TLS handshake
  error rate and duration, accept rate and active connections.
- **Fleet health — leak watch** *(the dogfooding-critical row)* — RSS and open
  file descriptors per instance, plus an **RSS leak-slope** panel
  (`deriv(...[30m])`): a persistently positive slope while request rate is flat
  is the silent memory-leak signal a front door must never hide. ACME
  renewals-vs-failures and sovereign classifications round it out.
- **Protocols & tarpit detail** — WebSocket upgrade rate, and tarpit requests
  held/s plus mean hold time (`rate(zion_tarpit_held_ms_total)/rate(zion_tarpit_total)`).
- **Mesh — AIMP fleet gossip** — mesh claims emitted/received/score-hits, claims
  dropped by reason (signature / replay / rate / other), and gossip bandwidth
  in/out. Flat at 0 unless the node runs `--features sovereign-aimp`.
- **Reliability & internals** — panics/s (must stay flat 0), audit-log events vs
  **dropped** (alert on any drop — the HMAC chain has gaps), trace emit/invalid,
  and admin-API rejects.

Every metric Zion exposes at `/metrics` has a panel here.

## Note on optional metrics

Two panels depend on a feature and read absent on a default build (that's
expected, not a misconfiguration): `zion_sovereign_classifications_total`
(`--features geo-ita`/`geo-eu`) is genuinely `#[cfg]`-gated. The `zion_acme_*`
and `zion_mesh_*` metrics are **always emitted** — they render as a flat `0`
line until you build with `--features acme` / `sovereign-aimp` respectively, so
their panels show zero rather than "no data".

The raw PromQL for each panel is also listed in
[`docs/deploy/observability.md`](../../docs/deploy/observability.md) if you'd
rather build your own panels or wire alerts.
