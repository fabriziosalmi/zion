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
  renewals-vs-failures and sovereign classifications round it out (both no-ops
  unless the matching feature is built in).

## Note on optional metrics

Some panels reference metrics that only appear with a feature: `zion_acme_*`
(`--features acme`) and `zion_sovereign_*` (`--features geo-ita`/`geo-eu`).
Those panels stay empty on a default build — that's expected, not a
misconfiguration.

The raw PromQL for each panel is also listed in
[`docs/deploy/observability.md`](../../docs/deploy/observability.md) if you'd
rather build your own panels or wire alerts.
