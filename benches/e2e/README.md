# benches/e2e — draconian end-to-end benchmark

Real-FQDN, real-TLS, **two-physical-node** Proxmox benchmark of Zion as a
production edge: a separate load box hammers Zion over the wire (TLS 1.3,
real Let's Encrypt cert) while Prometheus records the SUT. Designed to produce
**honest** numbers — every run is CPU-attributed so we never report the
load-generator's ceiling as Zion's.

**Read [RESULTS.md](RESULTS.md) for the measured numbers.** Highlights (Zion on
**2 Skylake vCPU**, WAF scanning every request, TLS 1.3):

- **96 k req/s** cache+WAF+TLS · **43 k req/s** proxy+WAF+TLS · RSS ~40 MB
- **origin self-heal 30 s → 1.4 s** (~21×, adaptive decorrelated-jitter recovery)
- **RSS flat (OLS −26 MB/h)** under a 4.67 M-request mixed attack while serving
  4.66 M legit cache-hits — 0 panics

## Topology

```
 node2 (i7-3770, 8 cores)            node1 (i7-6700 Skylake, 4 cores)        node3
 ┌────────────────────────┐   1GbE  ┌───────────────────────────────┐   ┌──────────────┐
 │ zion-attacker (9101)    │ ──────► │ zion-target (9001)            │   │ observer     │
 │   wrk / vegeta / h2load │  TLS    │   Zion  → cores 0,1 (pinned)   │◄──│  Prometheus  │
 │   8 cores (never the    │  1.3    │   nginx origin → core 2        │   │  Grafana     │
 │   bottleneck)           │         │   (real LE cert, AVX2/BMI2)    │   │  (.223)      │
 └────────────────────────┘         └───────────────────────────────┘   └──────────────┘
 demo.italiacdn.net → .221 (/etc/hosts)        SUT pinned, isolated         scrape 2s
```

The Skylake node is the SUT specifically because Zion's release binary is built
with AVX2/BMI2 and **cannot run** on the 2012 Ivy-Bridge node — which therefore
makes the perfect load generator (stock `wrk`/`vegeta` run fine on it).

## Layout

- `env.sh` — single source of truth (hosts, container IDs, IPs, Prometheus URL).
- `lib/orchestrate.sh` — control-host helpers (run-on-attacker, run-on-SUT,
  Prometheus instant/range queries, CPU sidecar).
- `scenarios/00_smoke.sh` — S0 GO/NO-GO preflight (cert, payload hashes, WAF
  boundary, Prometheus health). Run this first.
- `scenarios/03_throughput_grid.sh` — payload × concurrency keep-alive grid.
- `config/zion-fullstack.toml` — the "everything on" lane (TLS+WAF+static cache;
  limiters off so a single benchmark IP isn't throttled — the limiter/per-IP cap
  are exercised in a separate security lane).

## How to run

From a control host with SSH to both Proxmox nodes and LAN reach to the
container IPs:

```bash
source benches/e2e/env.sh
source benches/e2e/lib/orchestrate.sh
atk_push_run benches/e2e/scenarios/00_smoke.sh   # must print "S0 RESULT: GO"
```

## Honest caveats (see RESULTS.md for the full list)

Co-located origin (localhost upstream hop ⇒ optimistic vs a remote origin);
single attacker IP (per-IP cap proves enforcement, not cross-IP fairness);
**1 GbE inter-node link bounds payloads ≥ 10 KB** (so small-payload numbers are
the CPU ceiling, large-payload numbers are the link); Zion's latency histogram
is coarse power-of-2 — vegeta is the authoritative latency source.
