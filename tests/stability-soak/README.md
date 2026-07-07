# Stability soak

A front door runs for weeks. A per-request or per-reload leak that a unit test
never sees becomes an OOM kill or an fd-exhaustion page in production. This
soak drives a real Zion with the traffic shapes that exercise every
leak-prone surface, samples its own `zion_process_resident_memory_bytes` and
`zion_process_open_fds` over time, and **fails if RSS climbs past a budget or
fds grow without bound**. It is the automated form of the dashboard's
`deriv(RSS[30m])` leak-watch row.

## What it stresses (and why each matters)

A leak-surface investigation traced every request-reachable structure; all are
bounded (route cache 256/worker LRU, response cache by `max_entries`, rate map
fail-closed at 100k + a 60s scavenger, per-IP conn map self-cleaning, and the
reload `ArcSwap` snapshot freed by refcounting once readers drain). So a
correct build must show a **flat** slope — the soak is a regression guard, not
a bug hunt. The generators keep each of those paths hot:

| Generator | Traffic | Surface exercised |
|---|---|---|
| **G1** | random `Host` + `path` + `X-Forwarded-For` per request, alternating a cached GET and a WAF-scanned POST, each on a fresh TLS connection | route cache LRU eviction · response cache fill→evict · WAF body scan · per-resolved-IP rate map · connection/fd churn |
| **G3** | open the TLS port and close/RST immediately | handshake-error drop path (fd release on failed connect) |
| **G6** | rewrite `zion.toml` between two bodies (different upstream set + route shape) and `POST /admin/reload`, repeatedly | the `ArcSwap` snapshot + router radix-tree + health-map alloc/free lifecycle |

The one traffic-reachable fd risk the investigation found — an unbounded await
on the WebSocket upgrade handoff — was fixed separately (`proxy.rs`, bounded to
30s). Two genuinely-unbounded but non-request-reachable structures (the AIMP
mesh reputation table, off by default + signature-gated; the append-only audit
log on disk, off by default) are out of scope and tracked in their own issues.

## The verdict

- **RSS:** least-squares slope over the post-warm-up window (the first `WARMUP`
  seconds are excluded — RSS legitimately ramps as caches and pools fill;
  that's bounded, not a leak). But a bounded ramp can still be *mid-climb* at
  the window's end on a short gate, so the whole-window slope alone would flag
  it. The discriminator: a bounded process **decelerates** toward a plateau,
  a leak **sustains** its slope. So we also fit the **tail** (last 60% of
  samples) and FAIL only if the tail slope is (1) statistically significant
  (`> 3·SE`), (2) over budget (≥ `RSS_BUDGET_BPS` and a 24h extrapolation ≥
  `RSS_BUDGET_PCT`% of steady RSS), **and** (3) still ~as steep as the overall
  slope (`tail/overall ≥ 0.5` — i.e. not settling). A decelerating ramp or a
  noise-band trend passes. The raw per-sample table is printed to the log so
  the curve shape is auditable, not just the summary slope.
- **fds:** bounded range and no decile-over-decile drift — a leaked socket
  shows as a clean upward staircase.
- **reloads:** the config generation must have advanced under load (else the
  swaps didn't overlap the traffic and the Arc lifecycle wasn't tested).

## Linux only

The RSS/fd gauges are read from `/proc/self` and are **0 on macOS/Windows**
(`metrics.rs` gates them on `target_os = "linux"`). The harness hard-fails if
it reads 0 (not Linux, or `/proc` is masked) rather than passing vacuously.

Run it locally from a Mac in a Linux container (Docker Desktop's VM has a real
`/proc`), do not mask `/proc`, and don't set a `--memory` so tight the OOM
killer fires:

```console
$ docker run --rm --platform linux/amd64 -v "$PWD":/w -w /w rust:1.96-bookworm \
    bash -lc 'apt-get update && apt-get install -y curl gawk openssl \
      && DURATION=1800 WARMUP=300 ./tests/stability-soak/run.sh'
```

## CI

`.github/workflows/stability-soak.yml`: a **fast gate** (~2 min) on any change
to the leak-prone paths catches gross regressions; a **nightly** ~2h soak on a
cron is the authoritative slope/fd verdict and uploads `soak-samples.tsv` as a
14-day artifact. Both on `ubuntu-latest` (GitHub-hosted jobs run up to 6h).

Tunables (env): `DURATION WARMUP INTERVAL WORKERS RELOADS CARDINALITY
MAX_ENTRIES RATE_LIMIT_RPS RSS_BUDGET_BPS RSS_BUDGET_PCT FD_MARGIN FD_DRIFT`.
