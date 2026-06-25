# Zion edge baseline — benchmark + RFC conformance + cache-correctness

A reproducible harness that measures zion's data-path throughput/latency, its
HTTP/2 + TLS protocol conformance, and the correctness of the cache (the v0.4.2
`Age`/origin-TTL fix), then renders a tracked PDF. Establishes the release
"minimum bar" and a cross-version regression baseline on identical hardware.

## What it runs

| Dimension | Tool | What it checks |
|---|---|---|
| HTTP/2 conformance | [`h2spec`](https://github.com/summerwind/h2spec) | RFC 9113 / 7540 |
| TLS conformance | [`testssl.sh`](https://testssl.sh) | protocols, ciphers, FS, CVE probes |
| Throughput (cache / proxy) | `oha` | median of N trials + p50/p99/p99.9 + CPU%/RSS/req-per-core |
| Comparison | `nginx` (proxy_cache) | same box / cert / payload reference point |
| Protocol-pinned | `h2load` (H2), `wrk` (H1), `wrk2` (CO-corrected) | per-protocol cross-check |
| Concurrency sweep | `oha` | latency/throughput curve (saturation knee) |
| Payload matrix | `oha` | 1 KB / 64 KB / 1 MB bodies |
| Cache-correctness | `curl` + `/metrics` | `Age` present + monotonic; origin TTL honoured; stale-born passthrough; hit-ratio under load |

Lab topology: `client → zion (TLS :4432, min 1.2, memory cache) → Go bench-backend (:9090)`,
plus an optional `nginx (:4433, proxy_cache)` for comparison. Config:
[`zion-lab.toml`](zion-lab.toml). Mirrors the production edge profile (TLS floor
1.2, memory cache, no WAF).

## Reproduce

```bash
# authoritative run (isolated host; ≥4 cores recommended so load can be pinned off the server cores)
MODE=full  bash benchmarks/baseline/run-baseline.sh    # → benchmarks/baseline/zion-<version>-baseline.pdf

# fast pipeline check
MODE=smoke bash benchmarks/baseline/run-baseline.sh
```

Knobs (env, all have defaults): `MODE` (full|smoke), `TRIALS`, `DURATION`,
`CONNS`, `SWEEP`, `PAYLOADS`, `ZION_CPUS`/`LOAD_CPUS` (taskset pinning; auto-split
the allowed cpuset by default, skipped if <4 CPUs), `REPORT=0` (measure only —
the LXC produces `results/`, render the PDF on a host with weasyprint+matplotlib).

### Prerequisites

```bash
# macOS
brew install oha nghttp2 wrk testssl jq weasyprint
# Linux (Debian): apt install golang-go nghttp2-client wrk nginx jq ; cargo install oha ; (wrk2 from source)
# h2spec (no package): release binary into ~/http-tools/  — https://github.com/summerwind/h2spec/releases
```

`cargo`, `go`, `openssl`, `python3` required. Optional legs (nginx, wrk2, h2spec,
testssl, matplotlib) are **SKIP-logged** if absent, never a hard failure.

## Rigor notes

- **Multi-trial + 95% CI**: throughput is the median of `TRIALS` runs with a CI,
  so run-to-run variance is visible rather than hidden behind a single sample.
- **CPU pinning**: on Linux the allowed cpuset is auto-split (server | load) so
  the load generator can't steal the server's cores. Skipped on <4 CPUs (logged);
  there the throughput is "co-located, small-box indicative", not a peak.
- **Self-signed cert artifacts**: testssl flags chain-of-trust / grade as HIGH
  because the lab cert is self-signed; the report separates those from genuine
  crypto/protocol findings. Production serves a CA cert.
- **nginx CPU/RSS** are sampled on the master PID (workers do the work), so they
  read low — the req/s comparison is the valid signal.
- **Loopback numbers** measure server-side efficiency, not WAN; they are a
  cross-version regression baseline. The network-realistic distributed numbers
  live in [`benches/e2e/`](../../benches/e2e/).
- Every figure in the PDF is parsed from a raw tool output embedded verbatim in
  the report appendix — nothing hand-entered.

## Files

- `run-baseline.sh` — orchestrator. `lib.sh` — `/proc`-accurate CPU/RSS sampling.
- `build-report.py` — parses `results/` → `report.html` (PDF via the WeasyPrint CLI).
- `zion-lab.toml` — lab config (tracked). `zion-<version>-baseline.pdf` — the deliverable.
- `results/` + `report.html` — gitignored (raw evidence is embedded in the PDF).
