# Zion — draconian e2e benchmark results

Real-FQDN, real-TLS, two-physical-node Proxmox testbed. Every number below is
end-to-end over the wire (attacker → Zion :443 TLS 1.3 → origin), captured with
Prometheus + wrk/vegeta. See [TOPOLOGY.md](TOPOLOGY.md) for the rig and the
honest caveats.

## Testbed (one-paragraph)

- **SUT** — Zion `v0.3.x` (master), LXC on node1 (**Intel i7-6700 Skylake**,
  AVX2/BMI2), **pinned to 2 dedicated cores**; nginx origin co-host on a 3rd
  core; real Let's Encrypt cert (`CN=demo.italiacdn.net`, TLS 1.3,
  `TLS_AES_256_GCM_SHA384`, ALPN h2).
- **Load generator** — separate physical node2 (Intel i7-3770, **8 cores**),
  `wrk`/`vegeta`/`h2load`. (The 2012 Ivy-Bridge node lacks AVX2 and *cannot*
  run Zion's AVX2/BMI2 release binary — which is exactly why it is the load
  box and the Skylake node is the SUT.)
- **Observer** — Prometheus (2 s scrape) + Grafana on node3.
- Binary: `cargo build --release` (`opt-level=3`, **fat LTO**, `codegen-units=1`,
  `target-cpu=native`). Validity gate enforced on every run: a throughput
  number counts only if **Zion ≈ 190–200 % CPU (both cores pegged) while the
  attacker keeps ≥ 15 % idle** — otherwise it is the load-gen's ceiling, not
  Zion's.

## Headline numbers (2 Skylake vCPU)

### Throughput — full stack, WAF scanning every request, TLS 1.3

| Path | Mode | req/s | p50 | p99 | RSS |
|---|---|--:|--:|--:|--:|
| `/static/*` | **cache + WAF + TLS** | **96,029** | 1.99 ms | 3.59 ms | ~40 MB |
| `/` | **proxy + WAF + TLS** | **42,871** | 4.63 ms | 6.79 ms | ~42 MB |

- Cache-served path is **2.24× the proxy path** — WAF scans every request, but a
  hit is served from RAM with no origin round-trip. Proven by
  `zion_cache_hits` climbing **+1.92 M** during a 20 s run (≈ 96 k/s × 20 s).
- **Validity**: at the ceiling Zion sat at ~191 % CPU while the 8-core attacker
  stayed ~79 % idle → the number is Zion's, not the load-gen's.
- `target-cpu=native` ≈ `x86-64-v3` here (Skylake has no AVX-512) — within run
  noise; the cache (not the µ-arch flag) is the real lever.
- **Network caveat**: payloads ≥ 10 KB are bounded by the **1 GbE** physical
  link between the two nodes (~900 Mbps), *not* by Zion — so the small-payload
  numbers above are the CPU ceiling; large-payload throughput is a testbed
  link limit (future work: a dedicated ≥ 2.5 G inter-node link).

### Origin self-heal — adaptive decorrelated-jitter recovery (PR #173)

Measured live: stop the origin, wait for Zion to serve 503, restart the origin,
time until Zion serves 200 again (recovery = DOWN→UP, isolated from detection).

| Build | Recovery (DOWN→UP) |
|---|--:|
| Before — fixed 30 s probe | **29.79 s** |
| After — decorrelated jitter (100 ms→3 s) | **~1.4 s** (1.305 / 1.376 / 1.443) |

**≈ 21× faster self-heal.** Log-corroborated: `is DOWN — adaptive re-probe in
~192ms` → `is UP (257us)`. Steady-state healthy probe cadence unchanged (30 s),
so zero happy-path regression.

### Resilience under attack — "lo prendi a martellate, non si scompone"

180 s concurrent mixed load: legit cache traffic + a malicious stream tripping
the WAF (URI SQLi `' or 1=1`). Both streams pinned on the 8-core attacker.

| Stream | req/s | outcome |
|---|--:|---|
| legit (`/static`, cache+WAF) | **25,909** | 100 % 200, 0 socket errors |
| malicious (URI SQLi) | **25,962** | **100 % blocked** — 4,673,284 / 4,673,284 non-2xx (HTTP 400) |

→ **~52 k req/s mixed** sustained: ~4.66 M legit cache-hits served **while**
~4.67 M attacks were WAF-denied, concurrently.

**RSS stayed flat** (41 samples, 5 s step over 202 s): settled to **32 MB**
within ~10 s and held — `min 31.3 / mean 32.3 / max 39.0 MB`,
**OLS slope = −26 MB/hour** (≈ 0, drifting *down* — no leak).
`zion_panics_total = 0`, `open_fds = 20` (bounded — no fd leak),
`tls_handshake_errors` negligible.

```
RSS MB over the 180s attack:  39 33 32 32 32 ... 32 32 31   (flat)
```

The thesis, measured: under a 4.67 M-request attack Zion's working set does not
grow, it keeps serving legit traffic at full cache speed, and it never panics.
*Lo prendi a martellate, non si scompone.*

## Caveats (full list)

- Co-located origin (localhost hop → optimistic upstream latency vs a remote
  origin); single attacker IP (per-IP cap proves *enforcement*, not cross-IP
  *fairness*); coarse power-of-2 Zion latency histogram (vegeta is the
  authoritative latency source); 1 GbE inter-node link bounds large payloads.
