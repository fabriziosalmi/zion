# Release report: performance and HTTP conformance, one PDF per version

```bash
benchmarks/report/provision.sh                    # once, on the benchmark host
benchmarks/report/report.sh v0.11.0               # build the tag, measure, test, render
benchmarks/report/report.sh v0.12.0 --prev v0.11.0
```

The result is `reports/<ref>/zion-<ref>-report.pdf` and the JSON it was rendered from. A
report answers three questions about one release, on the same host, with the same procedure
as every earlier one:

1. **How fast is it, per core, next to nginx?** An example web site is served by a real
   nginx origin; zion is put in front of it; a real nginx with `proxy_cache` is put in
   front of the same origin as the reference; the origin read directly is the floor.
2. **Does it speak HTTP correctly?** About fifty checks of RFC 9110/9111/9112 (framing and
   request smuggling, hop-by-hop headers, validators, ranges, path traversal, TLS), `h2spec`
   for HTTP/2, and Mark Nottingham's `cache-tests` for RFC 9111, each run against zion and
   against nginx.
3. **Did it change since the last release?** A table of CPU per request, judged only beyond
   the tolerance *and* the measured noise.

It complements [`../regress/`](../regress/), which answers "did this commit make that code
path slower" in ten minutes on a build, and replaces [`../baseline/`](../baseline/), the
v0.4.2 harness.

## What "deterministic" means here

A CPU is not deterministic, so the numbers are not bit-identical from run to run. What the
harness fixes, and records in the report, is everything else:

| Fixed | How |
|---|---|
| The bytes served | `gen_site.py`: its own PRNG (SplitMix64), no clock, no `random`; the site's SHA-256 is in the report and in a unit test |
| The requests sent | Zipf over the manifest from a seeded PRNG per wrk thread; fixed paths elsewhere |
| The tools | `provision.sh` pins wrk, h2load, oha, h2spec, nginx, node, cache-tests (commit) and the Python packages (`requirements.lock`); the report prints `tools.lock` |
| The cores | origin on CPU 0, the proxy under test on CPU 1, load generators on 2-3. One core per proxy, so req/s is per core and nginx runs `worker_processes 1` |
| The order | trials interleaved across targets (zion, nginx, origin, zion, …), so drift hits all alike; each trial starts the proxy cold and warms it before timing |
| The procedure | `PROCEDURE` in `bench.py` and a hash of the harness files are in the result; reports of different procedures are not compared |

What the harness measures, so that noise is a number and not an excuse: a **canary**, a fixed
CPU workload, brackets the run; more than 3 % drift marks the report *noisy*. The host must be
97 % idle for five seconds before anything is timed. Every trial is **validated** (any non-2xx
or transport error discards it; a "cache hit" scenario is only reported if the origin saw
almost no requests, which is also how it is proved that hits were hits). Results are
medians with min–max, and a version-to-version change counts only beyond 5 % *and* three times
the noise of both measurements.

The PDF is reproducible from the JSON: vector charts, text converted to outlines, no
timestamp, content-derived PDF id. Rendering twice gives the same bytes.

## What is measured

Throughput on one core, TLS on loopback: a cached 5 KB document (HTTP/1.1 and HTTP/2), a
cached 200 KB image, the whole site in a Zipf mix, no cache (proxy only), files served from
disk, a new TLS handshake per request, a 10 MiB body, a concurrency sweep (1 to 1024), the
access log on in both, and latency at a fixed 5 000 and 15 000 req/s corrected for
coordinated omission. Per scenario: req/s, CPU µs per request (from `/proc`, for the whole
process tree), p50/p99/p99.9, server CPU %, peak RSS, cache hit ratio.

## Limits, said plainly

- Loopback on one machine: what the proxy *costs*, not a network.
- The host is an LXC on a shared hypervisor with turbo frequencies; the canary and the
  min–max are there because of it. Repeat a run you doubt.
- Not measured: HTTP/3, the WAF, rate limiting, response compression (zion has none yet,
  #474), WebSocket, multi-core scaling, long-duration memory (the soak workflow does that).
- `cache-tests` calls itself "not a conformance test suite": its counts include optional
  behaviour. Read the differences between zion and nginx, not the totals.
- With the access log on, zion's log writer shares the single core, which overstates the log's
  cost against a multi-core deployment. µs per request is the figure to read.

## Files

| File | Role |
|---|---|
| `provision.sh` | installs the pinned tools on the host (idempotent) |
| `report.sh` | one release: ship, build, measure, test, render, fetch |
| `gen_site.py` | the example site, deterministic to the byte |
| `bench.py` | the benchmark: rig, scenarios, trials, validation, `result.json` |
| `wrk.lua` | request mix and the percentile line `wrk` does not print |
| `conformance.py`, `probe_origin.py` | the HTTP checks and the origin that sends malformed messages |
| `external.py`, `ct-summary.mjs` | h2spec, cache-tests, the byte-exact crawl |
| `render.py` | JSON → HTML → PDF |
| `test_report.py` | unit tests: site hash, PRNG, parser, probe origin, judge |
