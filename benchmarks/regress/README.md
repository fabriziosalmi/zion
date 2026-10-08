# Performance regression harness

One release binary, seven data paths, and numbers that say whether a change made
zion slower or faster. It exists so that "performance unchanged" (a refactor of the
request pipeline, #529 to #531) and "30 % less CPU" (the cache, the static server,
the upstream pool: #564, #571, #577) are both claims with a measurement behind them,
taken the same way before and after.

It is not the release report. [`../baseline/`](../baseline/) is that (nginx
comparison, RFC conformance, a PDF). This answers one narrower question, in about ten
minutes, and refuses to report a number from a run that was not valid.

```bash
# on the Linux box (see "Where it runs"), from a checkout of the repo:
python3 benchmarks/regress/run.py --zion target/release/zion --out new.json --label my-change
python3 benchmarks/regress/compare.py benchmarks/regress/baselines/v0.9.13-ci-zion-A.json new.json
```

`compare.py` exits 1 when a scenario got worse in CPU per request or in throughput
beyond the noise.

## What it runs

zion is started once per scenario (so memory and cache state do not leak from one
to the next), warmed, settled for two seconds, then measured for `--trials` windows
(default 7) of `--duration` seconds (default 10). The load is `h2load`, HTTP/2 over
TLS 1.3, so the real pipeline runs: the plaintext `:80` handler is a different code
path and is not measured.

| Scenario | What it exercises |
|---|---|
| `cache_hit_1k` | one hot 1 KiB object served from the cache: routing, gates, lookup, response |
| `cache_hit_2000_keys` | the same with 2,000 distinct keys: the shared tier, not one hot entry |
| `proxy_1k` | no cache: the pipeline and one upstream round trip |
| `waf_post_json` | the pipeline with the WAF scanning a small JSON body |
| `uri_normalise` | 500 distinct paths with dot segments, doubled slashes and percent-encodings |
| `static_1m` | a 1 MiB file from disk (above the 576 KiB one-shot threshold: the streamed path) |
| `static_10m` | a 10 MiB file |

The backend is the Go `benchmarks/backend`, a fixed-size response. Zion and the
backend plus the load generator are pinned to separate CPUs (`taskset`; the first
half of the CPUs for zion, the second half for the rest) when the box has at least 4.

## What it reports

| Metric | Meaning |
|---|---|
| `cpu_us_per_req` | CPU time zion spent per request, from `/proc/<pid>/stat` around the measured window. **The number to trust**: it barely moves with the box's load or the load generator's speed |
| `rps` | requests per second |
| `mean_ms` | mean request latency (h2load does not report percentiles) |
| `server_cpu_pct` | how busy zion's cores were. Below about 80 % the load generator was the limit and `rps` says nothing about zion: `compare.py` marks it and does not judge it |
| `rss_hwm_mib` | peak resident memory over the scenario (`VmHWM`). Information only: it moves several percent between sessions |

Each trial is checked. A trial with any non-2xx status, failed, errored or timed-out
request aborts the run: a benchmark of an error path is not a benchmark.

## How big a difference means something

Two sessions of the same binary (v0.9.13, built from the tag, on the box below), run
back to back and compared:

| Scenario | CPU per request | req/s |
|---|---|---|
| `cache_hit_1k` | +0.7 % | −0.5 % |
| `cache_hit_2000_keys` | +2.5 % | −2.3 % |
| `proxy_1k` | −0.1 % | −0.0 % |
| `waf_post_json` | −0.0 % | −0.3 % |
| `uri_normalise` | +0.6 % | −0.2 % |
| `static_1m` | −0.6 % | +0.6 % |
| `static_10m` | +2.2 % | −2.5 % |

The largest drift between sessions is 2.6 %. `compare.py` calls a change real only
when it is beyond **both** the tolerance (`--tolerance`, default 5 %) and three
standard deviations of the noise of the two results (estimated from their MAD): for
`cache_hit_2000_keys` that comes out at about 10 %, for the others at the tolerance.
A change smaller than that is not a result of the harness, whichever way it points.

It does detect a regression: the same binary with its server pinned to one core
instead of two makes `compare.py` report `req/s` at −46 % (`worse`, exit status 1).
CPU per request did not rise (it read 3 to 5 % lower; I did not look into why), which
is why throughput is judged as well, and only when the server was busy.

The two committed results are in [`baselines/`](baselines/): `A` is the one to
compare against, `B` is the second session that gave the table above. Take a new
baseline with each release, from the tag, on the same box.

## Where it runs

On Linux, on a box that is otherwise idle: it reads `/proc`. The results above are from
the `ci-zion` LXC (4 cores of an Intel i7-6700, `h2load` from nghttp2 1.59): not a
GitHub runner, whose neighbours make a throughput number meaningless. Two results from
different machines are not comparable and `compare.py` says so.

To measure a ref:

```bash
git archive <ref> | ssh box 'mkdir -p zion-ref && tar -x -C zion-ref'
ssh box 'cd zion-ref && cargo build --release --locked --features dist'
ssh box 'cd zion && python3 benchmarks/regress/run.py --zion ~/zion-ref/target/release/zion --out /tmp/ref.json --label <ref>'
```

Requirements: `h2load` (`apt install nghttp2-client`), `go` (for the backend), `openssl`,
`python3`, `taskset`. `--quick` runs 2 trials of 3 seconds: a check that the harness
works, not a measurement.

## The weekly paired run

`.github/workflows/perf-regression.yml` runs every Monday on a GitHub runner: it builds the
latest `v*` tag and master, measures each twice in turn (base, new, base, new) on the same
runner, and compares the pairs with `compare.py --judge cpu --tolerance 10`. Only CPU per
request is judged there (a shared runner's throughput is the neighbours'), and the job fails
only when **both** rounds say worse. That catches a regression of about 10 % or more in a
scenario, not one of 3 %: for that, use the box above. The results of the two rounds are
attached to the run for 90 days. A cron that fails, or that GitHub stopped running, is
reported by `cron-watchdog`.

## Limits, said plainly

- Loopback on one box: it measures what zion costs per request, not the network.
- `h2load` reports a mean latency and its deviation, not percentiles. A change in the
  tail that leaves the mean alone is not seen here.
- Seven scenarios cover the paths the open performance work touches. They do not cover
  the WAF in streaming mode, HTTP/3, the rate limiter or the audit log; the Criterion
  benches in [`../../benches/`](../../benches/) cover some of those at the function level.
- A shared LXC on a shared host: if `load_avg_at_start` in a result is not near zero,
  throw the run away.
