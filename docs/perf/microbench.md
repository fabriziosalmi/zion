# Microbench harness — `cargo bench`

Tracking issue: [#54](https://github.com/fabriziosalmi/zion/issues/54).
Companion file: [`benchmarks/results/criterion/baseline.json`](../../benchmarks/results/criterion/baseline.json).

This page describes the Criterion-based microbench surface used to size
candidate optimisations from [`docs/perf/roadmap.md`](roadmap.md). The
end-to-end `wrk` suites under [`benchmarks/`](../../benchmarks/) are still
the source of truth for *real-world throughput*; what's documented here
is the **30-second feedback loop** for ranking *individual hot-path
changes* (NUMA sharding, io_uring, kTLS, BPF, scanner tweaks).

## Layout

```text
benches/
  waf_streaming.rs       — buffered vs StreamingScanner, 1KB→10MB sweep
  sovereign.rs           — record_classification + classify
  traceparent.rs         — W3C parser, RFC vectors + garbage
  audit_hmac.rs          — HMAC chain throughput (events/sec)
  cache_lookup.rs        — L1 hit / L2 hit / full miss / singleflight
  numa.rs                — NumaAwareMap vs DashMap baseline, 1/4 shards
benchmarks/results/criterion/
  baseline.json          — checked-in numbers from a stable laptop
.github/workflows/
  bench.yml              — manual dispatch CI (Criterion + diff comment)
scripts/
  criterion-diff.py      — diff two criterion trees, emit markdown
```

## Running

Quick smoke pass (~10 s per bench, sample size truncated):

```bash
cargo bench --no-default-features --bench traceparent -- --quick
```

Full Criterion run (the numbers committed in `baseline.json`):

```bash
cargo bench --no-default-features --bench waf_streaming
```

A specific group or bench, regex-matched:

```bash
cargo bench --no-default-features --bench waf_streaming -- waf/buffered
```

Criterion writes per-bench detail under `target/criterion/<group>/<bench>/`,
including `estimates.json` (point estimates), `report/index.html` (when
`html_reports` is enabled — we ship the `cargo_bench_support` feature only,
so HTML is generated only on local runs that have a browser to view it).

## Adding a new bench

1. Drop `benches/<name>.rs` containing a Criterion `criterion_main!` entry.
   Use `criterion_group!` with named functions per surface (one group per
   logical concept; `c.benchmark_group(...)` for nested ID prefixes).
2. Register the bench in `Cargo.toml`:
   ```toml
   [[bench]]
   name = "<name>"
   harness = false
   ```
3. The harness can only call `pub` items reachable from `src/lib.rs`. The
   lib already exposes `audit`, `observability`, `waf`, `sovereign` (and a
   small re-export for `WafMode`/`WafProfile`). If you need a module that
   isn't there, prefer one of:
     * making the surface `pub` in the existing module (cheap if the type
       is already a stable interface),
     * extracting the bench-relevant logic into a self-contained submodule
       and re-exporting it,
     * using a synthetic fixture in the bench file (the cache bench does
       this — it imports `dashmap` directly rather than dragging in the
       `cache::StaticCache` dependency closure).
4. Re-run and update `benchmarks/results/criterion/baseline.json` if the
   numbers materially change. Keep the "captured_at" / "platform" fields
   honest — they're how reviewers tell whether a delta is real or
   hardware-relative.

## What's measured (and what isn't)

* **Measured**: per-call cost of pure functions on the request hot path.
  These benches are kept short so they react to *one* line changing —
  if a refactor moves a `format!()` allocation back into
  `record_classification`, the sovereign bench moves by ~10 ns and the
  diff bot flags it.
* **Not measured**: end-to-end p99 latency under load, syscall behaviour,
  TLS handshake cost, allocator interaction across long runs. Those
  belong to the `wrk`/`hey` suites and the production-load profile.
* **Not stable across runners**: GitHub-hosted CI is too noisy for sub-50 ns
  benches. Treat CI deltas as *signals*, not gates — variance below ±5 %
  is in the noise floor on `ubuntu-latest`. Reproduce locally before
  reacting.

## Bench targets — what each one defends

| Bench file              | Defends                                                                                        |
|-------------------------|-----------------------------------------------------------------------------------------------|
| `traceparent.rs`        | Anti-panic guarantee on garbage input; nanosecond-level parser cost (every request hits it). |
| `audit_hmac.rs`         | HMAC-SHA256 chain throughput; sustained events/sec a single audit writer can produce.        |
| `sovereign.rs`          | `record_classification` stays a single atomic increment (no allocation regression).          |
| `cache_lookup.rs`       | L1/L2 lookup latencies; alerts if a refactor makes the L1 path drift toward L2 cost.         |
| `waf_streaming.rs`      | Aho-Corasick scan cost (gate 3) on representative payloads; per-chunk overhead of streaming. |
| `numa.rs`               | `NumaAwareMap` single-shard cost stays at `DashMap` baseline (issue #50 acceptance).         |

## Why `--no-default-features`

The default-features build pulls in a small set of integration crates
(geo data, ml-waf, ACME) that aren't relevant to the microbench surface
and slow compilation. The benches are written against the bare lib so
they compile in ~70 s on a cold cache, ~5 s on a warm one. If a bench
ever needs a feature-gated surface, gate the bench file the same way and
document it here.

## Comparison to the wrk suites

|                       | `cargo bench` (this harness)                | `benchmarks/baseline/` harness          |
|-----------------------|---------------------------------------------|-----------------------------------------|
| What it measures      | Per-call cost of pure functions             | End-to-end RPS / p99 / TLS handshake    |
| Target                | One hot-path component at a time            | Full request pipeline incl. upstream    |
| Reproducibility       | High (seconds, deterministic)               | Lower (network + kernel scheduling)     |
| Use when              | Ranking optimisation candidates             | Validating release-shape numbers        |

## Future work

* Continuous regression detection (own issue once the baseline numbers
  stabilise across at least three CI runs).
* Compare against a reference-proxy baseline (separate harness; avoids
  dragging Criterion into the wrk-suite path).
* Tier-2 bench targets: `waf::validate_uri`, simd-json structural pass,
  upstream connector pool checkout.
