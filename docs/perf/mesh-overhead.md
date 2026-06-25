# Mesh observability — performance budget

Tracking issue: [#69](https://github.com/fabriziosalmi/zion/issues/69).
Source: [`src/aimp_cp.rs`](../../src/aimp_cp.rs),
[`src/metrics.rs`](../../src/metrics.rs).
Operator guide: [`docs/mesh/integration.md`](../mesh/integration.md).

## Target

The mesh observability surface — eight always-on counters, three new
audit kinds, plus future tracing spans — must cost **< 0.5 % of host
throughput** on a 100 k rps workload that doesn't otherwise exercise
the mesh. Builds compiled without `--features sovereign-aimp` see
zero mesh-related work; this budget governs the path on builds that
opted in.

## Where the cost is

The instrumentation is scattered across the mesh hot path. Each
counter increment is a single relaxed `fetch_add` on a global
`AtomicU64` — same shape as the WAF / cache counters that have been
in production since v0.1.x. There are exactly three categories of
spend:

1. **Per-envelope receive cost** — every UDP packet that hits the
   gossip socket triggers one `fetch_add` for `gossip_bytes_in`,
   plus one `fetch_add` for the disposition (`received` or
   `dropped_*`). That's two atomic ops per envelope, served from
   the receiver task on its own runtime worker. Even at 10 k
   envelopes/sec — far above any plausible production rate — the
   atomic store cost is below microseconds-per-second.
2. **Per-emit cost** — `publish_block` bumps `mesh_claims_emitted`
   once and then enqueues the delta into the publish channel. The
   publisher task bumps `gossip_bytes_out` once per `send_to`.
   These run off the request hot path (publish_block enqueues + the
   publisher loop drains async); the dispatcher only pays the
   single `fetch_add` in `publish_block`.
3. **Per-request cost** — the dispatcher `cp.lookup(client_ip)` was
   already on the path before this PR. Issue #69 adds one
   `fetch_add` on the *positive* lookup path (`mesh_score_lookups`).
   Negative lookups pay nothing extra. So the per-request overhead
   is bounded by the hit rate of the mesh-score lookup table.

## Measured

Numbers below are taken on a 10-core M-series Mac with
`cargo bench --bench` (microbench harness, issue #54). The
methodology is: a fresh `AimpEnvelope` is constructed and fed
through `try_merge` 1 M times in a tight loop; then the same loop
without the `try_merge` body, used as the floor.

| Path | Median time | Counter ops |
|------|-------------|-------------|
| `try_merge` accept (clean envelope) | (bench TODO) | 2 fetch_add |
| `try_merge` reject (replay) | (bench TODO) | 2 fetch_add |
| `try_merge` reject (signature) | (bench TODO) | 2 fetch_add |
| `publish_block` enqueue | (bench TODO) | 1 fetch_add + 1 channel send |
| `cp.lookup` hit + counter | (bench TODO) | 1 hashmap get + 1 fetch_add |

The `(bench TODO)` rows will land alongside [#72 (Bench: --features
mesh cost at idle and at saturation)](https://github.com/fabriziosalmi/zion/issues/72)
once the mesh has a saturation workload to measure against.

## What's NOT measured here

- **Tracing span overhead** — `tracing::info_span!` is gated by the
  active subscriber. Under `RUST_LOG=warn` (production default) the
  mesh-receive event is never recorded; the cost is one branch
  prediction. Under `RUST_LOG=debug` (dev) it's a few hundred
  nanoseconds per event. Operators that flip mesh-tracing on in
  production should expect a few percent of the mesh receiver task's
  budget to go to span recording.
- **Audit-log mesh kinds** — `mesh_publish` / `mesh_receive` events
  are written to the audit log only when `[audit].enabled = true`.
  The audit writer is async (bounded mpsc, dedicated task) so the
  emit is non-blocking; the cost is one `try_send` on a channel.
  Sustained audit cost is dominated by the disk-flush rate, not by
  zion's emit-side.

## How to validate the budget

```bash
# 1. Build the binary with --features sovereign-aimp.
cargo build --release --features sovereign-aimp

# 2. Run zion against a backend (benchmarks/zion-bench-tls.toml)
#    with the mesh enabled but no peers. publish_block is never
#    called; mesh_score_lookups is exercised on every request.
ZION_AIMP_LISTEN=127.0.0.1:7777 ZION_AIMP_PEERS= \
  ZION_CONFIG=benchmarks/zion-bench-tls.toml ./target/release/zion &

# 3. wrk a 100k rps burst against /api/v1/data, scrape /metrics, and
#    confirm `zion_mesh_score_lookups_total` ticks at the expected
#    rate (1 per request that has a cp.lookup hit).
wrk -t8 -c128 -d30s -H 'Host: bench.local' \
  https://127.0.0.1:4430/api/v1/data

# 4. The throughput delta from the same workload without
#    --features sovereign-aimp is the mesh observability cost.
#    Target: < 0.5 %.
```

Issue [#72](https://github.com/fabriziosalmi/zion/issues/72) tracks
landing this measurement as a CI bench so the budget is enforced
automatically.
