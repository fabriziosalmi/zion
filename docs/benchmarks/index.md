# Benchmarks

Zion's benchmarks live in three places, by altitude:

| Where | What | Output |
|---|---|---|
| [`benchmarks/baseline/`](https://github.com/fabriziosalmi/zion/tree/master/benchmarks/baseline) | **Canonical** reproducible macro-benchmark: throughput (median-of-N trials + 95% CI + p50/p99/p99.9 + CPU/RSS), an nginx comparison on the same box, a concurrency sweep, a payload matrix, **HTTP/2 (h2spec) + TLS (testssl) conformance**, and **cache-correctness** — rendered to a tracked PDF. | `zion-<ver>-baseline.pdf` |
| [`benches/e2e/`](https://github.com/fabriziosalmi/zion/tree/master/benches/e2e) | Distributed 2-node rig (load box → SUT over a real NIC) — the network-realistic numbers. | `benches/e2e/RESULTS.md` |
| [`benches/`](https://github.com/fabriziosalmi/zion/tree/master/benches) | Rust `cargo bench` microbenches (Criterion): WAF scan, cache lookup, traceparent, audit HMAC, sovereign lookup, NUMA. | criterion baseline |

Specialised one-offs (`bench-pgo.sh`, `bench-mesh.sh`, `bench-xdp-ktls.sh`,
`bench-profile.sh`) live under [`benchmarks/`](https://github.com/fabriziosalmi/zion/tree/master/benchmarks).

## Honest snapshot

End-to-end TLS 1.3 over loopback to a zero-overhead hyper backend; median of
trials; **0 errors / all 2xx**. Two reference machines:

- **Apple M4** (fast desktop class): TLS reverse proxy **~100–108k req/s** (92k for 16 KB bodies), **~101k** with the WAF scanning every request, **190–222k** for cache hits served from RAM.
- **Isolated i7-6700 SUT** (3 vCPU, `governor=performance`, baseline harness): cache-hit **~55.9k vs nginx ~39.5k req/s on the same box (+41%)**; proxy passthrough ~27.7k; `h2load` 56k (H2) / `wrk` 59.5k (H1); concurrency-saturation knee ~c=50.

Against **nginx 1.27** under identical cgroup limits (1 CPU / 256 MB, byte-identical
responses): nginx leads raw uncached proxy by a few %, Zion is at parity on API
GET / WAF POST, and **wins on cacheable assets** where the in-RAM cache skips the
origin round-trip — all while terminating TLS *and* running the WAF inline.

These are server-side-efficiency figures (no network RTT), useful as a
cross-version regression baseline — **not** a WAN number. The full methodology,
raw tool output, and the nginx comparison are in the baseline PDF; WAN-realistic
numbers are in `benches/e2e/RESULTS.md`.

## Reproduce

```bash
# canonical baseline (throughput + conformance + cache-correctness → PDF)
MODE=full bash benchmarks/baseline/run-baseline.sh

# Rust microbenches
cargo bench --no-default-features --bench cache_lookup
```

See the [baseline harness README](https://github.com/fabriziosalmi/zion/blob/master/benchmarks/baseline/README.md)
for prerequisites, knobs (`MODE`, `TRIALS`, CPU pinning, `REPORT=0`), and rigor notes.
