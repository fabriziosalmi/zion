# Benchmarks

## Canonical: `baseline/`

[`baseline/run-baseline.sh`](baseline/) is the reproducible macro-benchmark —
throughput (median-of-N trials + 95% CI + p50/p99/p99.9 + CPU/RSS), an nginx
comparison on the same box, a concurrency sweep, a payload matrix, **HTTP/2 +
TLS conformance**, and **cache-correctness** — rendered to a tracked PDF. It
supersedes the older native/matrix/scientific throughput scripts (archived).

```bash
MODE=full  bash benchmarks/baseline/run-baseline.sh   # authoritative → zion-<ver>-baseline.pdf
MODE=smoke bash benchmarks/baseline/run-baseline.sh   # fast pipeline check
```

See [`baseline/README.md`](baseline/README.md) for prerequisites and knobs.

## Specialised scripts

| Script | Purpose | Duration |
|---|---|---|
| `bench-pgo.sh` | Two-phase PGO build (profile → optimized) | ~10–20 min |
| `bench-mesh.sh` | `--features sovereign-aimp` mesh cost (idle/lookup/3-node) — issue #72 | ~10 min |
| `bench-xdp-ktls.sh` | XDP + kTLS A/B (Track A, Linux) | varies |
| `bench-profile.sh` | CPU flamegraph profiling via `samply` | ~3 min |

## Distributed rig + microbenches

- Network-realistic numbers (load box → SUT over a real NIC): [`../benches/e2e/`](../benches/e2e/) (`RESULTS.md`).
- Rust `cargo bench` microbenches: [`../benches/`](../benches/) (Criterion; baseline at `results/criterion/baseline.json`).

## Configuration files

`zion-bench-tls*.toml` (TLS / +WAF / +cache / full) and `zion-docker*.toml`
(container variants) drive the specialised scripts. The baseline harness uses
its own [`baseline/zion-lab.toml`](baseline/zion-lab.toml).

## Archive

Superseded throughput scripts — `bench-native.sh`, `bench-matrix.sh`,
`bench-scientific.sh`, and their report generators — are preserved under
[`archive/`](archive/) for reference. Use `baseline/` instead.
