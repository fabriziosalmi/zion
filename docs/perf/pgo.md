# Profile-Guided Optimization (PGO) builds

Tracking issue: [#55](https://github.com/fabriziosalmi/zion/issues/55).
Companion script: [`scripts/pgo-collect.sh`](../../scripts/pgo-collect.sh).
Companion workflow: [`.github/workflows/release.yml`](../../.github/workflows/release.yml).

## Why

Zion's hot path — Aho-Corasick body scan, hyper request dispatch, the
DashMap L2 lookup — is exactly the workload PGO targets: tight inner
loops where branch prediction and inlining decisions dominate. Cloudflare
reported +10–20 % on Pingora with the same tooling; published Rust PGO
guides report similar deltas across server-style workloads.

PGO ships **alongside** the regular release binary, not in place of it.
Operators that don't want to trust a profile-trained binary can keep the
non-PGO artefact; the SHA256 differs by construction.

## What ships

For every release tag (`v*`) the build matrix produces:

* `zion-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` — regular build.
* `zion-vX.Y.Z-x86_64-unknown-linux-gnu-pgo.tar.gz` — PGO build.
* Each archive has its own SHA256SUMS line and its own SLSA build
  provenance (in-toto attestation via Sigstore + Rekor).

Other targets (musl, aarch64, macOS, Windows) are non-PGO today. Adding
them is a matter of flipping the matrix flag once we've validated the
wire-up over a few release cycles — see [Future expansion](#future-expansion).

## How the build works

```text
            ┌────────────────────────────────────────────────────────┐
            │ Phase 1: instrumented build                            │
            │   RUSTFLAGS="-Cprofile-generate=$PGO_DIR"              │
            │   cargo build --release --target …-linux-gnu           │
            └──────────────────────┬─────────────────────────────────┘
                                   ▼
            ┌────────────────────────────────────────────────────────┐
            │ Workload: scripts/pgo-collect.sh                       │
            │   - starts the Go test backend on :9090                │
            │   - starts the instrumented binary on :4430            │
            │   - 10 s wrk burst × 3 endpoints (WAF + cache + admin) │
            │   - SIGTERM the binary so the runtime flushes profraws │
            └──────────────────────┬─────────────────────────────────┘
                                   ▼
            ┌────────────────────────────────────────────────────────┐
            │ llvm-profdata merge                                    │
            │   $PGO_DIR/*.profraw  →  $PGO_DIR/merged.profdata      │
            └──────────────────────┬─────────────────────────────────┘
                                   ▼
            ┌────────────────────────────────────────────────────────┐
            │ Phase 2: optimised build                               │
            │   RUSTFLAGS="-Cprofile-use=$PGO_DIR/merged.profdata    │
            │             -Cllvm-args=-pgo-warn-missing-function"    │
            │   cargo build --release --target …-linux-gnu           │
            └────────────────────────────────────────────────────────┘
```

The workload is **deterministic** — fixed connection count, fixed wall
time, fixed endpoint set — so two consecutive PGO runs on the same
commit produce profraws of comparable shape, and the resulting binaries
land within ~1 % of each other on bench numbers.

## Reproducing locally

```bash
# 1. build instrumented
PGO_DIR=/tmp/zion-pgo
mkdir -p "$PGO_DIR"
RUSTFLAGS="-Cprofile-generate=$PGO_DIR" cargo build --release

# 2. collect profile (~30 s)
ZION_BIN=target/release/zion PGO_PROFILE_DIR=$PGO_DIR \
  bash scripts/pgo-collect.sh

# 3. merge
llvm-profdata merge -o "$PGO_DIR/merged.profdata" "$PGO_DIR"/*.profraw

# 4. rebuild optimised
cargo clean --release
RUSTFLAGS="-Cprofile-use=$PGO_DIR/merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
  cargo build --release
```

The legacy script `benchmarks/bench-pgo.sh` does the same thing for
local benchmarking against the longer 30s workload — that one is
intended for hand-tuning; `scripts/pgo-collect.sh` is the CI workload.

## Expected delta

Target: **+10 %** on the representative workloads tracked by the
[`benchmarks/baseline/`](../../benchmarks/baseline) harness
and the criterion microbench surface ([docs/perf/microbench.md](microbench.md)).
We expect the largest wins on:

* WAF gate 3 (Aho-Corasick scan) — tight inner loop, bench
  `waf/buffered/clean/*` and `waf/streaming/clean/*`.
* hyper request dispatch — large match in dispatch.rs.
* DashMap L2 lookup — bench `cache/l2/hit`.

When the first PGO release is cut we'll capture the actual numbers in
this section, side-by-side with the non-PGO baseline at the same tag.

## Verification

After downloading both archives from a release:

```bash
# PGO and non-PGO binaries differ by construction (different code layout
# from profile-driven inlining + bb-reordering).
sha256sum zion-*-x86_64-unknown-linux-gnu*.tar.gz
# zion-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz       → A
# zion-vX.Y.Z-x86_64-unknown-linux-gnu-pgo.tar.gz   → B  (B != A)

# Both carry SLSA provenance — verify before running.
gh attestation verify zion-vX.Y.Z-x86_64-unknown-linux-gnu-pgo.tar.gz \
  --owner fabriziosalmi
```

## Future expansion

* **musl x86_64** — should be a one-line matrix flip; the binary is
  static, the runner can execute it, the same workload applies. Pending
  one or two clean release cycles on the gnu variant first.
* **aarch64-unknown-linux-gnu** — needs QEMU on the runner (or a
  native arm64 runner); track with a follow-up issue once GitHub
  exposes affordable arm64 hosted runners.
* **macOS / Windows** — possible but lower ROI: the typical Zion
  deployment is a Linux server. Reconsider if downstream demand
  emerges.
* **BOLT post-link optimisation** — separate issue, downstream of PGO
  (mentioned in the [#55 spec](https://github.com/fabriziosalmi/zion/issues/55)
  as out of scope).
* **Auto-FDO** — would replace PGO; not on the roadmap for 2026.

## References

* Rust PGO guide: <https://doc.rust-lang.org/rustc/profile-guided-optimization.html>
* LLVM `llvm-profdata`: <https://llvm.org/docs/CommandGuide/llvm-profdata.html>
* The legacy [`benchmarks/bench-pgo.sh`](../../benchmarks/bench-pgo.sh)
  runs the same flow locally with a longer workload for hand-tuning.
