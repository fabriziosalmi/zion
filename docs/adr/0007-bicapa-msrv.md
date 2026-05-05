# ADR-0007: Two-tier MSRV — 1.82 core, 1.88 with optional features

- **Status**: accepted
- **Date**: 2026-05-04 (Track A)
- **Tags**: msrv, build-flavors

## Context

The Rust ecosystem ships several crates we depend on transitively that
have moved their own MSRV faster than we want to push *ours*. As of
v0.1.8:

- `time` (via `rcgen` from `--features acme`/`init`) requires
  `edition2024` ⇒ Rust 1.85.
- `time-core 0.1.8`, `time-macros 0.2.27`, `darling 0.23` ⇒ Rust 1.88.
- `instability 0.3.12` (via `ratatui` from `--features tui`) ⇒ Rust 1.88.
- `icu_*` 2.x (via the URL parser used in HTTP3) ⇒ Rust 1.86+.

We had two bad choices:

1. **Single MSRV ≥ 1.88**, blocking distros and operators stuck on
   slightly older toolchains from doing a default-features build of the
   core daemon.
2. **Single MSRV at 1.82**, refusing to ship `--features acme` /
   `auth` / `http3` / `tui` because the dep graph requires 1.88.

## Decision

Declare **two MSRVs**:

- **Core (no-default-features)**: Rust **1.82**. The pure TLS proxy +
  WAF + cache + metrics + observability + audit log compiles on 1.82
  and is verified by a dedicated CI job
  (`.github/workflows/ci.yml::msrv`).
- **Full (`--features acme,auth,http3,tui,init,otel,...`)**: Rust
  **1.88**. The opt-in features pull edition2024 transitive deps; we
  bump alongside the ecosystem.

The recommended dev / CI compiler is pinned via `rust-toolchain.toml`
to 1.88 — that's what we actually build with. The 1.82 floor is a
*support contract* enforced by CI, not the compiler we ship release
binaries with.

## Consequences

- **Positive**: distros / operators with a Rust 1.82 toolchain (e.g.
  Debian Bookworm + rustup pin) can build the lean daemon today.
- **Positive**: feature builds track the ecosystem; we don't manually
  pin transitive deps to artificially-old major versions just to keep
  one MSRV number low.
- **Positive**: the contract is testable. The MSRV CI job runs
  `cargo check --locked --no-default-features` on a pinned 1.82
  toolchain. Any transitive dep change that breaks the floor fails CI.
- **Negative**: README / Cargo.toml carry a small "1.82 core / 1.88 full"
  caveat instead of a single number. We documented it explicitly:
  ```
  # MSRV is the *core* default-features build (TLS proxy + WAF + cache
  # + metrics). Opt-in features (acme, auth, init, http3) pull
  # crypto/i18n crates that have their own, faster-moving MSRV.
  ```
- **Neutral**: `rust-version = "1.82"` in `Cargo.toml` is what
  crates.io uses for resolver hints. The full-feature MSRV is
  documented but not encoded — Cargo would have to grow per-feature
  MSRV declarations for that, which it currently lacks.

## Alternatives considered

- **Single MSRV 1.88** — simpler, but excludes a non-trivial set of
  build environments from the lean binary.
- **Single MSRV 1.82 with manual `[patch.crates-io]` pins** — each
  dependency-bump PR would require curating the patch list. High
  maintenance, low value.
- **Vendor critical deps** — moves us into long-tail maintenance
  ourselves. No.

## References

- `Cargo.toml` `rust-version` field.
- `rust-toolchain.toml`
- `.github/workflows/ci.yml` `msrv` job.
- README "Verifying a Release" section.
