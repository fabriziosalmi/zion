// SPDX-License-Identifier: Apache-2.0
//! Public library surface for testing / fuzzing / external tooling.
//!
//! Zion ships as a single binary (`src/main.rs`); 99% of its modules are
//! private to that binary because they aren't a stable public API. This
//! `lib.rs` deliberately exposes ONLY the small, pure, self-contained
//! modules that benefit from external testing harnesses (cargo-fuzz,
//! integration tests in another workspace member, downstream tooling
//! that wants to verify HMAC chains or parse traceparent headers
//! without depending on hyper / tokio).
//!
//! What's exposed here is therefore a contract: bumping the signature of
//! these items is a breaking change for the lib, even though the binary
//! is on its own SemVer track. Treat additions liberally, removals
//! conservatively.
//!
//! What's deliberately NOT exposed: anything that touches the request
//! hot path, hyper response builders, ArcSwap state, or the dispatch
//! table. Those live in `main.rs`-rooted modules where re-exporting
//! them would create lib/bin duplication of compilation units.

#![allow(clippy::let_and_return)]
// Match the bin's lint baseline so modules that compile under both
// targets (`waf`, `sovereign`, `audit`, `observability`) don't trip a
// strict-clippy run only because the lib has a stricter default.
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::needless_borrow)]

/// W3C Trace Context parser, panic hook, OpenMetrics exemplar counters.
pub mod observability;

/// HMAC-SHA256-chained audit log + PII redaction policy. Depends on
/// `logging` for boot-path warnings.
pub mod audit;

/// Top-level structured error type for the boot path.
pub mod error;

/// Boot-path text/JSON logger. Re-exposed here because `audit` depends on it
/// for warn/error output when the writer task fails to open its target.
pub mod logging;

// ─────────────────────────────────────────────────────────────────────────────
// Microbenchmark surface (Track: v0.2 — Performance ceiling, issue #54).
// The modules below are exposed for `cargo bench` / external regression
// harnesses. They are pure data structures + algorithms — no hyper, no
// tokio runtime ownership, no ArcSwap state. The `#[doc(hidden)]` markers
// keep them out of rendered docs; the items are NOT part of the SemVer
// contract beyond what is needed for the benches under `benches/`.
// ─────────────────────────────────────────────────────────────────────────────

/// WAF: Aho-Corasick scanner, `WafMode`, `WafProfile`, `StreamingScanner`,
/// `validate_request`. Self-contained — no dependency on other crate modules.
/// Exposed for `benches/waf_streaming.rs`.
#[doc(hidden)]
pub mod waf;

/// Sovereign Edge Intelligence — IP classifier. Pure (no internal deps).
/// Exposed for `benches/sovereign.rs`.
#[doc(hidden)]
pub mod sovereign;

/// NUMA-aware sharded map (issue #50). Pure — depends only on
/// `dashmap` + (Linux + `numa-aware`) `libc::sched_getcpu`. Exposed for
/// `benches/numa.rs` so the regression harness can compare the
/// single-shard fast path against the multi-shard wrapper.
#[doc(hidden)]
pub mod numa;

/// io_uring accept thread (issue #51, `--features io-uring-accept`).
/// Exposed for the chaos test (`tests/chaos.rs`) and external diagnostics.
#[doc(hidden)]
pub mod uring;
