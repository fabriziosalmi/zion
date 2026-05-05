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
