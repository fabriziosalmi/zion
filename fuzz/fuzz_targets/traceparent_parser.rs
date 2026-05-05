#![no_main]
//! Fuzz target — `observability::parse_traceparent`.
//!
//! Goal: prove the parser never panics, never infinite-loops, and never
//! produces an out-of-grammar `TraceContext` (all-zero IDs would slip
//! past validation). The parser sits on the request hot path; it eats
//! client-controlled `traceparent` header bytes on every connection.

use libfuzzer_sys::fuzz_target;
use zion::observability::parse_traceparent;

fuzz_target!(|data: &[u8]| {
    if let Some(ctx) = parse_traceparent(data) {
        // Post-conditions the parser MUST guarantee on success:
        //   1. trace_id is not all-zero (W3C §3.2.2.2).
        //   2. span_id is not all-zero (W3C §3.2.2.3).
        //   3. flags is a single byte, not constrained further by v0.
        assert!(ctx.trace_id.iter().any(|&b| b != 0));
        assert!(ctx.span_id.iter().any(|&b| b != 0));
        let _ = ctx.flags;
        let _ = ctx.is_sampled();
    }
});
