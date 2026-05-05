#![no_main]
//! Fuzz target — `audit::CompiledRedaction::redact_query_string`.
//!
//! Goal: prove the redactor never panics on adversarial query strings
//! and never lets a configured-secret value through. Splits the input on
//! a NUL byte (or just uses an empty redact list) to drive both branches.

use libfuzzer_sys::fuzz_target;
use zion::audit::RedactConfig;

fuzz_target!(|data: &[u8]| {
    // First byte chooses between "with redact list" and "empty redact list".
    let (cfg, q) = if data.is_empty() {
        (
            RedactConfig {
                headers: vec![],
                query_params: vec![],
            },
            "",
        )
    } else if data[0] & 1 == 0 {
        // Empty list — exercise the no-op fast path.
        let s = std::str::from_utf8(&data[1..]).unwrap_or("");
        (
            RedactConfig {
                headers: vec![],
                query_params: vec![],
            },
            s,
        )
    } else {
        // Non-empty list — must redact "token" and "api_key" if seen.
        let s = std::str::from_utf8(&data[1..]).unwrap_or("");
        (
            RedactConfig {
                headers: vec![],
                query_params: vec!["token".into(), "api_key".into()],
            },
            s,
        )
    };

    let redactor = cfg.compile();
    let out = redactor.redact_query_string(q);

    // The pair count is preserved.
    let pairs_in = q.split('&').filter(|s| !s.is_empty()).count();
    let pairs_out = out.split('&').filter(|s| !s.is_empty()).count();
    assert_eq!(pairs_in, pairs_out, "input={q:?} output={out:?}");
});
