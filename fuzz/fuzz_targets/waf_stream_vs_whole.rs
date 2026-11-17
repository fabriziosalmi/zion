#![no_main]
//! Fuzz target — the streaming WAF against the whole-body WAF.
//!
//! A large body is scanned as it arrives (`StreamingScanner`, chunk by chunk, carrying an
//! overlap so a pattern across a chunk boundary is still found), and then
//! `validate_request_prescanned` skips the raw pattern pass because the stream already ran
//! it. If the streaming pass ever missed a pattern the whole-body pass finds, that pair would
//! be a WAF bypass. For any body, any chunk size and either mode, the production pair must
//! deny exactly when `validate_request` on the whole body denies.

use libfuzzer_sys::fuzz_target;
use zion::waf::{
    validate_request, validate_request_prescanned, StreamVerdict, StreamingScanner, WafMode,
    WafProfile, WafVerdict,
};

const CONTENT_TYPES: [&str; 3] = [
    "application/x-www-form-urlencoded",
    "text/plain",
    "application/json",
];

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let mode = if data[0] & 1 == 0 {
        WafMode::Balanced
    } else {
        WafMode::Aggressive
    };
    let ct = CONTENT_TYPES[(data[0] as usize >> 1) % CONTENT_TYPES.len()];
    let chunk = 1 + (u16::from_le_bytes([data[1], data[2]]) as usize % 512);
    let body = &data[3..];

    let profile = WafProfile {
        mode,
        ..WafProfile::default()
    };
    let max_bytes = profile.max_body_mb.saturating_mul(1_048_576);

    let whole = validate_request("POST", Some(ct), body, &profile);

    let mut scanner = StreamingScanner::new(mode, max_bytes);
    let streamed_deny = body
        .chunks(chunk)
        .any(|c| matches!(scanner.feed(c), StreamVerdict::Deny(_)));
    let production = if streamed_deny {
        WafVerdict::Deny("streaming")
    } else {
        validate_request_prescanned("POST", Some(ct), body, &profile)
    };

    assert_eq!(
        matches!(whole, WafVerdict::Deny(_)),
        matches!(production, WafVerdict::Deny(_)),
        "mode {mode:?}, {ct}, chunk {chunk}: whole {whole:?} vs streamed {production:?} on {:?}",
        String::from_utf8_lossy(body)
    );
});
