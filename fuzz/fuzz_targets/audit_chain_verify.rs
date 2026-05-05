#![no_main]
//! Fuzz target — `audit::sign_event` + `audit::compute_hmac`.
//!
//! Drives the signing path with arbitrary event payloads. The property:
//! signing the *same* event twice with the same key + prev_hash must
//! return the *same* hmac. Determinism is the load-bearing assumption
//! that every external chain verifier relies on.

use libfuzzer_sys::fuzz_target;
use zion::audit::{compute_hmac, genesis_hash, sign_event, AuditEvent};

fuzz_target!(|data: &[u8]| {
    use aws_lc_rs::hmac;

    // Carve up the input. We need at least 32 bytes for a key plus some
    // payload bytes for the event detail.
    if data.len() < 33 {
        return;
    }
    let (key_bytes, payload) = data.split_at(32);
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);

    // Build a minimal event whose `detail` carries the fuzzer payload.
    // The serializer escapes anything non-UTF-8 via lossy conversion so
    // we never panic on bad bytes.
    let detail = String::from_utf8_lossy(payload).into_owned();
    let prev = genesis_hash(&key);
    let event = AuditEvent {
        seq: 1,
        ts: "2026-05-05T08:00:00.000000Z".into(),
        kind: "fuzz",
        trace_id: None,
        remote_ip: None,
        method: None,
        path: None,
        detail: Some(detail.clone()),
    };

    // Determinism: signing twice ⇒ identical hmac.
    let (s1, _) = match sign_event(&key, event.clone(), prev.clone()) {
        Ok(p) => p,
        Err(_) => return,
    };
    let (s2, _) = match sign_event(&key, event, prev.clone()) {
        Ok(p) => p,
        Err(_) => return,
    };
    assert_eq!(s1.hmac, s2.hmac, "non-deterministic sign for detail={detail:?}");

    // Sanity: compute_hmac is the underlying primitive — calling it
    // directly on the canonical event JSON must equal the signer's output.
    let canonical = serde_json::to_string(&s1.event).expect("event was already signed once");
    let direct = compute_hmac(&key, &canonical, &prev);
    assert_eq!(direct, s1.hmac, "direct compute_hmac diverged from sign_event");
});
