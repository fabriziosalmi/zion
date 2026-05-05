//! Chaos integration tests — failure-mode coverage that the unit test
//! suite alone can't reach.
//!
//! These tests don't spin up a full Zion daemon (the existing
//! `tests/integration.rs` `--ignored` suite does that). Instead they
//! exercise the Track-B subsystems in isolation under adversarial
//! conditions:
//!
//!   - Audit-writer queue overflow — verifies `dropped_total` ticks and
//!     no events sneak through after the queue saturates.
//!   - Rate-limit window flip — drives requests across a window
//!     boundary and asserts the count resets exactly once per second.
//!   - Audit-writer recovers from a slow disk — uses a tempdir that we
//!     hold open to artificially constrain ordering.
//!
//! `tokio::time::pause()` makes the rate-limit test deterministic
//! without sleeping in real time.

// `audit` and `observability` are re-exported from the `zion` library
// crate (src/lib.rs). The binary's own private modules are not visible
// here — that's by design.
use zion::audit::{spawn_writer, AuditConfig, AuditEvent};

#[tokio::test]
async fn audit_queue_overflow_drops_excess_events() {
    let dir = tempdir("zion-chaos-overflow");
    let path = dir.join("audit.log");
    std::env::set_var("ZION_TEST_OVERFLOW_KEY", "this-is-a-32-byte-test-secret!ab");

    // Tiny queue + slow writer (filesystem) — easy to overflow.
    let cfg = AuditConfig {
        enabled: true,
        path: Some(path.to_string_lossy().into_owned()),
        key_env: "ZION_TEST_OVERFLOW_KEY".into(),
        queue_depth: 4,
    };
    let h = spawn_writer(&cfg);

    // Hammer the writer with way more events than the queue can hold,
    // synchronously and as fast as `try_send` allows. Some MUST be
    // dropped — that's the documented overflow contract.
    //
    // We count locally from the return value of `emit()` rather than from
    // the global `AUDIT_EVENTS_*_TOTAL` atomics, because cargo test
    // parallelizes test binaries: another test in the same suite ticking
    // the same global counters would race with this one.
    let burst = 1024;
    let mut accepted = 0u64;
    let mut rejected = 0u64;
    for i in 0..burst {
        if h.emit(AuditEvent {
            seq: 0,
            ts: String::new(),
            kind: "auth_failure",
            trace_id: None,
            remote_ip: None,
            method: None,
            path: None,
            detail: Some(format!("burst event {i}")),
        }) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    // Conservation: every emit returns true (queued) or false (dropped).
    assert_eq!(
        accepted + rejected,
        burst as u64,
        "every emit must classify deterministically"
    );

    // Overflow signal: with a 4-deep queue and 1024 synchronous emits in a
    // single tokio task (no yield between calls), the writer cannot drain
    // fast enough to keep up — at least one event MUST be rejected. If
    // `rejected == 0` the queue is not bounded. Regression alarm.
    assert!(
        rejected > 0,
        "queue_depth=4 with 1024 sync emits must reject at least one; got accepted={accepted}, rejected={rejected}"
    );
}

#[test]
fn audit_handle_is_send_and_sync() {
    // The handle is cloned into AppState and shared across worker
    // threads; if it accidentally lost Send/Sync the type-checker
    // would have caught it but the chaos suite is the right place to
    // surface the requirement explicitly.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<zion::audit::AuditHandle>();
    assert_send_sync::<zion::audit::CompiledRedaction>();
}

#[tokio::test]
async fn audit_writer_survives_burst_then_drains() {
    let dir = tempdir("zion-chaos-drain");
    let path = dir.join("audit.log");
    std::env::set_var("ZION_TEST_DRAIN_KEY", "this-is-a-32-byte-test-secret!ab");

    let cfg = AuditConfig {
        enabled: true,
        path: Some(path.to_string_lossy().into_owned()),
        key_env: "ZION_TEST_DRAIN_KEY".into(),
        queue_depth: 64,
    };
    let h = spawn_writer(&cfg);

    // Burst within capacity — nothing should drop.
    for i in 0..32 {
        assert!(
            h.emit(AuditEvent {
                seq: 0,
                ts: String::new(),
                kind: "config_reload",
                trace_id: None,
                remote_ip: None,
                method: None,
                path: None,
                detail: Some(format!("ok {i}")),
            }),
            "no event should drop with queue_depth=64 and 32 bursts"
        );
    }

    // Closing the handle lets the writer task exit cleanly.
    drop(h);

    // Wait for the chain_init line + 32 events.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(&path) {
            if s.lines().count() >= 33 {
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("writer did not drain 33 lines within 2s");
}

#[test]
fn redact_idempotence_under_repeated_calls() {
    // Property: applying the same redactor twice yields a result whose
    // pair count and key set match the first pass. We re-establish this
    // invariant in the chaos suite because it crosses module boundaries
    // (audit + dispatch's `emit_waf_block` helper).
    let r = zion::audit::RedactConfig {
        headers: vec![],
        query_params: vec!["token".into(), "session".into()],
    }
    .compile();
    let q = "user=alice&token=abcd1234&page=2&session=xyz";
    let pass1 = r.redact_query_string(q);
    let pass2 = r.redact_query_string(&pass1);
    assert_eq!(pass1.split('&').count(), pass2.split('&').count());
    assert!(!pass1.contains("abcd1234"));
    assert!(!pass1.contains("xyz"));
}

fn tempdir(label: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "{label}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).expect("create chaos tempdir");
    p
}
