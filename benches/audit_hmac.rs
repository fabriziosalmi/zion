// SPDX-License-Identifier: Apache-2.0
//! Microbench: audit log HMAC chain throughput.
//!
//! Tracks two surfaces that compose the audit-log hot path:
//!   * `compute_hmac` — pure HMAC-SHA256 over `event_json || '|' || prev_hash`;
//!   * `sign_event` — full `serialize → hmac → wrap` for one chain link.
//!
//! Throughput is reported in events/sec. The audit writer is async (mpsc),
//! so this bench measures the *signing* cost only — the disk-flush cost is
//! orthogonal and lives in a separate harness.

use aws_lc_rs::hmac;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use zion::audit::{compute_hmac, genesis_hash, sign_event, AuditEvent};

fn key() -> hmac::Key {
    // 32 bytes of stable test material — `cargo bench` reruns must be
    // deterministic so criterion's regression detector works.
    let raw = [0xA5u8; 32];
    hmac::Key::new(hmac::HMAC_SHA256, &raw)
}

fn typical_event() -> AuditEvent {
    AuditEvent {
        seq: 1,
        ts: "2026-05-08T12:00:00Z".into(),
        kind: "request_blocked",
        trace_id: Some("0af7651916cd43dd8448eb211c80319c".into()),
        remote_ip: Some("203.0.113.5".into()),
        method: Some("POST".into()),
        path: Some("/api/v1/widgets".into()),
        detail: Some("waf=balanced reason=injection_pattern_detected".into()),
    }
}

fn bench_compute_hmac(c: &mut Criterion) {
    let k = key();
    let event = typical_event();
    let json = serde_json::to_string(&event).unwrap();
    let prev = genesis_hash(&k);

    let mut g = c.benchmark_group("audit/compute_hmac");
    g.throughput(Throughput::Bytes(json.len() as u64));
    g.bench_function("typical_event", |b| {
        b.iter(|| {
            let h = compute_hmac(black_box(&k), black_box(&json), black_box(&prev));
            black_box(h)
        })
    });
    // Larger detail blob — represents an `auth_failure` with a verbose
    // audit detail field. Worst-case shape we encode in production.
    let big_event = AuditEvent {
        detail: Some("x".repeat(2048)),
        ..typical_event()
    };
    let big_json = serde_json::to_string(&big_event).unwrap();
    g.throughput(Throughput::Bytes(big_json.len() as u64));
    g.bench_function("verbose_2kb_detail", |b| {
        b.iter(|| {
            let h = compute_hmac(black_box(&k), black_box(&big_json), black_box(&prev));
            black_box(h)
        })
    });
    g.finish();
}

fn bench_sign_event(c: &mut Criterion) {
    let k = key();
    let mut g = c.benchmark_group("audit/sign_event");
    g.throughput(Throughput::Elements(1));
    g.bench_function("single_link", |b| {
        let prev = genesis_hash(&k);
        b.iter_batched(
            || (typical_event(), prev.clone()),
            |(ev, prev)| {
                let (signed, new_prev) = sign_event(black_box(&k), ev, prev).unwrap();
                black_box((signed, new_prev))
            },
            criterion::BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_chain_throughput(c: &mut Criterion) {
    // Sustained chain throughput: how many events/sec can we sign if each
    // event's `prev_hash` feeds the next? This is the bottleneck for the
    // audit writer when the queue is saturated.
    let k = key();
    let mut g = c.benchmark_group("audit/chain");
    g.throughput(Throughput::Elements(64));
    g.bench_function("64_link_chain", |b| {
        b.iter(|| {
            let mut prev = genesis_hash(black_box(&k));
            for _ in 0..64 {
                let (_, new_prev) = sign_event(&k, typical_event(), prev).unwrap();
                prev = new_prev;
            }
            black_box(prev)
        })
    });
    g.finish();
}

fn bench_genesis(c: &mut Criterion) {
    let k = key();
    c.bench_function("audit/genesis_hash", |b| {
        b.iter(|| black_box(genesis_hash(black_box(&k))))
    });
}

criterion_group!(
    benches,
    bench_compute_hmac,
    bench_sign_event,
    bench_chain_throughput,
    bench_genesis
);
criterion_main!(benches);
