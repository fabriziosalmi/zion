// SPDX-License-Identifier: Apache-2.0
//! Microbench: WAF — buffered `validate_request` vs `StreamingScanner::feed`.
//!
//! The buffered path is what dispatch uses today: collect the whole body,
//! then scan once. The streaming path (Track D, issue #49) feeds the
//! scanner chunk-by-chunk and can early-exit before the body finishes
//! uploading. The two paths converge to identical verdicts on clean input.
//!
//! What this bench actually measures:
//!   * `validate_request` cost across 1 KB / 1 MB / 10 MB clean payloads —
//!     the worst case for the buffered path is the full-body scan.
//!   * `StreamingScanner::feed` cost across the same sizes, in 8 KB chunks
//!     (mirrors the chunk size hyper hands us off the wire).
//!   * **Per-chunk overhead** of the streaming path vs a single
//!     `is_match` over the buffered body. Aho-Corasick early-exits on the
//!     first match, so even the buffered scan denies fast when an attack
//!     pattern is in the first 64 bytes; the streaming path adds
//!     overlap-buffer + length-tracking work per chunk. The streaming
//!     path's real-world win is *peak memory* and *upload-bytes-on-the-
//!     wire*, neither of which a microbench can capture — this number is
//!     the cost the dispatcher pays for those properties on a same-size
//!     payload.
//!
//! Sample-size knob: 10 MB benches use a smaller sample count to stay
//! under the issue's 60 s wall-clock budget on a developer laptop.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use zion::waf::{validate_request, StreamVerdict, StreamingScanner, WafMode, WafProfile};

const CHUNK: usize = 8 * 1024;
const KB_1: usize = 1024;
const MB_1: usize = 1_048_576;
const MB_10: usize = 10 * 1_048_576;

fn profile() -> WafProfile {
    // High max_body_mb so size-limit gating doesn't dominate: we want to
    // measure scan cost, not the bytes-counter check.
    //
    // `allowed_content_types` is widened so the bench's `text/plain`
    // payload reaches gate 3 (Aho-Corasick scan). Default profile
    // accepts only `application/json` and `multipart/form-data`, both
    // of which trigger gate 5 (JSON structural validation) and pollute
    // the scan-cost number we want to track.
    //
    // Entropy gate is disabled because it kicks in on bodies ≥256 bytes
    // and adds an O(N) pass that's orthogonal to what this bench
    // measures (the AC scan).
    WafProfile {
        max_body_mb: 64,
        allowed_content_types: vec!["text/plain".to_string()],
        deny_unknown_content_types: true,
        entropy_check: false,
        ..WafProfile::default()
    }
}

fn clean_body(n: usize) -> Vec<u8> {
    // Fill with a non-attack ASCII pattern that the scanner will not match.
    // We avoid `'a'` repetition to defeat any future SIMD-prefix shortcut.
    let mut v = Vec::with_capacity(n);
    let cycle = b"The quick brown fox jumps over the lazy dog. ";
    while v.len() < n {
        let take = (n - v.len()).min(cycle.len());
        v.extend_from_slice(&cycle[..take]);
    }
    v
}

fn attack_first_64b(n: usize) -> Vec<u8> {
    // Attack pattern in the first 64 bytes; rest is clean. Streaming must
    // deny on chunk #1; buffered scans the whole body.
    let mut v = Vec::with_capacity(n);
    v.extend_from_slice(b"<script>alert(1)</script> trailing padding ");
    while v.len() < n {
        v.push(b'.');
    }
    v
}

fn feed_chunked(scanner: &mut StreamingScanner, body: &[u8]) -> StreamVerdict {
    for chunk in body.chunks(CHUNK) {
        let v = scanner.feed(chunk);
        if matches!(v, StreamVerdict::Deny(_)) {
            return v;
        }
    }
    StreamVerdict::Allow
}

fn bench_clean_buffered(c: &mut Criterion) {
    let p = profile();
    let mut g = c.benchmark_group("waf/buffered/clean");
    for &(label, size) in &[("1KB", KB_1), ("1MB", MB_1)] {
        let body = clean_body(size);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(label, |b| {
            b.iter(|| {
                let v = validate_request(
                    black_box("POST"),
                    black_box(Some("text/plain")),
                    black_box(&body),
                    black_box(&p),
                );
                black_box(v)
            })
        });
    }
    // 10 MB gets a smaller sample size — full-body scans dominate.
    g.sample_size(20);
    let body = clean_body(MB_10);
    g.throughput(Throughput::Bytes(MB_10 as u64));
    g.bench_function("10MB", |b| {
        b.iter(|| {
            let v = validate_request(
                black_box("POST"),
                black_box(Some("text/plain")),
                black_box(&body),
                black_box(&p),
            );
            black_box(v)
        })
    });
    g.finish();
}

fn bench_clean_streaming(c: &mut Criterion) {
    let p = profile();
    let max = p.max_body_mb * 1_048_576;
    let mut g = c.benchmark_group("waf/streaming/clean");
    for &(label, size) in &[("1KB", KB_1), ("1MB", MB_1)] {
        let body = clean_body(size);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(label, |b| {
            b.iter_batched(
                || StreamingScanner::new(WafMode::Balanced, max),
                |mut s| black_box(feed_chunked(&mut s, &body)),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    g.sample_size(20);
    let body = clean_body(MB_10);
    g.throughput(Throughput::Bytes(MB_10 as u64));
    g.bench_function("10MB", |b| {
        b.iter_batched(
            || StreamingScanner::new(WafMode::Balanced, max),
            |mut s| black_box(feed_chunked(&mut s, &body)),
            criterion::BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_attack_asymmetry(c: &mut Criterion) {
    // Both paths early-exit on the first match — buffered uses one
    // `is_match` call on the full slice (Aho-Corasick stops at the first
    // hit), streaming exits on the first `feed` chunk that matches. So
    // the actual numbers below are NOT an asymmetry between paths but
    // the cost the streaming path pays per-chunk vs the cost of a single
    // matched is_match call. Real-world streaming wins are upload-bytes
    // and peak-memory, neither captured here.
    let p = profile();
    let max = p.max_body_mb * 1_048_576;
    let body = attack_first_64b(MB_10);

    let mut g = c.benchmark_group("waf/attack_first_64b/10MB");
    g.throughput(Throughput::Bytes(MB_10 as u64));
    g.sample_size(20);

    g.bench_function("buffered_scans_full_body", |b| {
        b.iter(|| {
            let v = validate_request(
                black_box("POST"),
                black_box(Some("text/plain")),
                black_box(&body),
                black_box(&p),
            );
            black_box(v)
        })
    });

    g.bench_function("streaming_early_exit", |b| {
        b.iter_batched(
            || StreamingScanner::new(WafMode::Balanced, max),
            |mut s| black_box(feed_chunked(&mut s, &body)),
            criterion::BatchSize::SmallInput,
        )
    });

    g.finish();
}

fn bench_chunk_size_sweep(c: &mut Criterion) {
    // How sensitive is `StreamingScanner::feed` to the chunk size hyper
    // hands us? Sweep over typical wire-frame sizes. Smaller chunks =
    // more `feed` calls = more overlap-buffer copies.
    let p = profile();
    let max = p.max_body_mb * 1_048_576;
    let body = clean_body(MB_1);

    let mut g = c.benchmark_group("waf/streaming/chunk_size");
    g.throughput(Throughput::Bytes(MB_1 as u64));
    for &chunk_size in &[1024usize, 4 * 1024, 16 * 1024, 64 * 1024] {
        g.bench_function(format!("{chunk_size}B"), |b| {
            b.iter_batched(
                || StreamingScanner::new(WafMode::Balanced, max),
                |mut s| {
                    for chunk in body.chunks(chunk_size) {
                        if matches!(s.feed(chunk), StreamVerdict::Deny(_)) {
                            break;
                        }
                    }
                    black_box(s.bytes_seen())
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_clean_buffered,
    bench_clean_streaming,
    bench_attack_asymmetry,
    bench_chunk_size_sweep
);
criterion_main!(benches);
