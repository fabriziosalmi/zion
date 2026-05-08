// SPDX-License-Identifier: Apache-2.0
//! Microbench: W3C `traceparent` parser.
//!
//! Tracks `zion::observability::parse_traceparent` on three input shapes:
//!   * RFC-valid header (the happy path);
//!   * outright garbage (a regression bench for the anti-panic guarantee — a
//!     zero-byte / overflowed input must return `None`, never panic);
//!   * structurally-valid but semantically-rejected input (all-zero IDs).
//!
//! The parser is on the request hot path — every incoming HTTP request
//! that carries a `traceparent` header is parsed before dispatch — so it is
//! a sensitivity gate for HTTP throughput. Nanosecond-level changes here
//! show up as percentage-level changes at p99 latency.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use zion::observability::parse_traceparent;

const VALID_RFC: &[u8] = b"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const VALID_RFC_FLAG_ZERO: &[u8] = b"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00";
const ALL_ZERO_TRACE: &[u8] = b"00-00000000000000000000000000000000-b7ad6b7169203331-01";
const ALL_ZERO_SPAN: &[u8] = b"00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01";
// Garbage shapes the parser must reject without panicking.
const TOO_SHORT: &[u8] = b"00-foo";
const NON_HEX: &[u8] = b"00-zzz7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const WRONG_VERSION: &[u8] = b"ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const BAD_DASH: &[u8] = b"00X0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

fn bench_valid(c: &mut Criterion) {
    let mut g = c.benchmark_group("traceparent/valid");
    g.throughput(Throughput::Bytes(VALID_RFC.len() as u64));
    g.bench_function("rfc_example", |b| {
        b.iter(|| {
            let r = parse_traceparent(black_box(VALID_RFC));
            black_box(r.is_some())
        })
    });
    g.bench_function("flag_unsampled", |b| {
        b.iter(|| {
            let r = parse_traceparent(black_box(VALID_RFC_FLAG_ZERO));
            black_box(r.is_some())
        })
    });
    g.finish();
}

fn bench_rejected(c: &mut Criterion) {
    let mut g = c.benchmark_group("traceparent/rejected");
    g.bench_function("all_zero_trace_id", |b| {
        b.iter(|| black_box(parse_traceparent(black_box(ALL_ZERO_TRACE))))
    });
    g.bench_function("all_zero_span_id", |b| {
        b.iter(|| black_box(parse_traceparent(black_box(ALL_ZERO_SPAN))))
    });
    g.bench_function("wrong_version", |b| {
        b.iter(|| black_box(parse_traceparent(black_box(WRONG_VERSION))))
    });
    g.finish();
}

fn bench_garbage(c: &mut Criterion) {
    let mut g = c.benchmark_group("traceparent/garbage");
    g.bench_function("too_short", |b| {
        b.iter(|| black_box(parse_traceparent(black_box(TOO_SHORT))))
    });
    g.bench_function("non_hex_digits", |b| {
        b.iter(|| black_box(parse_traceparent(black_box(NON_HEX))))
    });
    g.bench_function("malformed_dash", |b| {
        b.iter(|| black_box(parse_traceparent(black_box(BAD_DASH))))
    });
    g.bench_function("empty", |b| {
        b.iter(|| black_box(parse_traceparent(black_box(b""))))
    });
    g.finish();
}

criterion_group!(benches, bench_valid, bench_rejected, bench_garbage);
criterion_main!(benches);
