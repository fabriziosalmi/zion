// SPDX-License-Identifier: Apache-2.0
//! Microbench: Sovereign Edge Intelligence — IP classification + counters.
//!
//! Tracks two surfaces:
//!   * `record_classification` — single relaxed `fetch_add` on a per-class
//!     atomic counter. The previous `format!()`-based label path was
//!     replaced with `IpClass::index() → CLASS_COUNTERS[i]`, eliminating
//!     a `String` allocation on every request. The current cost should be
//!     in the low-nanosecond range; this bench guards the regression.
//!   * `classify` — `O(log N)` binary search over a sorted `CidrEntry`
//!     array for IPv4. With no `geo-*` feature the dataset is empty and
//!     the function is purely the `match` over `IpAddr`; the result is a
//!     baseline that downstream binaries with `geo-ita` can compare
//!     against to size their classification overhead.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zion::sovereign::{classify, record_classification, IpClass};

fn bench_record_classification(c: &mut Criterion) {
    let mut g = c.benchmark_group("sovereign/record_classification");
    g.throughput(Throughput::Elements(1));
    // The previous `format!()` baseline allocated ~16 B/call. The current
    // path is 1 atomic increment. Keep this bench so the regression is
    // visible if anyone refactors `record_classification` and re-introduces
    // a String allocation.
    g.bench_function("residential_ita", |b| {
        b.iter(|| record_classification(black_box(IpClass::ResidentialIta)))
    });
    g.bench_function("unknown", |b| {
        b.iter(|| record_classification(black_box(IpClass::Unknown)))
    });
    g.bench_function("gov_ita", |b| {
        b.iter(|| record_classification(black_box(IpClass::GovIta)))
    });
    g.finish();
}

fn bench_classify(c: &mut Criterion) {
    let mut g = c.benchmark_group("sovereign/classify");
    g.throughput(Throughput::Elements(1));

    // IPv4 in the residential-ITA range (Telecom Italia: 79.16.0.0/14).
    // With `geo-ita` enabled the classifier returns ResidentialIta;
    // without the feature, the dataset is empty so this measures the
    // bare match + binary-search-on-empty cost.
    let v4 = IpAddr::V4(Ipv4Addr::new(79, 17, 100, 200));
    g.bench_function("ipv4_in_range", |b| {
        b.iter(|| black_box(classify(black_box(v4))))
    });

    // IPv4-mapped IPv6 (`::ffff:a.b.c.d`) — should hit the v4 path.
    let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x4f11, 0x64c8));
    g.bench_function("ipv6_v4mapped", |b| {
        b.iter(|| black_box(classify(black_box(mapped))))
    });

    // Pure IPv6 — must early-return Unknown without entering the search.
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    g.bench_function("ipv6_pure", |b| {
        b.iter(|| black_box(classify(black_box(v6))))
    });

    // Public IPv4 outside any baked range — full O(log N) miss.
    let miss = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    g.bench_function("ipv4_miss", |b| {
        b.iter(|| black_box(classify(black_box(miss))))
    });
    g.finish();
}

fn bench_label_lookup(c: &mut Criterion) {
    // `IpClass::as_str` is on the metrics-render path. Constant-time match;
    // benched here so any refactor that replaces it with a `format!()` or
    // `.to_string()` is caught immediately.
    let mut g = c.benchmark_group("sovereign/as_str");
    g.bench_function("residential_ita", |b| {
        b.iter(|| black_box(black_box(IpClass::ResidentialIta).as_str()))
    });
    g.bench_function("unknown", |b| {
        b.iter(|| black_box(black_box(IpClass::Unknown).as_str()))
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_record_classification,
    bench_classify,
    bench_label_lookup
);
criterion_main!(benches);
