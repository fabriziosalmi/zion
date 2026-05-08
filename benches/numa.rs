// SPDX-License-Identifier: Apache-2.0
//! Microbench: NUMA-aware sharded map (issue #50).
//!
//! Three things this bench measures:
//!
//!   1. **Same-socket access cost == baseline?** A 1-shard
//!      `NumaAwareMap` must perform within noise of a bare `DashMap`.
//!      The wrapper's only overhead in the single-node case is one
//!      length comparison in `local_idx`; this bench guards that
//!      remains true across compiler versions and refactors. This is
//!      the **acceptance criterion** for issue #50.
//!
//!   2. **Multi-shard wrapper overhead, local-hit case.** With N>1
//!      shards even a perfectly-routed local-shard hit costs more
//!      than the single-shard baseline because each DashMap brings
//!      its own internal-shard metadata; with 4 wrappers × ~ncpus
//!      internal shards each, the metadata footprint is 4× and the
//!      L1 pressure on `shards[0]`'s metadata access shows up as a
//!      few extra ns. The number we publish is the floor; an
//!      operator on a real 4-socket box will see additional cost
//!      from cross-socket cacheline traffic (not measurable on
//!      single-socket CI, but the layout cost is).
//!
//!   3. **Cross-shard fallback bounded?** When a key is absent
//!      everywhere, `get` probes all N shards. We measure the worst
//!      case so any future regression in the fallback path shows up
//!      immediately. Linear in N, as expected.
//!
//! The bench compiles unconditionally (the wrapper degrades to single
//! shard on non-Linux / `--no-default-features`); under
//! `--features numa-aware` on a multi-socket Linux box, the
//! `current_thread_node` routing kicks in but the bench numbers are
//! still meaningful — the bench thread runs on whatever CPU the
//! scheduler picks.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr};
use zion::numa::NumaAwareMap;

fn populated_dashmap(n: u32) -> DashMap<IpAddr, u32> {
    let map = DashMap::new();
    for i in 0..n {
        let octets = i.to_be_bytes();
        let ip = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
        map.insert(ip, i);
    }
    map
}

fn populated_numa_single(n: u32) -> NumaAwareMap<IpAddr, u32> {
    let map = NumaAwareMap::with_shards(1);
    for i in 0..n {
        let octets = i.to_be_bytes();
        let ip = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
        map.insert(ip, i);
    }
    map
}

fn populated_numa_quad(n: u32) -> NumaAwareMap<IpAddr, u32> {
    // 4 shards. The bench thread inserts into shard[0] (the local
    // shard for tests), so `get` is always a local hit here.
    let map = NumaAwareMap::with_shards(4);
    for i in 0..n {
        let octets = i.to_be_bytes();
        let ip = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
        map.insert(ip, i);
    }
    map
}

fn bench_baseline_get(c: &mut Criterion) {
    let map = populated_dashmap(10_000);
    let probe = IpAddr::V4(Ipv4Addr::new(10, 0x01, 0x02, 0x03));
    let mut g = c.benchmark_group("numa/baseline_dashmap");
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_hit", |b| {
        b.iter(|| black_box(map.get(black_box(&probe)).map(|r| *r.value())))
    });
    let absent = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    g.bench_function("get_miss", |b| {
        b.iter(|| black_box(map.get(black_box(&absent)).is_none()))
    });
    g.finish();
}

fn bench_single_shard_get(c: &mut Criterion) {
    let map = populated_numa_single(10_000);
    let probe = IpAddr::V4(Ipv4Addr::new(10, 0x01, 0x02, 0x03));
    let mut g = c.benchmark_group("numa/single_shard");
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_hit", |b| {
        b.iter(|| black_box(map.get(black_box(&probe)).map(|r| *r.value())))
    });
    let absent = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    g.bench_function("get_miss", |b| {
        b.iter(|| black_box(map.get(black_box(&absent)).is_none()))
    });
    g.finish();
}

fn bench_quad_shard_local_hit(c: &mut Criterion) {
    let map = populated_numa_quad(10_000);
    // Sanity: bench thread routing must put every insert in shard[0]
    // (current_thread_node returns 0 off-feature). If this assertion
    // ever trips, the bench number below is no longer measuring
    // "local-shard hit" and should be re-interpreted.
    let lens = map.shard_lens();
    assert_eq!(
        lens[0], 10_000,
        "fixture must be entirely in shard[0]; got {lens:?}"
    );
    assert_eq!(
        lens[1] + lens[2] + lens[3],
        0,
        "fixture leaked outside shard[0]: {lens:?}"
    );

    let probe = IpAddr::V4(Ipv4Addr::new(10, 0x01, 0x02, 0x03));
    let mut g = c.benchmark_group("numa/quad_shard_local");
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_hit", |b| {
        b.iter(|| black_box(map.get(black_box(&probe)).map(|r| *r.value())))
    });
    g.finish();
}

fn bench_quad_shard_full_miss(c: &mut Criterion) {
    // Worst case: 4 shards, key absent everywhere → full scan.
    let map = populated_numa_quad(10_000);
    let absent = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let mut g = c.benchmark_group("numa/quad_shard_full_miss");
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_miss", |b| {
        b.iter(|| black_box(map.get(black_box(&absent)).is_none()))
    });
    g.finish();
}

fn bench_insert(c: &mut Criterion) {
    // `insert` purges remote shards before writing local — make sure
    // that overhead stays bounded on the 4-shard case.
    let mut g = c.benchmark_group("numa/insert");
    g.throughput(Throughput::Elements(1));

    g.bench_function("baseline_dashmap", |b| {
        let map = DashMap::new();
        let mut counter = 0u32;
        b.iter(|| {
            let octets = counter.to_be_bytes();
            counter = counter.wrapping_add(1);
            let ip = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
            map.insert(black_box(ip), black_box(counter));
        })
    });

    g.bench_function("single_shard", |b| {
        let map: NumaAwareMap<IpAddr, u32> = NumaAwareMap::with_shards(1);
        let mut counter = 0u32;
        b.iter(|| {
            let octets = counter.to_be_bytes();
            counter = counter.wrapping_add(1);
            let ip = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
            map.insert(black_box(ip), black_box(counter));
        })
    });

    g.bench_function("quad_shard", |b| {
        let map: NumaAwareMap<IpAddr, u32> = NumaAwareMap::with_shards(4);
        let mut counter = 0u32;
        b.iter(|| {
            let octets = counter.to_be_bytes();
            counter = counter.wrapping_add(1);
            let ip = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
            map.insert(black_box(ip), black_box(counter));
        })
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_baseline_get,
    bench_single_shard_get,
    bench_quad_shard_local_hit,
    bench_quad_shard_full_miss,
    bench_insert
);
criterion_main!(benches);
