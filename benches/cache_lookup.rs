// SPDX-License-Identifier: Apache-2.0
//! Microbench: cache lookup paths.
//!
//! Measures the same shape `crate::cache::StaticCache` exposes, but on
//! synthetic fixtures so the bench does not pull in `crate::bootstrap`,
//! `crate::metrics`, or `crate::reload` (none of which fit a portable
//! lib surface — they touch hardware probes and global atomics owned
//! by the binary).
//!
//! What's modeled:
//!   * **L1 hit**: thread-local `HashMap<Arc<str>, Bytes>` lookup. Same
//!     data shape as `cache::L1Cache` (LRU touched only on miss; hits
//!     are pure reads).
//!   * **L2 hit**: `dashmap::DashMap<Arc<str>, Bytes>` get + clone of
//!     a small body. Mirrors the production hot path step-for-step.
//!   * **Full miss**: lookup against an empty L1 + L2 (`get` returns
//!     `None`).
//!   * **Singleflight coalesce**: when N callers race on the same miss,
//!     only one origin fetch fires; the rest park on a oneshot. Modeled
//!     here with `tokio::sync::OnceCell` to bound the contention cost.
//!
//! If `crate::cache` ever grows a more reachable test surface (e.g.
//! `pub use cache::StaticCache` from `lib.rs`), this bench should be
//! migrated to it. Until then, the synthetic shape is close enough to
//! detect regressions in the *algorithms* — not the wiring.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use dashmap::DashMap;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

const POPULATED: usize = 10_000;
const SMALL_BODY: usize = 256;

fn body(size: usize) -> Bytes {
    Bytes::from(vec![b'x'; size])
}

fn make_keys(n: usize) -> Vec<Arc<str>> {
    (0..n)
        .map(|i| Arc::<str>::from(format!("/path/segment/{i}")))
        .collect()
}

fn populated_l2(n: usize) -> (DashMap<Arc<str>, Bytes>, Vec<Arc<str>>) {
    let map = DashMap::with_capacity(n);
    let keys = make_keys(n);
    for k in &keys {
        map.insert(k.clone(), body(SMALL_BODY));
    }
    (map, keys)
}

thread_local! {
    static L1_FIXTURE: RefCell<HashMap<Arc<str>, Bytes>> = RefCell::new(HashMap::new());
}

fn populate_thread_local(keys: &[Arc<str>]) {
    L1_FIXTURE.with(|m| {
        let mut m = m.borrow_mut();
        m.clear();
        for k in keys {
            m.insert(k.clone(), body(SMALL_BODY));
        }
    });
}

fn bench_l1_hit(c: &mut Criterion) {
    let keys = make_keys(POPULATED);
    populate_thread_local(&keys);
    let probe = keys[POPULATED / 2].clone();

    let mut g = c.benchmark_group("cache/l1");
    g.throughput(Throughput::Elements(1));
    g.bench_function("hit", |b| {
        b.iter(|| {
            L1_FIXTURE.with(|m| {
                let m = m.borrow();
                let r = m.get(black_box(&*probe));
                black_box(r.cloned())
            })
        })
    });
    g.bench_function("miss", |b| {
        let absent: Arc<str> = Arc::from("/not/in/l1");
        b.iter(|| {
            L1_FIXTURE.with(|m| {
                let m = m.borrow();
                black_box(m.get(black_box(&*absent)).cloned())
            })
        })
    });
    g.finish();
}

fn bench_l2_hit(c: &mut Criterion) {
    let (map, keys) = populated_l2(POPULATED);
    let probe = keys[POPULATED / 2].clone();
    let absent: Arc<str> = Arc::from("/not/in/l2");

    let mut g = c.benchmark_group("cache/l2");
    g.throughput(Throughput::Elements(1));
    g.bench_function("hit", |b| {
        b.iter(|| {
            let entry = map.get(black_box(&probe));
            black_box(entry.map(|e| e.value().clone()))
        })
    });
    g.bench_function("miss", |b| {
        b.iter(|| {
            let entry = map.get(black_box(&absent));
            black_box(entry.is_none())
        })
    });
    g.finish();
}

fn bench_full_miss(c: &mut Criterion) {
    // Empty L1 + L2: both reads miss, we measure the cost of failing fast.
    let l2: DashMap<Arc<str>, Bytes> = DashMap::new();
    let probe: Arc<str> = Arc::from("/anything");

    let mut g = c.benchmark_group("cache/full_miss");
    g.throughput(Throughput::Elements(1));
    g.bench_function("l1_then_l2_both_miss", |b| {
        b.iter(|| {
            let l1_hit = L1_FIXTURE.with(|m| m.borrow().get(&*probe).cloned());
            if l1_hit.is_some() {
                return black_box(l1_hit);
            }
            let entry = l2.get(black_box(&probe));
            black_box(entry.map(|e| e.value().clone()))
        })
    });
    g.finish();
}

fn bench_singleflight_coalesce(c: &mut Criterion) {
    // Coalesce model: N callers race on the same miss. Without coalescing
    // each caller would fire an origin fetch; with `OnceCell` only the
    // first does the work, the rest park on it. We bench the single-call
    // path here (no contention) — the value is the regression baseline:
    // any future singleflight-coalesce implementation must not regress
    // this number in the uncontended case.
    use tokio::sync::OnceCell;
    let cell: OnceCell<Bytes> = OnceCell::new();
    cell.set(body(SMALL_BODY)).unwrap();

    let mut g = c.benchmark_group("cache/singleflight");
    g.throughput(Throughput::Elements(1));
    g.bench_function("oncecell_uncontended_get", |b| {
        b.iter(|| black_box(cell.get().cloned()))
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_l1_hit,
    bench_l2_hit,
    bench_full_miss,
    bench_singleflight_coalesce
);
criterion_main!(benches);
