// SPDX-License-Identifier: Apache-2.0
//! Microbench: the per-thread route cache that `dispatch::route::resolve` reads first.
//!
//! The cache is the real one: `src/dispatch/route_cache.rs` is included as a module, so these
//! numbers come from the code that runs, slot hash and full-key compare included. The value is an
//! `Arc`, as the production `Arc<ResolvedRoute>`, so a hit pays the same refcount bump.
//!
//! What's measured:
//!   * **hit, no host**: `route_cache_key` plus `get` for a path the cache holds, without host
//!     routing (`host = None`, the hostless deployment).
//!   * **hit, host**: the same with a host, as when any route is host-bound.
//!   * **radix**: a `matchit` lookup in a tree of 17 routes (16 prefixes and a catch-all), the
//!     lookup a miss falls through to. The production `HostRouter` adds one `HashMap` probe for
//!     the host when host routing is on; it is built from a parsed config, which a bench cannot
//!     reach, so it is not included.
//!   * **miss**: what `resolve` does when the path is not cached: a `get` that misses, the radix
//!     lookup, and the `insert` that evicts the least recently used entry (512 distinct paths
//!     cycled through a cache of 256, so every lookup misses).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;

#[allow(dead_code)]
#[path = "../src/dispatch/route_cache.rs"]
mod route_cache;

use route_cache::{route_cache_key, RouteCache, ROUTE_CACHE_CAP};

const HOST: &str = "api.example.com";
const HOT: &str = "/api/v1/users/42/profile";

fn paths(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("/api/v1/items/{i}/detail"))
        .collect()
}

/// A full cache (`ROUTE_CACHE_CAP` entries) that holds `HOT`, keyed with `host`.
fn full_cache(host: Option<&str>) -> RouteCache<Arc<u32>> {
    let mut c = RouteCache::new(ROUTE_CACHE_CAP);
    for (i, p) in paths(ROUTE_CACHE_CAP - 1).iter().enumerate() {
        c.insert(route_cache_key(host, p), host, p, Arc::new(i as u32));
    }
    c.insert(route_cache_key(host, HOT), host, HOT, Arc::new(u32::MAX));
    c
}

fn radix() -> matchit::Router<Arc<u32>> {
    let mut r = matchit::Router::new();
    for (i, prefix) in [
        "api/v1/users",
        "api/v1/items",
        "api/v1/orders",
        "api/v1/search",
        "api/v2/users",
        "api/v2/items",
        "static",
        "assets",
        "img",
        "auth",
        "admin",
        "ws",
        "events",
        "health",
        "docs",
        "blog",
    ]
    .iter()
    .enumerate()
    {
        r.insert(format!("/{prefix}/{{*rest}}"), Arc::new(i as u32))
            .unwrap();
    }
    r.insert("/{*rest}", Arc::new(999)).unwrap();
    r
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("route_cache");

    let mut hostless = full_cache(None);
    g.bench_function("hit_no_host", |b| {
        b.iter(|| {
            let path = black_box(HOT);
            let key = route_cache_key(None, path);
            hostless.get(key, None, path)
        })
    });

    let mut hosted = full_cache(Some(HOST));
    g.bench_function("hit_host", |b| {
        b.iter(|| {
            let (host, path) = (black_box(HOST), black_box(HOT));
            let key = route_cache_key(Some(host), path);
            hosted.get(key, Some(host), path)
        })
    });

    let router = radix();
    g.bench_function("radix", |b| {
        b.iter(|| router.at(black_box(HOT)).ok().map(|m| m.value.clone()))
    });

    let cycle = paths(2 * ROUTE_CACHE_CAP);
    let mut cold = RouteCache::new(ROUTE_CACHE_CAP);
    let mut i = 0usize;
    g.bench_function("miss", |b| {
        b.iter(|| {
            let path = cycle[i % cycle.len()].as_str();
            i = i.wrapping_add(1);
            let key = route_cache_key(None, path);
            if let Some(route) = cold.get(key, None, path) {
                return Some(route);
            }
            let route = router.at(path).ok()?.value.clone();
            cold.insert(key, None, path, route.clone());
            Some(route)
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
