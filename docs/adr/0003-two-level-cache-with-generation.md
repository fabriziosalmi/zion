# ADR-0003: Two-level cache with per-snapshot generation counter

- **Status**: accepted
- **Date**: 2026-04-29
- **Tags**: cache, concurrency, hot-reload

## Context

Static-cache routes (CSS / JS / fonts / images) need a memory cache that:

1. Has O(1) hit cost on the hot path (we're targeting 200K+ req/s on
   representative workloads).
2. Survives a config hot-reload — but only when the *cacheable* config
   for that route hasn't changed. A reload that flips a route from
   `static_cache` to `proxy` must invalidate the route's cached entries
   even though the bytes-on-disk haven't moved.
3. Coalesces concurrent misses for the same key into a single upstream
   fetch (singleflight) — N parallel requests for an uncached asset
   should produce 1 origin request, not N.

## Decision

Two cooperating caches plus a generation counter:

- **L1**: thread-local FNV-hashed LRU, ~256 entries / worker, intrusive
  doubly-linked list — pure O(1) get / insert / evict, zero locking.
- **L2**: `dashmap::DashMap` keyed by URL — sharded so high concurrency
  doesn't bottleneck on a single mutex. TTL is per-route, configurable
  in `[cache_profile]`.
- **Generation**: each `ResolvedAppConfig` snapshot ([ADR-0001](0001-arcswap-config-hot-reload.md))
  carries a monotonic `generation: u64`. Cache entries are tagged with
  the generation they were inserted under. A read that observes
  `entry.generation < state.cfg().generation` is a stale-read; it's
  treated as a miss and re-fetched.

Singleflight is implemented via `tokio::sync::watch::Sender<bool>`
stored in `inflight: DashMap<Arc<str>, _>`. The first miss inserts the
sender; subsequent misses subscribe and `wait_for(true)` — race-free
even when the fetcher completes between `get()` and `await` because
`watch::Receiver::wait_for` inspects the current value at first poll.

## Consequences

- **Positive**: L1 hit is O(1), thread-local, zero atomics. L2 hit is
  O(1) under the DashMap shard lock (only contended under cross-shard
  workloads, rare in practice).
- **Positive**: hot-reload of a `[cache_profile]` instantly invalidates
  the affected entries on the next read — no explicit purge, no stale
  serving window.
- **Positive**: singleflight delivers measurable origin-protection
  under cold-start / cache-miss storms.
- **Negative**: every cache entry carries a `u64` generation tag —
  acceptable storage overhead.
- **Neutral**: L1 / L2 coherence relies on the L1 entry holding a
  reference into the L2 *bytes*, not a copy, so eviction from L2 is
  observable via the L1 entry going stale on the next access.

## Alternatives considered

- **Single-tier DashMap-only cache** — simpler, but the per-shard
  lock cost shows up in microbenchmarks at our concurrency targets.
- **Explicit cache-key versioning in URLs** (the "fingerprint" pattern)
  — solves invalidation but pushes complexity to the operator's build
  pipeline. We support it, but the cache shouldn't *require* it.
- **Tokio `Notify` for singleflight** — race window between the fetcher
  signalling and a late waiter subscribing. `watch` doesn't have that
  hazard because it has stored state.

## References

- [src/cache.rs](../../src/cache.rs)
- [src/dispatch.rs](../../src/dispatch.rs) — `state.inflight` usage in
  `handle_static_cache`.
- Tokio `watch` docs: <https://docs.rs/tokio/latest/tokio/sync/watch/>
