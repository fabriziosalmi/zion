// SPDX-License-Identifier: Apache-2.0
//! Two-level cache: L1 thread-local + L2 shared DashMap.
//!
//! L1: per-thread, zero contention, ~5ns lookup. LRU eviction.
//!     Sized from bootstrap detection (50% of L1d cache).
//! L2: shared DashMap, sharded lock-free, ~30ns lookup. TTL eviction.
//!     Sized from config (max_entries + ttl_seconds).
//!
//! Lookup: L1 hit → return (no atomic). L1 miss → L2 hit → promote to L1 → return.
//! Insert: write to L2 (source of truth). L1 populated lazily on get.

use bytes::Bytes;
use dashmap::DashMap;
use hyper::header::HeaderValue;
use hyper::StatusCode;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached response metadata — stored alongside the body so cache hits
/// preserve upstream Content-Type, Content-Encoding, status, and other
/// essential headers.
#[derive(Clone, Debug)]
pub struct CachedMeta {
    pub content_type: Option<HeaderValue>,
    pub content_encoding: Option<HeaderValue>,
    pub status: StatusCode,
}

/// Result of a cache hit — body + preserved metadata.
#[derive(Clone)]
pub struct CacheHit {
    pub body: Bytes,
    pub meta: CachedMeta,
    /// Seconds since the origin generated this response — the value to emit as
    /// the `Age` header. Seeded from the upstream `Age` at insert (so time
    /// spent in the shield Varnish counts) plus the time the entry has lived in
    /// zion's cache. Without this, downstream caches reset their freshness
    /// clock on every hit and serve content far past its real lifetime.
    pub age_secs: u64,
    /// The entry's freshness lifetime in seconds — the `max-age` to emit so
    /// downstream caches compute the same expiry zion does.
    pub max_age_secs: u64,
}

/// L1 entry — with TTL from L2 (prevents stale data after expiry).
struct L1Entry {
    body: Bytes,
    meta: CachedMeta,
    inserted_at: Instant,
    expires_at: Instant,
    /// Age the object already carried on arrival (upstream `Age` header).
    initial_age_secs: u64,
    /// Freshness lifetime used for this entry (origin-derived, clamped to profile).
    freshness_secs: u64,
    /// Cache generation at promotion time — stale if < StaticCache.generation.
    generation: u64,
}

/// L2 entry — with TTL.
struct L2Entry {
    body: Bytes,
    meta: CachedMeta,
    inserted_at: Instant,
    expires_at: Instant,
    /// Age the object already carried on arrival (upstream `Age` header).
    initial_age_secs: u64,
    /// Freshness lifetime used for this entry (origin-derived, clamped to profile).
    freshness_secs: u64,
}

/// Expiry instant from a freshness lifetime and the age the object already
/// carried on arrival. An object that arrives already older than its freshness
/// lifetime expires immediately (`expires_at == now`).
#[inline]
fn expiry_from(now: Instant, freshness_secs: u64, initial_age_secs: u64) -> Instant {
    now + Duration::from_secs(freshness_secs.saturating_sub(initial_age_secs))
}

/// Thread-local L1 cache with O(1) LRU eviction.
///
/// Uses a HashMap for O(1) lookup + a compact doubly-linked list via Vec
/// indices for O(1) touch/evict. No linear scans — all operations are O(1).
/// The linked list tracks access order: head = LRU (evict first), tail = MRU.
struct L1Cache {
    /// Key → (entry, node index in `nodes`)
    map: HashMap<Arc<str>, (L1Entry, usize)>,
    /// Doubly-linked list nodes stored in a Vec (cache-line friendly)
    nodes: Vec<LruNode>,
    /// Free list of recycled node indices
    free: Vec<usize>,
    /// Index of LRU head (oldest), or usize::MAX if empty
    head: usize,
    /// Index of MRU tail (newest), or usize::MAX if empty
    tail: usize,
    max_entries: usize,
}

struct LruNode {
    key: Arc<str>,
    prev: usize, // usize::MAX = no prev
    next: usize, // usize::MAX = no next
}

const NIL: usize = usize::MAX;

impl L1Cache {
    fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::with_capacity(max_entries),
            nodes: Vec::with_capacity(max_entries),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
            max_entries,
        }
    }

    /// Allocate a node index (reuse from free list or push new)
    #[inline]
    fn alloc_node(&mut self, key: Arc<str>) -> usize {
        if let Some(idx) = self.free.pop() {
            self.nodes[idx] = LruNode {
                key,
                prev: NIL,
                next: NIL,
            };
            idx
        } else {
            let idx = self.nodes.len();
            self.nodes.push(LruNode {
                key,
                prev: NIL,
                next: NIL,
            });
            idx
        }
    }

    /// Unlink a node from the list (O(1))
    #[inline]
    fn unlink(&mut self, idx: usize) {
        let prev = self.nodes[idx].prev;
        let next = self.nodes[idx].next;
        if prev != NIL {
            self.nodes[prev].next = next;
        } else {
            self.head = next;
        }
        if next != NIL {
            self.nodes[next].prev = prev;
        } else {
            self.tail = prev;
        }
        self.nodes[idx].prev = NIL;
        self.nodes[idx].next = NIL;
    }

    /// Append a node to tail (MRU position) — O(1)
    #[inline]
    fn push_tail(&mut self, idx: usize) {
        self.nodes[idx].prev = self.tail;
        self.nodes[idx].next = NIL;
        if self.tail != NIL {
            self.nodes[self.tail].next = idx;
        } else {
            self.head = idx;
        }
        self.tail = idx;
    }

    /// Move a node to MRU position — O(1) unlink + push_tail
    #[inline]
    fn touch(&mut self, idx: usize) {
        self.unlink(idx);
        self.push_tail(idx);
    }

    #[inline]
    fn get(&mut self, path: &str, current_gen: u64) -> Option<CacheHit> {
        let (entry, node_idx) = self.map.get(path)?;
        if Instant::now() >= entry.expires_at || entry.generation < current_gen {
            // Expired or stale generation — remove
            let idx = *node_idx;
            self.unlink(idx);
            self.free.push(idx);
            self.map.remove(path);
            return None;
        }
        let body = entry.body.clone();
        let meta = entry.meta.clone();
        let age_secs = entry.initial_age_secs + entry.inserted_at.elapsed().as_secs();
        let max_age_secs = entry.freshness_secs;
        let idx = *node_idx;
        self.touch(idx);

        Some(CacheHit {
            body,
            meta,
            age_secs,
            max_age_secs,
        })
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        path: Arc<str>,
        body: Bytes,
        meta: CachedMeta,
        inserted_at: Instant,
        expires_at: Instant,
        initial_age_secs: u64,
        freshness_secs: u64,
        generation: u64,
    ) {
        // If key already exists, update in place and move to MRU
        if let Some((entry, node_idx)) = self.map.get_mut(path.as_ref()) {
            *entry = L1Entry {
                body,
                meta,
                inserted_at,
                expires_at,
                initial_age_secs,
                freshness_secs,
                generation,
            };
            let idx = *node_idx;
            self.touch(idx);
            return;
        }

        // Evict LRU entries until we have space
        while self.map.len() >= self.max_entries && self.head != NIL {
            let lru_idx = self.head;
            let lru_key = self.nodes[lru_idx].key.clone();
            self.unlink(lru_idx);
            self.free.push(lru_idx);
            self.map.remove(&lru_key);
        }

        let idx = self.alloc_node(path.clone());
        self.push_tail(idx);
        self.map.insert(
            path,
            (
                L1Entry {
                    body,
                    meta,
                    inserted_at,
                    expires_at,
                    initial_age_secs,
                    freshness_secs,
                    generation,
                },
                idx,
            ),
        );
    }
}

thread_local! {
    static L1: RefCell<Option<L1Cache>> = const { RefCell::new(None) };
}

thread_local! {
    static LOCAL_L2: RefCell<HashMap<Arc<str>, L2Entry>> = RefCell::new(HashMap::new());
}

/// Two-level static cache.
pub struct StaticCache {
    l2: Option<DashMap<Arc<str>, L2Entry>>,
    l1_max_entries: usize,
    /// Monotonic counter bumped on every L2 insert/update.
    /// L1 caches store the generation at promotion time; on get, if the
    /// global generation has advanced, the L1 entry is stale and re-fetched
    /// from L2. This prevents serving stale data for the TTL duration.
    generation: std::sync::atomic::AtomicU64,
}

impl StaticCache {
    pub fn new() -> Self {
        let platform = crate::bootstrap::detect();
        let l1_max = platform.l1_hot_entries;
        // Phase 2 Tuning: adaptive backend fallback
        // If we only have 1 worker thread (e.g. 1 vCPU docker container), DashMap lock sharding
        // generates pointless context switching overhead. We bypass it entirely.
        let l2 = if platform.worker_threads < 2 {
            crate::logging::info("cache", "deploying single-core lock-free backend");
            None
        } else {
            Some(DashMap::new())
        };

        Self {
            l2,
            l1_max_entries: l1_max,
            generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn get(&self, path: &str) -> Option<CacheHit> {
        let l1_max = self.l1_max_entries;

        // If Single-Core fallback is active, bypass L1/L2 distinction.
        // The L2 becomes thread-local Hashmap (L1 speed for all misses).
        // `let-else` binds l2 for the concurrent path below and diverges
        // (returns) on the single-core path — this replaces a later
        // `unreachable!()` that was a latent process-abort under panic=abort.
        let Some(l2_concurrent) = &self.l2 else {
            let mut expired = false;
            let hit = LOCAL_L2.with(|map| {
                let m = map.borrow();
                if let Some(entry) = m.get(path) {
                    if Instant::now() >= entry.expires_at {
                        expired = true;
                        None
                    } else {
                        Some(CacheHit {
                            body: entry.body.clone(),
                            meta: entry.meta.clone(),
                            age_secs: entry.initial_age_secs
                                + entry.inserted_at.elapsed().as_secs(),
                            max_age_secs: entry.freshness_secs,
                        })
                    }
                } else {
                    None
                }
            });
            if expired {
                LOCAL_L2.with(|map| map.borrow_mut().remove(path));
            }
            if hit.is_some() {
                crate::metrics::METRICS
                    .cache_hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                crate::metrics::METRICS
                    .cache_misses
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return hit;
        };

        let current_gen = self.generation.load(std::sync::atomic::Ordering::Acquire);

        // L1: thread-local, zero contention
        let l1_hit = L1.with(|l1| {
            let mut l1 = l1.borrow_mut();
            let l1 = l1.get_or_insert_with(|| L1Cache::new(l1_max));
            l1.get(path, current_gen)
        });

        if let Some(hit) = l1_hit {
            crate::metrics::METRICS
                .cache_hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some(hit);
        }

        // L2: shared DashMap. A true absence is a miss and must be counted —
        // the bare `?` here previously returned None without recording it, so
        // on multi-core builds cache_misses was undercounted and the reported
        // hit-rate inflated.
        let Some(entry) = l2_concurrent.get(path) else {
            crate::metrics::METRICS
                .cache_misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        };
        if Instant::now() >= entry.expires_at {
            drop(entry);
            l2_concurrent.remove(path);
            crate::metrics::METRICS
                .cache_misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        let body = entry.body.clone();
        let meta = entry.meta.clone();
        let key: Arc<str> = entry.key().clone();
        let inserted_at = entry.inserted_at;
        let expires_at = entry.expires_at;
        let initial_age_secs = entry.initial_age_secs;
        let freshness_secs = entry.freshness_secs;
        drop(entry); // release DashMap read lock

        // Promote to L1 preserving the original birth time, TTL and generation.
        L1.with(|l1| {
            let mut l1 = l1.borrow_mut();
            let l1 = l1.get_or_insert_with(|| L1Cache::new(l1_max));
            l1.insert(
                key,
                body.clone(),
                meta.clone(),
                inserted_at,
                expires_at,
                initial_age_secs,
                freshness_secs,
                current_gen,
            );
        });

        crate::metrics::METRICS
            .cache_hits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(CacheHit {
            body,
            meta,
            age_secs: initial_age_secs + inserted_at.elapsed().as_secs(),
            max_age_secs: freshness_secs,
        })
    }

    /// Insert into L2 (source of truth). L1 populated lazily on next get.
    ///
    /// `freshness_secs` is the entry's freshness lifetime (origin `max-age` /
    /// `s-maxage`, clamped to the profile TTL by the caller). `initial_age_secs`
    /// is the age the object already carried on arrival (upstream `Age` header),
    /// so an object cached behind the shield Varnish expires at the right wall
    /// time rather than getting a fresh full lifetime at every tier.
    pub fn insert(
        &self,
        path: &str,
        body: Bytes,
        meta: CachedMeta,
        freshness_secs: u64,
        initial_age_secs: u64,
        max_entries: usize,
    ) {
        // `let-else`: bind l2 for the concurrent path, diverge (return) on the
        // single-core path — mirrors get(), removes the `unreachable!()` abort.
        let Some(l2_concurrent) = &self.l2 else {
            // Lock-free single-core backend insertion
            LOCAL_L2.with(|map| {
                let mut m = map.borrow_mut();
                if max_entries > 0 && m.len() >= max_entries {
                    let now = Instant::now();
                    let mut expired_keys = Vec::new();
                    let mut oldest_key = None;
                    let mut oldest_expiry = now + Duration::from_secs(86400 * 365);
                    for (k, v) in m.iter().take(64) {
                        if now >= v.expires_at {
                            expired_keys.push(k.clone());
                        } else if v.expires_at < oldest_expiry {
                            oldest_expiry = v.expires_at;
                            oldest_key = Some(k.clone());
                        }
                    }
                    for k in &expired_keys {
                        m.remove(k);
                    }
                    if expired_keys.is_empty() {
                        if let Some(k) = oldest_key {
                            m.remove(&k);
                        }
                    }
                }
                let now = Instant::now();
                m.insert(
                    Arc::from(path),
                    L2Entry {
                        body,
                        meta,
                        inserted_at: now,
                        expires_at: expiry_from(now, freshness_secs, initial_age_secs),
                        initial_age_secs,
                        freshness_secs,
                    },
                );
            });
            return;
        };

        if max_entries > 0 && l2_concurrent.len() >= max_entries {
            let now = Instant::now();

            // Sampled eviction: scan at most 64 entries to avoid O(N) full scan.
            // Phase 1: collect expired entries from sample.
            let sample_size = 64.min(l2_concurrent.len());
            let mut expired_keys: Vec<Arc<str>> = Vec::new();
            let mut oldest_key: Option<Arc<str>> = None;
            let mut oldest_expiry = Instant::now() + Duration::from_secs(86400 * 365);

            for (i, entry) in l2_concurrent.iter().enumerate() {
                if i >= sample_size {
                    break;
                }
                if now >= entry.expires_at {
                    expired_keys.push(entry.key().clone());
                } else if entry.expires_at < oldest_expiry {
                    oldest_expiry = entry.expires_at;
                    oldest_key = Some(entry.key().clone());
                }
            }

            // Remove expired entries
            for key in &expired_keys {
                l2_concurrent.remove(key);
            }

            // Phase 2: if still full after removing expired, evict closest-to-expiry from sample
            if expired_keys.is_empty() {
                if let Some(key) = oldest_key {
                    l2_concurrent.remove(&key);
                }
            }
        }

        let now = Instant::now();
        l2_concurrent.insert(
            Arc::from(path),
            L2Entry {
                body,
                meta,
                inserted_at: now,
                expires_at: expiry_from(now, freshness_secs, initial_age_secs),
                initial_age_secs,
                freshness_secs,
            },
        );
        // Bump generation so L1 caches on other threads see the update
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        if let Some(l2_concurrent) = &self.l2 {
            l2_concurrent.len()
        } else {
            LOCAL_L2.with(|m| m.borrow().len())
        }
    }

    /// Purge the whole cache. Clears L2 (source of truth) and bumps the
    /// generation so every thread-local L1 entry is treated as stale on its
    /// next get — no cross-thread iteration needed. Returns the number of L2
    /// entries dropped. Lets a deploy hook invalidate immediately instead of
    /// waiting out the TTL.
    pub fn purge_all(&self) -> usize {
        let n = if let Some(l2) = &self.l2 {
            let n = l2.len();
            l2.clear();
            n
        } else {
            LOCAL_L2.with(|m| {
                let mut m = m.borrow_mut();
                let n = m.len();
                m.clear();
                n
            })
        };
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        n
    }

    /// Purge L2 entries whose key (path+query) starts with `prefix`. Returns
    /// the count removed. Bumps the generation, which lazily invalidates ALL
    /// L1 entries (not just the prefix) — over-broad but safe: unaffected keys
    /// simply re-promote from L2 on next get. The common deploy case
    /// (invalidate `/assets/...`) is well served.
    pub fn purge_prefix(&self, prefix: &str) -> usize {
        let mut removed = 0;
        if let Some(l2) = &self.l2 {
            let keys: Vec<Arc<str>> = l2
                .iter()
                .filter(|e| e.key().starts_with(prefix))
                .map(|e| e.key().clone())
                .collect();
            for k in &keys {
                l2.remove(k);
                removed += 1;
            }
        } else {
            LOCAL_L2.with(|m| {
                let mut m = m.borrow_mut();
                let keys: Vec<Arc<str>> = m
                    .keys()
                    .filter(|k| k.starts_with(prefix))
                    .cloned()
                    .collect();
                for k in &keys {
                    m.remove(k);
                    removed += 1;
                }
            });
        }
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_meta() -> CachedMeta {
        CachedMeta {
            content_type: Some(HeaderValue::from_static("text/css")),
            content_encoding: None,
            status: StatusCode::OK,
        }
    }

    #[test]
    fn insert_and_get() {
        let cache = StaticCache::new();
        cache.insert(
            "/style.css",
            Bytes::from("body{}"),
            default_meta(),
            3600,
            0,
            100,
        );
        let hit = cache.get("/style.css").unwrap();
        assert_eq!(hit.body, Bytes::from("body{}"));
        assert_eq!(hit.meta.content_type.unwrap(), "text/css");
        assert_eq!(hit.meta.status, StatusCode::OK);
    }

    #[test]
    fn get_miss_returns_none() {
        let cache = StaticCache::new();
        assert!(cache.get("/nonexistent").is_none());
    }

    #[test]
    fn insert_overwrites_existing() {
        let cache = StaticCache::new();
        cache.insert("/a.js", Bytes::from("v1"), default_meta(), 3600, 0, 100);
        let meta2 = CachedMeta {
            content_type: Some(HeaderValue::from_static("application/javascript")),
            content_encoding: None,
            status: StatusCode::OK,
        };
        cache.insert("/a.js", Bytes::from("v2"), meta2, 3600, 0, 100);
        let hit = cache.get("/a.js").unwrap();
        assert_eq!(hit.body, Bytes::from("v2"));
        assert_eq!(hit.meta.content_type.unwrap(), "application/javascript");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn ttl_expiration() {
        let cache = StaticCache::new();
        cache.insert("/expired.js", Bytes::from("old"), default_meta(), 0, 0, 100);
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.get("/expired.js").is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn max_entries_eviction() {
        let cache = StaticCache::new();
        cache.insert("/a", Bytes::from("a"), default_meta(), 3600, 0, 3);
        cache.insert("/b", Bytes::from("b"), default_meta(), 3600, 0, 3);
        cache.insert("/c", Bytes::from("c"), default_meta(), 3600, 0, 3);
        assert_eq!(cache.len(), 3);

        cache.insert("/d", Bytes::from("d"), default_meta(), 3600, 0, 3);
        assert_eq!(cache.len(), 3);
        assert!(cache.get("/d").is_some());
    }

    #[test]
    fn zero_max_entries_disables_eviction() {
        let cache = StaticCache::new();
        cache.insert("/a", Bytes::from("a"), default_meta(), 3600, 0, 0);
        cache.insert("/b", Bytes::from("b"), default_meta(), 3600, 0, 0);
        cache.insert("/c", Bytes::from("c"), default_meta(), 3600, 0, 0);
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn empty_body_cacheable() {
        let cache = StaticCache::new();
        cache.insert("/empty", Bytes::new(), default_meta(), 3600, 0, 100);
        assert!(cache.get("/empty").is_some());
    }

    #[test]
    fn large_body_cacheable() {
        let cache = StaticCache::new();
        let big = Bytes::from(vec![0xFFu8; 1024 * 1024]);
        cache.insert("/big.bin", big.clone(), default_meta(), 3600, 0, 100);
        let hit = cache.get("/big.bin").unwrap();
        assert_eq!(hit.body, big);
    }

    #[test]
    fn l1_promotion() {
        let cache = StaticCache::new();
        cache.insert("/hot.js", Bytes::from("hot"), default_meta(), 3600, 0, 100);

        // First get: L2 hit + L1 promote
        assert!(cache.get("/hot.js").is_some());

        // Second get: should be L1 hit (no way to verify directly,
        // but we can verify correctness)
        let hit = cache.get("/hot.js").unwrap();
        assert_eq!(hit.body, Bytes::from("hot"));
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(StaticCache::new());
        let mut handles = vec![];

        for i in 0..10 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                let key = format!("/item/{i}");
                let val = Bytes::from(format!("value-{i}"));
                c.insert(&key, val, default_meta(), 3600, 0, 1000);
            }));
        }

        for _ in 0..10 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                for i in 0..10 {
                    let key = format!("/item/{i}");
                    let _ = c.get(&key);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn preserves_content_type_none() {
        let cache = StaticCache::new();
        let meta = CachedMeta {
            content_type: None,
            content_encoding: None,
            status: StatusCode::OK,
        };
        cache.insert("/no-ct", Bytes::from("data"), meta, 3600, 0, 100);
        let hit = cache.get("/no-ct").unwrap();
        assert!(hit.meta.content_type.is_none());
    }

    #[test]
    fn preserves_status_code() {
        let cache = StaticCache::new();
        let meta = CachedMeta {
            content_type: None,
            content_encoding: None,
            status: StatusCode::NOT_MODIFIED,
        };
        cache.insert("/304", Bytes::new(), meta, 3600, 0, 100);
        let hit = cache.get("/304").unwrap();
        assert_eq!(hit.meta.status, StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn hit_reports_freshness_as_max_age() {
        let cache = StaticCache::new();
        cache.insert("/a.css", Bytes::from("x"), default_meta(), 600, 0, 100);
        let hit = cache.get("/a.css").unwrap();
        assert_eq!(hit.max_age_secs, 600);
    }

    #[test]
    fn fresh_entry_has_zero_age() {
        let cache = StaticCache::new();
        cache.insert("/a.css", Bytes::from("x"), default_meta(), 600, 0, 100);
        let hit = cache.get("/a.css").unwrap();
        // Just inserted with no upstream age — Age must be ~0, never the lifetime.
        assert_eq!(hit.age_secs, 0);
    }

    #[test]
    fn initial_age_is_carried_into_age_header() {
        // Object arrived from the shield already 120s old (upstream Age: 120).
        let cache = StaticCache::new();
        cache.insert("/a.css", Bytes::from("x"), default_meta(), 600, 120, 100);
        let hit = cache.get("/a.css").unwrap();
        assert!(
            hit.age_secs >= 120,
            "Age must include the upstream age, got {}",
            hit.age_secs
        );
    }

    #[test]
    fn purge_all_empties_and_invalidates() {
        let cache = StaticCache::new();
        cache.insert("/a.css", Bytes::from("a"), default_meta(), 3600, 0, 100);
        cache.insert("/b.css", Bytes::from("b"), default_meta(), 3600, 0, 100);
        assert!(cache.get("/a.css").is_some()); // promote into L1
        let n = cache.purge_all();
        assert_eq!(n, 2);
        assert_eq!(cache.len(), 0);
        // L1 entry must be treated as stale after the generation bump
        assert!(cache.get("/a.css").is_none());
        assert!(cache.get("/b.css").is_none());
    }

    #[test]
    fn purge_prefix_removes_only_matching() {
        let cache = StaticCache::new();
        cache.insert(
            "/assets/x.js",
            Bytes::from("x"),
            default_meta(),
            3600,
            0,
            100,
        );
        cache.insert(
            "/assets/y.js",
            Bytes::from("y"),
            default_meta(),
            3600,
            0,
            100,
        );
        cache.insert(
            "/index.html",
            Bytes::from("h"),
            default_meta(),
            3600,
            0,
            100,
        );
        let n = cache.purge_prefix("/assets/");
        assert_eq!(n, 2);
        assert!(cache.get("/assets/x.js").is_none());
        assert!(
            cache.get("/index.html").is_some(),
            "non-matching key survives"
        );
    }

    #[test]
    fn initial_age_shortens_lifetime() {
        // Freshness 100s but already 100s old on arrival → already stale.
        let cache = StaticCache::new();
        cache.insert("/stale", Bytes::from("x"), default_meta(), 100, 100, 100);
        assert!(
            cache.get("/stale").is_none(),
            "an object that arrives already past its lifetime must not be served"
        );
    }
}
