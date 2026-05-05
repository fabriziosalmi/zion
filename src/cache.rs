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
}

/// L1 entry — with TTL from L2 (prevents stale data after expiry).
struct L1Entry {
    body: Bytes,
    meta: CachedMeta,
    expires_at: Instant,
    /// Cache generation at promotion time — stale if < StaticCache.generation.
    generation: u64,
}

/// L2 entry — with TTL.
struct L2Entry {
    body: Bytes,
    meta: CachedMeta,
    expires_at: Instant,
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
        let idx = *node_idx;
        self.touch(idx);

        Some(CacheHit { body, meta })
    }

    #[inline]
    fn insert(
        &mut self,
        path: Arc<str>,
        body: Bytes,
        meta: CachedMeta,
        expires_at: Instant,
        generation: u64,
    ) {
        // If key already exists, update in place and move to MRU
        if let Some((entry, node_idx)) = self.map.get_mut(path.as_ref()) {
            *entry = L1Entry {
                body,
                meta,
                expires_at,
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
                    expires_at,
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

/// Initialize thread-local L1 cache with detected capacity.
/// Called lazily on first access per thread.
#[allow(dead_code)]
fn ensure_l1(max_entries: usize) {
    L1.with(|l1| {
        let mut l1 = l1.borrow_mut();
        if l1.is_none() {
            *l1 = Some(L1Cache::new(max_entries));
        }
    });
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
        if self.l2.is_none() {
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
        }

        let Some(l2_concurrent) = &self.l2 else {
            unreachable!()
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

        // L2: shared DashMap
        let entry = l2_concurrent.get(path)?;
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
        let expires_at = entry.expires_at;
        drop(entry); // release DashMap read lock

        // Promote to L1 with same TTL and current generation
        L1.with(|l1| {
            let mut l1 = l1.borrow_mut();
            let l1 = l1.get_or_insert_with(|| L1Cache::new(l1_max));
            l1.insert(key, body.clone(), meta.clone(), expires_at, current_gen);
        });

        crate::metrics::METRICS
            .cache_hits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(CacheHit { body, meta })
    }

    /// Insert into L2 (source of truth). L1 populated lazily on next get.
    pub fn insert(
        &self,
        path: &str,
        body: Bytes,
        meta: CachedMeta,
        ttl_seconds: u64,
        max_entries: usize,
    ) {
        if self.l2.is_none() {
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
                m.insert(
                    Arc::from(path),
                    L2Entry {
                        body,
                        meta,
                        expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
                    },
                );
            });
            return;
        }

        let Some(l2_concurrent) = &self.l2 else {
            unreachable!()
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

        l2_concurrent.insert(
            Arc::from(path),
            L2Entry {
                body,
                meta,
                expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
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
        cache.insert("/a.js", Bytes::from("v1"), default_meta(), 3600, 100);
        let meta2 = CachedMeta {
            content_type: Some(HeaderValue::from_static("application/javascript")),
            content_encoding: None,
            status: StatusCode::OK,
        };
        cache.insert("/a.js", Bytes::from("v2"), meta2, 3600, 100);
        let hit = cache.get("/a.js").unwrap();
        assert_eq!(hit.body, Bytes::from("v2"));
        assert_eq!(hit.meta.content_type.unwrap(), "application/javascript");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn ttl_expiration() {
        let cache = StaticCache::new();
        cache.insert("/expired.js", Bytes::from("old"), default_meta(), 0, 100);
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.get("/expired.js").is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn max_entries_eviction() {
        let cache = StaticCache::new();
        cache.insert("/a", Bytes::from("a"), default_meta(), 3600, 3);
        cache.insert("/b", Bytes::from("b"), default_meta(), 3600, 3);
        cache.insert("/c", Bytes::from("c"), default_meta(), 3600, 3);
        assert_eq!(cache.len(), 3);

        cache.insert("/d", Bytes::from("d"), default_meta(), 3600, 3);
        assert_eq!(cache.len(), 3);
        assert!(cache.get("/d").is_some());
    }

    #[test]
    fn zero_max_entries_disables_eviction() {
        let cache = StaticCache::new();
        cache.insert("/a", Bytes::from("a"), default_meta(), 3600, 0);
        cache.insert("/b", Bytes::from("b"), default_meta(), 3600, 0);
        cache.insert("/c", Bytes::from("c"), default_meta(), 3600, 0);
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn empty_body_cacheable() {
        let cache = StaticCache::new();
        cache.insert("/empty", Bytes::new(), default_meta(), 3600, 100);
        assert!(cache.get("/empty").is_some());
    }

    #[test]
    fn large_body_cacheable() {
        let cache = StaticCache::new();
        let big = Bytes::from(vec![0xFFu8; 1024 * 1024]);
        cache.insert("/big.bin", big.clone(), default_meta(), 3600, 100);
        let hit = cache.get("/big.bin").unwrap();
        assert_eq!(hit.body, big);
    }

    #[test]
    fn l1_promotion() {
        let cache = StaticCache::new();
        cache.insert("/hot.js", Bytes::from("hot"), default_meta(), 3600, 100);

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
                c.insert(&key, val, default_meta(), 3600, 1000);
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
        cache.insert("/no-ct", Bytes::from("data"), meta, 3600, 100);
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
        cache.insert("/304", Bytes::new(), meta, 3600, 100);
        let hit = cache.get("/304").unwrap();
        assert_eq!(hit.meta.status, StatusCode::NOT_MODIFIED);
    }
}
