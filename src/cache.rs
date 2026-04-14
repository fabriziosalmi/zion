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

/// Thread-local L1 cache. One per tokio worker thread.
/// Uses a VecDeque as an LRU eviction queue for true O(1) eviction.
/// The deque maintains access order (front = oldest, back = newest).
struct L1Cache {
    map: HashMap<Arc<str>, L1Entry>,
    /// LRU eviction queue — front is oldest, back is most recently used.
    /// On eviction, pop_front() in O(1). On access, move-to-back.
    order: std::collections::VecDeque<Arc<str>>,
    max_entries: usize,
}

impl L1Cache {
    fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::with_capacity(max_entries),
            order: std::collections::VecDeque::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Move a key to the back of the eviction queue (most recently used).
    /// O(N) in theory but L1 is tiny (32–128 entries), so this is ~3ns.
    #[inline]
    fn touch(&mut self, key: &Arc<str>) {
        // Remove from current position (linear scan on small deque)
        if let Some(pos) = self.order.iter().position(|k| k.as_ref() == key.as_ref()) {
            self.order.remove(pos);
        }
        self.order.push_back(key.clone());
    }

    #[inline]
    fn get(&mut self, path: &str, current_gen: u64) -> Option<CacheHit> {
        // Check if entry exists
        let (body, meta, expired, key) = {
            let entry = self.map.get(path)?;
            if Instant::now() >= entry.expires_at || entry.generation < current_gen {
                (None, None, true, None)
            } else {
                (
                    Some(entry.body.clone()),
                    Some(entry.meta.clone()),
                    false,
                    // Find the key Arc for touch
                    self.order.iter().find(|k| k.as_ref() == path).cloned(),
                )
            }
        };

        if expired {
            self.map.remove(path);
            self.order.retain(|k| k.as_ref() != path);
            return None;
        }

        if let Some(key) = key {
            self.touch(&key);
        }

        Some(CacheHit {
            body: body.unwrap(),
            meta: meta.unwrap(),
        })
    }

    #[inline]
    fn insert(&mut self, path: Arc<str>, body: Bytes, meta: CachedMeta, expires_at: Instant, generation: u64) {
        // If key already exists, update in place and move to back
        if self.map.contains_key(&path) {
            self.map.insert(
                path.clone(),
                L1Entry {
                    body,
                    meta,
                    expires_at,
                    generation,
                },
            );
            self.touch(&path);
            return;
        }

        // Evict from front of queue until we have space
        while self.map.len() >= self.max_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            } else {
                break;
            }
        }

        self.order.push_back(path.clone());
        self.map.insert(
            path,
            L1Entry {
                body,
                meta,
                expires_at,
                generation,
            },
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

        let Some(l2_concurrent) = &self.l2 else { unreachable!() };

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

        let Some(l2_concurrent) = &self.l2 else { unreachable!() };

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
        self.generation.fetch_add(1, std::sync::atomic::Ordering::Release);
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
                let key = format!("/item/{}", i);
                let val = Bytes::from(format!("value-{}", i));
                c.insert(&key, val, default_meta(), 3600, 1000);
            }));
        }

        for _ in 0..10 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                for i in 0..10 {
                    let key = format!("/item/{}", i);
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
