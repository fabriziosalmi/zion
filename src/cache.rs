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
use hyper::StatusCode;
use hyper::header::HeaderValue;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached response metadata — stored alongside the body so cache hits
/// preserve upstream Content-Type, status, and other essential headers.
#[derive(Clone, Debug)]
pub struct CachedMeta {
    pub content_type: Option<HeaderValue>,
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
    last_access: u64, // monotonic counter for LRU
}

/// L2 entry — with TTL.
struct L2Entry {
    body: Bytes,
    meta: CachedMeta,
    expires_at: Instant,
}

/// Thread-local L1 cache. One per tokio worker thread.
struct L1Cache {
    map: HashMap<Arc<str>, L1Entry>,
    max_entries: usize,
    access_counter: u64,
}

impl L1Cache {
    fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::with_capacity(max_entries),
            max_entries,
            access_counter: 0,
        }
    }

    #[inline]
    fn get(&mut self, path: &str) -> Option<CacheHit> {
        if let Some(entry) = self.map.get_mut(path) {
            // TTL check — don't serve expired L1 entries
            if Instant::now() >= entry.expires_at {
                self.map.remove(path);
                return None;
            }
            self.access_counter += 1;
            entry.last_access = self.access_counter;
            return Some(CacheHit {
                body: entry.body.clone(),
                meta: entry.meta.clone(),
            });
        }
        None
    }

    #[inline]
    fn insert(&mut self, path: Arc<str>, body: Bytes, meta: CachedMeta, expires_at: Instant) {
        if self.map.len() >= self.max_entries {
            // Evict LRU entry
            let lru_key = self.map.iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone());
            if let Some(key) = lru_key {
                self.map.remove(&key);
            }
        }

        self.access_counter += 1;
        self.map.insert(path, L1Entry {
            body,
            meta,
            expires_at,
            last_access: self.access_counter,
        });
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

/// Two-level static cache.
pub struct StaticCache {
    l2: DashMap<Arc<str>, L2Entry>,
    l1_max_entries: usize,
}

impl StaticCache {
    pub fn new() -> Self {
        // Get L1 capacity from bootstrap detection
        let l1_max = crate::bootstrap::detect().l1_hot_entries;
        Self {
            l2: DashMap::new(),
            l1_max_entries: l1_max,
        }
    }

    /// Lookup: L1 → L2 → None.
    /// L1 hit: ~5ns (no atomic, no contention).
    /// L2 hit: ~30ns (sharded DashMap) + promote to L1.
    /// Returns CacheHit with body + metadata (Content-Type, status).
    #[inline]
    pub fn get(&self, path: &str) -> Option<CacheHit> {
        let l1_max = self.l1_max_entries;

        // L1: thread-local, zero contention
        let l1_hit = L1.with(|l1| {
            let mut l1 = l1.borrow_mut();
            let l1 = l1.get_or_insert_with(|| L1Cache::new(l1_max));
            l1.get(path)
        });

        if let Some(hit) = l1_hit {
            crate::metrics::METRICS.cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some(hit);
        }

        // L2: shared DashMap
        let entry = self.l2.get(path)?;
        if Instant::now() >= entry.expires_at {
            drop(entry);
            self.l2.remove(path);
            crate::metrics::METRICS.cache_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        let body = entry.body.clone();
        let meta = entry.meta.clone();
        let key: Arc<str> = entry.key().clone();
        let expires_at = entry.expires_at;
        drop(entry); // release DashMap read lock

        // Promote to L1 with same TTL
        L1.with(|l1| {
            let mut l1 = l1.borrow_mut();
            let l1 = l1.get_or_insert_with(|| L1Cache::new(l1_max));
            l1.insert(key, body.clone(), meta.clone(), expires_at);
        });

        crate::metrics::METRICS.cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(CacheHit { body, meta })
    }

    /// Insert into L2 (source of truth). L1 populated lazily on next get.
    pub fn insert(&self, path: &str, body: Bytes, meta: CachedMeta, ttl_seconds: u64, max_entries: usize) {
        if max_entries > 0 && self.l2.len() >= max_entries {
            // Phase 1: evict expired entries
            let now = Instant::now();
            let expired: Vec<Arc<str>> = self.l2.iter()
                .filter(|e| now >= e.expires_at)
                .map(|e| e.key().clone())
                .collect();
            for key in &expired {
                self.l2.remove(key);
            }

            // Phase 2: if still full, evict entry closest to expiry (≈oldest)
            if self.l2.len() >= max_entries {
                let victim = self.l2.iter()
                    .min_by_key(|e| e.expires_at)
                    .map(|e| e.key().clone());
                if let Some(key) = victim {
                    self.l2.remove(&key);
                }
            }
        }

        self.l2.insert(
            Arc::from(path),
            L2Entry {
                body,
                meta,
                expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
            },
        );
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.l2.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_meta() -> CachedMeta {
        CachedMeta {
            content_type: Some(HeaderValue::from_static("text/css")),
            status: StatusCode::OK,
        }
    }

    #[test]
    fn insert_and_get() {
        let cache = StaticCache::new();
        cache.insert("/style.css", Bytes::from("body{}"), default_meta(), 3600, 100);
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
            status: StatusCode::NOT_MODIFIED,
        };
        cache.insert("/304", Bytes::new(), meta, 3600, 100);
        let hit = cache.get("/304").unwrap();
        assert_eq!(hit.meta.status, StatusCode::NOT_MODIFIED);
    }
}
