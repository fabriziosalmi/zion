// SPDX-License-Identifier: Apache-2.0
//! Thread-local route LRU.
//!
//! O(1) get/insert/evict via an intrusive doubly-linked list backed by a Vec.
//! Same primitive as cache::L1Cache but stripped to what the route cache needs:
//! no TTL (routes are immutable for the lifetime of the daemon: they come
//! from the static config) and no generation counter. The slot is chosen by
//! the FNV hash of `(host, path)` (computed at the call site), but an entry
//! is identified by the `(host, path)` it was resolved for, which it keeps and
//! which a lookup compares in full. FNV is unseeded and public: two different
//! paths with one hash can be computed offline, and a hash-only hit served one
//! path under the other's route (its `internal_only`, auth and WAF policy).
//!
//! A file of its own so `benches/route_cache.rs` measures this code, not a copy.

/// Thread-local route-cache slot hash. Folds the normalized host in when a host
/// is present (host routing active), so two authorities that share a path land
/// in different slots; with `host = None` it is the bare path hash, so
/// hostless deployments are unchanged. `str`'s `Hash` writes a terminator, so
/// `(host, path)` can never alias a different host/path split.
///
/// The hash only picks the slot. It is unseeded 64-bit FNV, so a colliding pair
/// can be computed offline; what keeps one request from reusing another's cached
/// `ResolvedRoute` (its WAF/auth profile, its `internal_only` gate, the ADR-0010
/// cache invariant) is that a hit also compares the full `(host, path)`.
#[inline]
pub(crate) fn route_cache_key(host: Option<&str>, path: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = fnv::FnvHasher::default();
    if let Some(host) = host {
        host.hash(&mut h);
    }
    path.hash(&mut h);
    h.finish()
}

pub(super) const ROUTE_CACHE_CAP: usize = 256;
/// The longest `host` + `path`, in bytes, the cache keeps. Each entry holds its own key,
/// so this bounds what a flood of long distinct paths can make a worker thread hold
/// (about 256 x 512 bytes, against 256 x 8 KiB at the URI length cap). A longer request
/// is resolved by the radix tree every time, which is what a miss costs anyway.
pub(super) const ROUTE_CACHE_MAX_KEY_LEN: usize = 512;
const NIL: usize = usize::MAX;

struct Node {
    key: u64,
    prev: usize,
    next: usize,
}

/// `Slot::host_len` of a request without a host.
const NO_HOST: usize = usize::MAX;

/// What one hash slot holds: the request it was filled for and its route.
struct Slot<V> {
    /// The host (if any) then the path, in one allocation.
    key: Box<str>,
    /// Where the path starts in `key`, or [`NO_HOST`].
    host_len: usize,
    value: V,
    idx: usize,
}

impl<V> Slot<V> {
    fn new(host: Option<&str>, path: &str, value: V, idx: usize) -> Self {
        let (key, host_len) = Self::key_of(host, path);
        Self {
            key,
            host_len,
            value,
            idx,
        }
    }

    fn key_of(host: Option<&str>, path: &str) -> (Box<str>, usize) {
        match host {
            None => (Box::from(path), NO_HOST),
            Some(host) => {
                let mut key = String::with_capacity(host.len() + path.len());
                key.push_str(host);
                key.push_str(path);
                (key.into_boxed_str(), host.len())
            }
        }
    }

    /// Whether this slot was filled for exactly this `(host, path)`.
    #[inline]
    fn is_for(&self, host: Option<&str>, path: &str) -> bool {
        match host {
            None => self.host_len == NO_HOST && *self.key == *path,
            Some(host) => {
                let (key, split) = (self.key.as_bytes(), host.len());
                self.host_len == split
                    && key.len() == split + path.len()
                    && key[..split] == *host.as_bytes()
                    && key[split..] == *path.as_bytes()
            }
        }
    }
}

/// Generic on V so tests can drive the LRU with a trivial value type
/// (e.g. u32) without needing to construct a fully populated
/// ResolvedRoute. Monomorphises to the same code at the call site.
pub(super) struct RouteCache<V: Clone> {
    map: fnv::FnvHashMap<u64, Slot<V>>,
    nodes: Vec<Node>,
    free: Vec<usize>,
    head: usize, // LRU, evicted first
    tail: usize, // MRU
    cap: usize,
}

impl<V: Clone> RouteCache<V> {
    /// Drop every entry (the capacity and allocations are kept).
    pub(super) fn clear(&mut self) {
        self.map.clear();
        self.nodes.clear();
        self.free.clear();
        self.head = NIL;
        self.tail = NIL;
    }

    pub(super) fn new(cap: usize) -> Self {
        Self {
            map: fnv::FnvHashMap::with_capacity_and_hasher(cap, Default::default()),
            nodes: Vec::with_capacity(cap),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
            cap,
        }
    }

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

    #[inline]
    fn alloc_node(&mut self, key: u64) -> usize {
        if let Some(idx) = self.free.pop() {
            self.nodes[idx] = Node {
                key,
                prev: NIL,
                next: NIL,
            };
            idx
        } else {
            let idx = self.nodes.len();
            self.nodes.push(Node {
                key,
                prev: NIL,
                next: NIL,
            });
            idx
        }
    }

    /// Lookup with MRU promotion: the value cached for exactly `(host, path)`, whose
    /// hash is `key`. A slot filled for another `(host, path)` with the same hash is a
    /// miss. Returns a clone of the value (for `Arc<T>` this is just an atomic refcount
    /// bump).
    pub(super) fn get(&mut self, key: u64, host: Option<&str>, path: &str) -> Option<V> {
        let slot = self.map.get(&key)?;
        if !slot.is_for(host, path) {
            return None;
        }
        let value = slot.value.clone();
        let idx = slot.idx;
        self.unlink(idx);
        self.push_tail(idx);
        Some(value)
    }

    /// Insert or update the value for `(host, path)`, whose hash is `key`. On capacity
    /// full, evicts the LRU entry. Always places the inserted/updated key at MRU. A slot
    /// held by another `(host, path)` with the same hash now belongs to this one. A key
    /// longer than [`ROUTE_CACHE_MAX_KEY_LEN`] is not kept.
    pub(super) fn insert(&mut self, key: u64, host: Option<&str>, path: &str, value: V) {
        if host.map_or(0, str::len) + path.len() > ROUTE_CACHE_MAX_KEY_LEN {
            return;
        }
        if let Some(slot) = self.map.get_mut(&key) {
            if !slot.is_for(host, path) {
                (slot.key, slot.host_len) = Slot::<V>::key_of(host, path);
            }
            slot.value = value;
            let idx = slot.idx;
            self.unlink(idx);
            self.push_tail(idx);
            return;
        }
        // Evict LRU if at capacity (must run BEFORE allocating, otherwise
        // a single-shot of cap+1 distinct keys would never reclaim space).
        while self.map.len() >= self.cap && self.head != NIL {
            let lru_idx = self.head;
            let lru_key = self.nodes[lru_idx].key;
            self.unlink(lru_idx);
            self.free.push(lru_idx);
            self.map.remove(&lru_key);
        }
        let idx = self.alloc_node(key);
        self.push_tail(idx);
        self.map.insert(key, Slot::new(host, path, value, idx));
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns keys in LRU→MRU order. Test-only helper that walks the
    /// intrusive list, so it also implicitly verifies link integrity.
    #[cfg(test)]
    pub(super) fn order(&self) -> Vec<u64> {
        let mut out = Vec::with_capacity(self.map.len());
        let mut cur = self.head;
        while cur != NIL {
            out.push(self.nodes[cur].key);
            cur = self.nodes[cur].next;
        }
        out
    }
}
