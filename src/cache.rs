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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Cached response metadata — stored alongside the body so cache hits
/// preserve upstream Content-Type, Content-Encoding, status, and other
/// essential headers.
#[derive(Clone, Debug)]
pub struct CachedMeta {
    pub content_type: Option<HeaderValue>,
    pub content_encoding: Option<HeaderValue>,
    pub status: StatusCode,
    /// Validators preserved for conditional requests (RFC 9110 §8.8). `etag`
    /// answers a client `If-None-Match` (→ 304) and seeds origin revalidation;
    /// `last_modified` backs `If-Modified-Since`.
    pub etag: Option<HeaderValue>,
    pub last_modified: Option<HeaderValue>,
    /// `stale-while-revalidate=N` from the origin (RFC 5861), in seconds; `0` =
    /// not offered. While an entry is at most this far past its freshness
    /// lifetime it may be served stale while a background refresh runs.
    pub stale_while_revalidate_secs: u64,
    /// The origin forbade serving this response once stale without validating it
    /// (`must-revalidate`, `proxy-revalidate`, or `s-maxage`, which carries the
    /// proxy-revalidate semantics for a shared cache: RFC 9111 §4.2.4, §5.2.2). It
    /// must then neither be served stale-while-revalidate nor on an origin error.
    pub must_revalidate: bool,
}

impl CachedMeta {
    /// The same metadata, with header values that own their bytes.
    ///
    /// hyper parses response headers without copying: each `HeaderValue` is a slice of the
    /// connection's read buffer. Storing one keeps that whole buffer alive (8 KiB or more,
    /// the body's bytes included) for as long as the entry is cached, on top of the body the
    /// cache copies itself. A copy of a few dozen bytes lets the buffer go.
    fn detached(mut self) -> Self {
        for value in [
            &mut self.content_type,
            &mut self.content_encoding,
            &mut self.etag,
            &mut self.last_modified,
        ]
        .into_iter()
        .flatten()
        {
            // `from_bytes` accepts every value hyper's parser does; if it ever refused one,
            // the original (shared) value is kept rather than lost.
            if let Ok(mut owned) = HeaderValue::from_bytes(value.as_bytes()) {
                owned.set_sensitive(value.is_sensitive());
                *value = owned;
            }
        }
        self
    }
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

/// Outcome of a cache lookup (RFC 9111 §4.3). `Stale` returns the stored entry
/// **without evicting it**, so the caller can revalidate with the origin and, on
/// a `304 Not Modified`, revive it via [`StaticCache::refresh`] instead of
/// re-downloading the body.
pub enum CacheLookup {
    /// Within its freshness lifetime — serve directly.
    Fresh(CacheHit),
    /// Past its freshness lifetime but still stored — revalidate before serving.
    Stale(CacheHit),
    /// Not stored.
    Miss,
}

impl CacheLookup {
    /// The fresh hit, if this lookup was `Fresh`. Ergonomic accessor for the
    /// common "serve-now-or-nothing" callers (and tests); `Stale`/`Miss` → `None`.
    #[inline]
    pub fn fresh(self) -> Option<CacheHit> {
        match self {
            CacheLookup::Fresh(hit) => Some(hit),
            _ => None,
        }
    }
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

/// Most `Surrogate-Key` tags one response may carry and still be cached.
pub const MAX_TAGS_PER_ENTRY: usize = 32;
/// Longest accepted tag, in bytes.
pub const MAX_TAG_LEN: usize = 128;
/// Distinct tags the index tracks.
const MAX_TAGS: usize = 10_000;
/// (tag, key) pairs the index holds, live or dangling.
const MAX_TAGGED_KEYS: usize = 200_000;

/// The tags of a response (`Surrogate-Key`, space- or comma-separated, repeatable), or `Err`
/// when they cannot be honoured: too many, too long, or not plain visible ASCII. A response
/// whose tags cannot be tracked is **not cached**: the origin asked to be able to purge it by
/// tag, and an entry no purge can reach is worse than a miss.
pub fn surrogate_keys(headers: &hyper::HeaderMap) -> Result<Vec<String>, ()> {
    let mut out: Vec<String> = Vec::new();
    for v in headers.get_all("surrogate-key") {
        let Ok(text) = v.to_str() else { return Err(()) };
        for t in text.split(|c: char| c.is_ascii_whitespace() || c == ',') {
            if t.is_empty() {
                continue;
            }
            if t.len() > MAX_TAG_LEN || !t.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(());
            }
            if !out.iter().any(|x| x == t) {
                out.push(t.to_string());
                if out.len() > MAX_TAGS_PER_ENTRY {
                    return Err(());
                }
            }
        }
    }
    Ok(out)
}

/// What [`StaticCache::insert_tagged`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagStore {
    Stored,
    /// A tag purge ran after the response's fetch began: it may predate the purge.
    PurgedMeanwhile,
    /// The tag index is full; the previous entry under the key (if any) was dropped too, so
    /// nothing is left that a purge could not reach.
    IndexFull,
}

/// tag ↔ cache key, both directions, so replacing a key's tags can drop the old ones.
#[derive(Default)]
struct TagIndex {
    by_tag: HashMap<Arc<str>, HashSet<Arc<str>>>,
    by_key: HashMap<Arc<str>, Vec<Arc<str>>>,
    /// (tag, key) pairs held.
    pairs: usize,
}

impl TagIndex {
    /// Forget everything recorded for `key`.
    fn detach(&mut self, key: &str) {
        let Some(tags) = self.by_key.remove(key) else {
            return;
        };
        for t in tags {
            if let Some(set) = self.by_tag.get_mut(&t) {
                if set.remove(key) {
                    self.pairs = self.pairs.saturating_sub(1);
                }
                if set.is_empty() {
                    self.by_tag.remove(&t);
                }
            }
        }
    }
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
    /// Which request headers each primary key's responses vary on (RFC 9111 §4.1).
    pub vary: crate::vary::VaryRules,
    /// Surrogate-Key tag index. Its lock also orders tagged inserts against tag purges.
    tags: Mutex<TagIndex>,
    /// `by_key.len()`, readable without the lock: untagged inserts skip it while nothing is tagged.
    tagged_keys: std::sync::atomic::AtomicUsize,
    /// Bumped by every tag purge (and `purge_all`): a response fetched before a purge must not
    /// be stored after it (see [`StaticCache::insert_tagged`]).
    tag_epoch: std::sync::atomic::AtomicU64,
    /// What the stored entries cost in memory ([`entry_cost`] of each), plus the room
    /// reserved by inserts in progress. Every change to the store goes through
    /// `map_insert` / `map_remove` / `map_retain`, which keep it exact.
    bytes: std::sync::atomic::AtomicU64,
    /// A budget for this cache alone, in place of the process-wide one (tests).
    own_budget: Option<std::sync::atomic::AtomicU64>,
}

/// The memory budget of the response cache, in bytes: `[server] cache_max_memory_mb`,
/// applied at boot and when a reload is published. `0` = no budget.
static BYTE_BUDGET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Set the process-wide byte budget of the response cache (`0` = none). A lower budget
/// takes effect as entries are stored: each insert evicts until the cache is under it.
pub fn configure(budget_bytes: u64) {
    BYTE_BUDGET.store(budget_bytes, std::sync::atomic::Ordering::Relaxed);
}

/// The budget when `cache_max_memory_mb` is not set: an eighth of the memory the process
/// may use (the cgroup limit when there is one), and never less than 32 MiB.
pub fn default_budget_mb(usable_memory_mb: u64) -> u64 {
    (usable_memory_mb / 8).max(32)
}

/// What one entry is counted as, on top of its key and body: the entry itself, its
/// metadata (a few short header values) and its slot in the map. An estimate, there so
/// that a cache of empty bodies is not counted as free.
const ENTRY_OVERHEAD_BYTES: u64 = 256;

/// The memory one stored entry is counted as.
fn entry_cost(key: &str, entry: &L2Entry) -> u64 {
    (key.len() + entry.body.len()) as u64 + ENTRY_OVERHEAD_BYTES
}

/// The largest body a worker thread keeps in its own L1 cache. L1 entries are not in the
/// byte budget (they are clones the shared store may have evicted since), and each thread
/// holds up to `l1_hot_entries` of them: without a cap, a few hundred large objects per
/// thread could stay alive long after the store dropped them. Larger bodies are served
/// from the shared store on every hit.
const L1_MAX_BODY_BYTES: usize = 64 * 1024;

/// Entries one eviction round looks at: a bounded sample, never the whole map.
const EVICT_SAMPLE: usize = 64;
/// Most eviction rounds one insert runs before it stores its entry regardless. A round that
/// removes nothing means another thread took the victim, so the map shrank anyway; the limit
/// only bounds the work of a single insert.
const EVICT_ROUNDS: usize = 8;

impl StaticCache {
    /// One eviction round over a sample of the store: drop what has expired, or else the
    /// entries closest to expiring, one of them and then as many more as it takes to free
    /// `need_bytes`. Returns nothing: what was freed shows in `self.bytes`, and a round that
    /// frees nothing means another thread took the same victims.
    ///
    /// `keep` is never a victim: the key an insert is about to replace. Its bytes are already
    /// counted against the room that insert reserved, so evicting it frees nothing the insert
    /// can use, and the count would end over the budget by exactly its size.
    fn evict_round(&self, need_bytes: u64, keep: Option<&str>) {
        let now = Instant::now();
        // First pass, which is all an insert at the entry cap needs and costs what it did
        // before there was a budget: what has expired, and the one entry closest to it.
        let mut expired: Vec<Arc<str>> = Vec::new();
        let mut oldest: Option<(Arc<str>, Instant)> = None;
        self.sample(|key, expires_at| {
            if keep == Some(key.as_ref()) {
                return;
            }
            if now >= expires_at {
                expired.push(key.clone());
            } else if oldest.as_ref().is_none_or(|(_, at)| expires_at < *at) {
                oldest = Some((key.clone(), expires_at));
            }
        });
        let mut freed = 0u64;
        for key in &expired {
            freed += self.map_remove(key).map_or(0, |e| entry_cost(key, &e));
        }
        if expired.is_empty() {
            if let Some((key, _)) = &oldest {
                freed += self.map_remove(key).map_or(0, |e| entry_cost(key, &e));
            }
        }
        if freed >= need_bytes {
            return;
        }
        // The bytes ask for more than that: the rest of the sample, soonest to expire first.
        let mut rest: Vec<(Arc<str>, Instant)> = Vec::new();
        self.sample(|key, expires_at| {
            if keep != Some(key.as_ref()) {
                rest.push((key.clone(), expires_at));
            }
        });
        rest.sort_by_key(|(_, expires_at)| *expires_at);
        for (key, _) in &rest {
            if freed >= need_bytes {
                break;
            }
            freed += self.map_remove(key).map_or(0, |e| entry_cost(key, &e));
        }
    }

    /// Visit the entries one eviction round looks at: (key, when it expires).
    fn sample(&self, mut visit: impl FnMut(&Arc<str>, Instant)) {
        match &self.l2 {
            Some(l2) => {
                for e in l2.iter().take(EVICT_SAMPLE) {
                    visit(e.key(), e.expires_at);
                }
            }
            None => LOCAL_L2.with(|m| {
                for (k, v) in m.borrow().iter().take(EVICT_SAMPLE) {
                    visit(k, v.expires_at);
                }
            }),
        }
    }

    /// The byte budget in force for this cache (`0` = none).
    fn budget(&self) -> u64 {
        self.own_budget
            .as_ref()
            .unwrap_or(&BYTE_BUDGET)
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// What the cache holds, in bytes as [`entry_cost`] counts them.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn sub_bytes(&self, n: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        // Never below zero: a counter that wrapped would look like a cache over any budget.
        let mut seen = self.bytes.load(Relaxed);
        while let Err(now) =
            self.bytes
                .compare_exchange_weak(seen, seen.saturating_sub(n), Relaxed, Relaxed)
        {
            seen = now;
        }
    }

    /// Store an entry in whichever backend is in use, without touching the byte count
    /// (the caller reserved the room): the entry it replaced, if any.
    fn map_insert_raw(&self, key: Arc<str>, entry: L2Entry) -> Option<L2Entry> {
        match &self.l2 {
            Some(l2) => l2.insert(key, entry),
            None => LOCAL_L2.with(|m| m.borrow_mut().insert(key, entry)),
        }
    }

    /// Remove one entry, and its cost from the byte count.
    fn map_remove(&self, key: &str) -> Option<L2Entry> {
        let removed = match &self.l2 {
            Some(l2) => l2.remove(key).map(|(_, e)| e),
            None => LOCAL_L2.with(|m| m.borrow_mut().remove(key)),
        };
        if let Some(e) = &removed {
            self.sub_bytes(entry_cost(key, e));
        }
        removed
    }

    /// Keep the entries `keep` says to, drop the others and their cost: how many went.
    fn map_retain(&self, mut keep: impl FnMut(&str) -> bool) -> usize {
        let (mut removed, mut freed) = (0usize, 0u64);
        let mut visit = |k: &Arc<str>, e: &mut L2Entry| {
            let stay = keep(k);
            if !stay {
                removed += 1;
                freed += entry_cost(k, e);
            }
            stay
        };
        match &self.l2 {
            Some(l2) => l2.retain(&mut visit),
            None => LOCAL_L2.with(|m| m.borrow_mut().retain(&mut visit)),
        }
        self.sub_bytes(freed);
        removed
    }

    /// The cost of the entry stored under `key`, `0` when there is none.
    fn cost_of(&self, key: &str) -> u64 {
        match &self.l2 {
            Some(l2) => l2.get(key).map_or(0, |e| entry_cost(key, &e)),
            None => LOCAL_L2.with(|m| m.borrow().get(key).map_or(0, |e| entry_cost(key, e))),
        }
    }

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
            vary: crate::vary::VaryRules::default(),
            tags: Mutex::new(TagIndex::default()),
            tagged_keys: std::sync::atomic::AtomicUsize::new(0),
            tag_epoch: std::sync::atomic::AtomicU64::new(0),
            bytes: std::sync::atomic::AtomicU64::new(0),
            own_budget: None,
        }
    }

    /// A cache with a byte budget of its own, whatever the process-wide one is.
    #[cfg(test)]
    fn with_byte_budget(budget_bytes: u64) -> Self {
        Self {
            own_budget: Some(std::sync::atomic::AtomicU64::new(budget_bytes)),
            ..Self::new()
        }
    }

    /// The same on the single-worker backend (a map local to the calling thread), which a
    /// machine with one core selects and a test machine never does.
    #[cfg(test)]
    fn single_worker_with_byte_budget(budget_bytes: u64) -> Self {
        // The map belongs to the thread, not to the cache: start from an empty one.
        LOCAL_L2.with(|m| m.borrow_mut().clear());
        Self {
            l2: None,
            ..Self::with_byte_budget(budget_bytes)
        }
    }

    /// The bytes the store holds, counted entry by entry: what `bytes` must equal when
    /// no insert is in progress.
    #[cfg(test)]
    fn recount(&self) -> u64 {
        match &self.l2 {
            Some(l2) => l2.iter().map(|e| entry_cost(e.key(), &e)).sum(),
            None => LOCAL_L2.with(|m| m.borrow().iter().map(|(k, e)| entry_cost(k, e)).sum()),
        }
    }

    /// Read before fetching a response you may store with [`Self::insert_tagged`].
    pub fn tag_epoch(&self) -> u64 {
        self.tag_epoch.load(std::sync::atomic::Ordering::Acquire)
    }

    fn lock_tags(&self) -> std::sync::MutexGuard<'_, TagIndex> {
        self.tags.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn holds(&self, key: &str) -> bool {
        match &self.l2 {
            Some(l2) => l2.contains_key(key),
            None => LOCAL_L2.with(|m| m.borrow().contains_key(key)),
        }
    }

    fn remove_key(&self, key: &str) -> bool {
        self.map_remove(key).is_some()
    }

    fn sync_tagged_keys(&self, idx: &TagIndex) {
        self.tagged_keys
            .store(idx.by_key.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Store `body` under `path`, indexed under exactly `tags` (`Surrogate-Key`): whatever tags
    /// the key had before are replaced, and none at all means it is no longer reachable by tag.
    /// A response with tags is refused ([`TagStore::PurgedMeanwhile`]) when a tag purge happened
    /// since `epoch` was read, and ([`TagStore::IndexFull`]) when the index has no room.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_tagged(
        &self,
        path: &str,
        body: Bytes,
        meta: CachedMeta,
        freshness_secs: u64,
        initial_age_secs: u64,
        max_entries: usize,
        tags: &[String],
        epoch: u64,
    ) -> TagStore {
        if tags.is_empty() {
            if self.tagged_keys.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                let mut idx = self.lock_tags();
                idx.detach(path);
                self.sync_tagged_keys(&idx);
            }
            self.insert(
                path,
                body,
                meta,
                freshness_secs,
                initial_age_secs,
                max_entries,
            );
            return TagStore::Stored;
        }
        let mut idx = self.lock_tags();
        if self.tag_epoch() != epoch {
            return TagStore::PurgedMeanwhile;
        }
        idx.detach(path); // the new response's tags replace the old ones
        let admit = |idx: &TagIndex| {
            let new_tags = tags
                .iter()
                .filter(|t| !idx.by_tag.contains_key(t.as_str()))
                .count();
            idx.by_tag.len() + new_tags <= MAX_TAGS && idx.pairs + tags.len() <= MAX_TAGGED_KEYS
        };
        if !admit(&idx) {
            // Make room: forget keys that are no longer cached.
            let dead: Vec<Arc<str>> = idx
                .by_key
                .keys()
                .filter(|k| !self.holds(k))
                .cloned()
                .collect();
            for k in dead {
                idx.detach(&k);
            }
        }
        if !admit(&idx) {
            self.remove_key(path);
            self.sync_tagged_keys(&idx);
            return TagStore::IndexFull;
        }
        let key: Arc<str> = Arc::from(path);
        let mut mine = Vec::with_capacity(tags.len());
        for t in tags {
            let t: Arc<str> = Arc::from(t.as_str());
            if idx.by_tag.entry(t.clone()).or_default().insert(key.clone()) {
                idx.pairs += 1;
            }
            mine.push(t);
        }
        idx.by_key.insert(key, mine);
        self.sync_tagged_keys(&idx);
        // stored while the index lock is held: a purge that takes the lock afterwards sees it
        self.insert(
            path,
            body,
            meta,
            freshness_secs,
            initial_age_secs,
            max_entries,
        );
        TagStore::Stored
    }

    /// Revive an entry after a `304` (its tags are unchanged). Refused, storing nothing, when a
    /// tag purge ran since `epoch` was read: the purge may have removed this very entry, and the
    /// revalidation must not bring it back.
    #[allow(clippy::too_many_arguments)]
    pub fn refresh_checked(
        &self,
        path: &str,
        body: Bytes,
        meta: CachedMeta,
        freshness_secs: u64,
        initial_age_secs: u64,
        max_entries: usize,
        epoch: u64,
    ) -> bool {
        let _idx = self.lock_tags();
        if self.tag_epoch() != epoch {
            return false;
        }
        self.refresh(
            path,
            body,
            meta,
            freshness_secs,
            initial_age_secs,
            max_entries,
        );
        true
    }

    /// Drop every entry stored under any of `tags`. One generation bump however many go;
    /// returns the entries removed.
    pub fn purge_tags(&self, tags: &[&str]) -> usize {
        let keys: HashSet<Arc<str>> = {
            let mut idx = self.lock_tags();
            self.tag_epoch
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            let mut keys = HashSet::new();
            for t in tags {
                if let Some(set) = idx.by_tag.get(*t) {
                    keys.extend(set.iter().cloned());
                }
            }
            // each removed key leaves all of its tags, not only the purged ones
            for k in &keys {
                idx.detach(k);
            }
            self.sync_tagged_keys(&idx);
            keys
        };
        let removed = keys.iter().filter(|k| self.remove_key(k)).count();
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        removed
    }

    #[inline]
    pub fn get(&self, path: &str) -> CacheLookup {
        use std::sync::atomic::Ordering::Relaxed;
        let l1_max = self.l1_max_entries;

        // Single-core fallback: LOCAL_L2 only. A stored-but-expired entry is
        // returned as `Stale` (kept in place) so the caller can revalidate —
        // RFC 9111 §4.3 — instead of the old evict-and-refetch.
        let Some(l2_concurrent) = &self.l2 else {
            return LOCAL_L2.with(|map| {
                let m = map.borrow();
                match m.get(path) {
                    Some(entry) => {
                        let hit = CacheHit {
                            body: entry.body.clone(),
                            meta: entry.meta.clone(),
                            age_secs: entry.initial_age_secs
                                + entry.inserted_at.elapsed().as_secs(),
                            max_age_secs: entry.freshness_secs,
                        };
                        if Instant::now() >= entry.expires_at {
                            CacheLookup::Stale(hit)
                        } else {
                            crate::metrics::METRICS.cache_hits.fetch_add(1, Relaxed);
                            CacheLookup::Fresh(hit)
                        }
                    }
                    None => {
                        crate::metrics::METRICS.cache_misses.fetch_add(1, Relaxed);
                        CacheLookup::Miss
                    }
                }
            });
        };

        let current_gen = self.generation.load(std::sync::atomic::Ordering::Acquire);

        // L1: thread-local, zero contention. `L1Cache::get` returns a fresh hit
        // only (it evicts its own expired / stale-generation entries), so a miss
        // here falls through to L2 — the source of truth for freshness.
        let l1_hit = L1.with(|l1| {
            let mut l1 = l1.borrow_mut();
            let l1 = l1.get_or_insert_with(|| L1Cache::new(l1_max));
            l1.get(path, current_gen)
        });

        if let Some(hit) = l1_hit {
            crate::metrics::METRICS.cache_hits.fetch_add(1, Relaxed);
            return CacheLookup::Fresh(hit);
        }

        // L2: shared DashMap. Absent = Miss (counted — a bare `?` here once
        // undercounted misses and inflated the hit-rate). Expired = Stale, kept
        // in place for origin revalidation (§4.3), NOT evicted. Fresh = promote
        // to L1 and serve.
        let Some(entry) = l2_concurrent.get(path) else {
            crate::metrics::METRICS.cache_misses.fetch_add(1, Relaxed);
            return CacheLookup::Miss;
        };
        let body = entry.body.clone();
        let meta = entry.meta.clone();
        let age_secs = entry.initial_age_secs + entry.inserted_at.elapsed().as_secs();
        let freshness_secs = entry.freshness_secs;
        if Instant::now() >= entry.expires_at {
            drop(entry); // release the DashMap read lock; leave the entry stored
            return CacheLookup::Stale(CacheHit {
                body,
                meta,
                age_secs,
                max_age_secs: freshness_secs,
            });
        }
        let key: Arc<str> = entry.key().clone();
        let inserted_at = entry.inserted_at;
        let expires_at = entry.expires_at;
        let initial_age_secs = entry.initial_age_secs;
        drop(entry); // release DashMap read lock

        // Promote to L1 preserving the original birth time, TTL and generation. Small
        // bodies only: see L1_MAX_BODY_BYTES.
        if body.len() <= L1_MAX_BODY_BYTES {
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
        }

        crate::metrics::METRICS.cache_hits.fetch_add(1, Relaxed);
        CacheLookup::Fresh(CacheHit {
            body,
            meta,
            age_secs,
            max_age_secs: freshness_secs,
        })
    }

    /// Revalidation refresh (RFC 9111 §4.3): after the origin answers a
    /// conditional request with `304 Not Modified`, re-stamp the stored entry
    /// with a fresh freshness lifetime, reusing the body the caller already
    /// holds (from a [`CacheLookup::Stale`]). A 304 keeps the same body, so this
    /// is an `insert` of the stored bytes with a new lifetime — reviving the
    /// entry across all tiers (L2 write + generation bump ⇒ L1 re-promotes).
    pub fn refresh(
        &self,
        path: &str,
        body: Bytes,
        meta: CachedMeta,
        freshness_secs: u64,
        initial_age_secs: u64,
        max_entries: usize,
    ) {
        self.insert(
            path,
            body,
            meta,
            freshness_secs,
            initial_age_secs,
            max_entries,
        );
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
        // Every store goes through here: nothing kept may reference the upstream's buffer.
        let meta = meta.detached();
        let key: Arc<str> = Arc::from(path);
        let now = Instant::now();
        let entry = L2Entry {
            body,
            meta,
            inserted_at: now,
            expires_at: expiry_from(now, freshness_secs, initial_age_secs),
            initial_age_secs,
            freshness_secs,
        };
        let cost = entry_cost(&key, &entry);
        let budget = self.budget();
        let Some(reserved) = self.make_room(&key, cost, max_entries, budget) else {
            return; // no room for it: served, not stored
        };
        self.store_reserved(key, entry, cost, reserved, budget);
    }

    /// Make room for an entry of `cost` under `key`, by count and by bytes, and reserve the
    /// bytes it adds. `None` when room cannot be made: nothing is reserved, and whatever is
    /// stored under the key stays. The first half of [`Self::insert`]; the second is
    /// [`Self::store_reserved`].
    fn make_room(&self, key: &str, cost: u64, max_entries: usize, budget: u64) -> Option<u64> {
        use std::sync::atomic::Ordering::Relaxed;
        if budget > 0 && cost > budget {
            // It would not fit in an empty cache.
            crate::metrics::METRICS
                .cache_budget_skipped
                .fetch_add(1, Relaxed);
            return None;
        }

        // By count. One round is not enough under concurrency: every thread that evicts at
        // the same moment samples the same entries and picks the same victims, and all but
        // one of those removals find them gone. Inserting anyway grew the map by one entry
        // per collision, for good: it was never brought back under the cap (#481). So evict
        // until there is room; the same loop shrinks a map that is over its cap because a
        // reload lowered it.
        if max_entries > 0 {
            let mut rounds = 0;
            while self.len() >= max_entries && rounds < EVICT_ROUNDS {
                self.evict_round(0, None);
                rounds += 1;
            }
        }

        // By bytes (#524). The room is reserved first, so that threads storing at the same
        // moment see each other's entries: what is stored never exceeds the budget. An entry
        // that replaces one under the same key (a revalidation re-stores the same body)
        // reserves only the difference, or it would evict others to make room for bytes that
        // are already counted.
        let reserved = cost.saturating_sub(self.cost_of(key));
        let mut total = self.bytes.fetch_add(reserved, Relaxed) + reserved;
        if budget > 0 {
            let mut rounds = 0;
            while total > budget && rounds < EVICT_ROUNDS {
                self.evict_round(total - budget, Some(key));
                rounds += 1;
                total = self.bytes.load(Relaxed);
            }
            if total > budget {
                // No room could be made within the work one insert may do.
                self.sub_bytes(reserved);
                crate::metrics::METRICS
                    .cache_budget_skipped
                    .fetch_add(1, Relaxed);
                return None;
            }
        }
        Some(reserved)
    }

    /// Store `entry`, for which [`Self::make_room`] reserved `reserved` bytes, and settle
    /// the count with what was really replaced.
    fn store_reserved(&self, key: Arc<str>, entry: L2Entry, cost: u64, reserved: u64, budget: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        // The count holds `reserved`; what really changed is `cost` less the entry replaced.
        let replaced = self
            .map_insert_raw(key.clone(), entry)
            .map_or(0, |old| entry_cost(&key, &old));
        let settled = cost.saturating_sub(replaced);
        if settled >= reserved {
            self.bytes.fetch_add(settled - reserved, Relaxed);
        } else {
            self.sub_bytes(reserved - settled);
        }
        if cost < replaced {
            self.sub_bytes(replaced - cost);
        }
        // The entry measured when the room was reserved is not the one replaced when another
        // thread removed or shrank it in between: then this insert took more room than it
        // reserved. Make that room now, and give the entry up if it cannot be made, so the
        // budget still holds.
        if budget > 0 && settled > reserved {
            let mut rounds = 0;
            while self.bytes.load(Relaxed) > budget && rounds < EVICT_ROUNDS {
                self.evict_round(self.bytes.load(Relaxed) - budget, Some(&key));
                rounds += 1;
            }
            if self.bytes.load(Relaxed) > budget {
                self.map_remove(&key);
                crate::metrics::METRICS
                    .cache_budget_skipped
                    .fetch_add(1, Relaxed);
            }
        }
        // Bump generation so L1 caches on other threads see the update
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

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
        self.vary.clear();
        {
            let mut idx = self.lock_tags();
            self.tag_epoch
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            *idx = TagIndex::default();
            self.sync_tagged_keys(&idx);
        }
        // (entry by entry, not `clear`: an insert racing with it keeps its bytes counted)
        let n = self.map_retain(|_| false);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        n
    }

    /// Purge L2 entries whose key (path+query) starts with `prefix`. Returns
    /// the count removed. Bumps the generation, which lazily invalidates ALL
    /// L1 entries (not just the prefix) — over-broad but safe: unaffected keys
    /// simply re-promote from L2 on next get. The common deploy case
    /// (invalidate `/assets/...`) is well served.
    /// Drop every entry for `path` (RFC 9111 §4.4): the URI itself, every query
    /// variant of it, and each `Accept-Encoding` / `Vary` variant — but not a longer
    /// path that merely starts the same (`/a` does not touch `/ab` or `/a/b`). One scan
    /// and one generation bump, however many keys go. Returns the entries removed.
    pub fn invalidate_path(&self, path: &str) -> usize {
        let exact = format!("{path}\u{1f}");
        let with_query = format!("{path}?");
        let hit = |k: &str| k.starts_with(&exact) || k.starts_with(&with_query);
        self.vary.remove_prefix(&exact);
        self.vary.remove_prefix(&with_query);
        let removed = self.map_retain(|k| !hit(k));
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        removed
    }

    pub fn purge_prefix(&self, prefix: &str) -> usize {
        self.vary.remove_prefix(prefix);
        let removed = self.map_retain(|k| !k.starts_with(prefix));
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        removed
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn invalidate_path_removes_the_path_its_queries_and_variants_only() {
        let cache = StaticCache::new();
        let put = |k: &str| {
            cache.insert(
                k,
                Bytes::from_static(b"x"),
                default_meta(),
                3600,
                0,
                100_000,
            )
        };
        for k in [
            "/a\u{1f}",
            "/a\u{1f}gzip",
            "/a?x=1\u{1f}",
            "/a?x=2\u{1f}gzip",
            "/a\u{1f}\u{1e}accept=de\u{1f}",
            "/ab\u{1f}",
            "/a/b\u{1f}",
            "/b\u{1f}",
        ] {
            put(k);
        }
        assert_eq!(cache.invalidate_path("/a"), 5);
        for gone in [
            "/a\u{1f}",
            "/a\u{1f}gzip",
            "/a?x=1\u{1f}",
            "/a?x=2\u{1f}gzip",
        ] {
            assert!(matches!(cache.get(gone), CacheLookup::Miss), "{gone}");
        }
        for kept in ["/ab\u{1f}", "/a/b\u{1f}", "/b\u{1f}"] {
            assert!(cache.get(kept).fresh().is_some(), "{kept} must survive");
        }
    }

    /// One invalidation over a full default-sized cache stays cheap.
    #[test]
    fn invalidate_path_cost_with_a_full_cache() {
        let cache = StaticCache::new();
        for i in 0..10_000 {
            cache.insert(
                &format!("/p/{i}\u{1f}"),
                Bytes::from_static(b"x"),
                default_meta(),
                3600,
                0,
                100_000,
            );
        }
        let t = std::time::Instant::now();
        for _ in 0..100 {
            cache.invalidate_path("/nothing-here");
        }
        let per_call = t.elapsed() / 100;
        // ~10 µs measured; the bound only guards against an accidental O(n²)
        assert!(
            per_call < std::time::Duration::from_millis(50),
            "{per_call:?} per call"
        );
        assert_eq!(cache.len(), 10_000);
    }

    use super::*;

    fn default_meta() -> CachedMeta {
        CachedMeta {
            content_type: Some(HeaderValue::from_static("text/css")),
            content_encoding: None,
            status: StatusCode::OK,
            etag: None,
            last_modified: None,
            stale_while_revalidate_secs: 0,
            must_revalidate: false,
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
        let hit = cache.get("/style.css").fresh().unwrap();
        assert_eq!(hit.body, Bytes::from("body{}"));
        assert_eq!(hit.meta.content_type.unwrap(), "text/css");
        assert_eq!(hit.meta.status, StatusCode::OK);
    }

    #[test]
    fn get_miss_returns_none() {
        let cache = StaticCache::new();
        assert!(cache.get("/nonexistent").fresh().is_none());
    }

    #[test]
    fn insert_overwrites_existing() {
        let cache = StaticCache::new();
        cache.insert("/a.js", Bytes::from("v1"), default_meta(), 3600, 0, 100);
        let meta2 = CachedMeta {
            content_type: Some(HeaderValue::from_static("application/javascript")),
            content_encoding: None,
            status: StatusCode::OK,
            etag: None,
            last_modified: None,
            stale_while_revalidate_secs: 0,
            must_revalidate: false,
        };
        cache.insert("/a.js", Bytes::from("v2"), meta2, 3600, 0, 100);
        let hit = cache.get("/a.js").fresh().unwrap();
        assert_eq!(hit.body, Bytes::from("v2"));
        assert_eq!(hit.meta.content_type.unwrap(), "application/javascript");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn ttl_expiration_returns_stale_kept_in_place() {
        let cache = StaticCache::new();
        cache.insert("/expired.js", Bytes::from("old"), default_meta(), 0, 0, 100);
        std::thread::sleep(std::time::Duration::from_millis(10));
        // #266: an expired entry is not served fresh …
        assert!(cache.get("/expired.js").fresh().is_none());
        // … but it is kept for revalidation (Stale), not evicted.
        assert!(matches!(
            cache.get("/expired.js"),
            CacheLookup::Stale(hit) if hit.body.as_ref() == b"old"
        ));
        assert_eq!(
            cache.len(),
            1,
            "stale entries stay stored until refreshed/evicted"
        );
    }

    #[test]
    fn refresh_revives_a_stale_entry_to_fresh_reusing_the_body() {
        let cache = StaticCache::new();
        // freshness 0 ⇒ immediately stale.
        cache.insert("/r.js", Bytes::from("v1"), default_meta(), 0, 0, 100);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let stale = match cache.get("/r.js") {
            CacheLookup::Stale(hit) => hit,
            other => panic!("expected Stale, got {}", disp(&other)),
        };
        // #266: a 304 revives it with a fresh lifetime, reusing the stored body.
        cache.refresh(
            "/r.js",
            stale.body.clone(),
            stale.meta.clone(),
            3600,
            0,
            100,
        );
        let hit = cache
            .get("/r.js")
            .fresh()
            .expect("entry must be fresh after refresh");
        assert_eq!(
            hit.body,
            Bytes::from("v1"),
            "refresh reuses the stored body"
        );
        assert_eq!(cache.len(), 1);
    }

    fn disp(l: &CacheLookup) -> &'static str {
        match l {
            CacheLookup::Fresh(_) => "Fresh",
            CacheLookup::Stale(_) => "Stale",
            CacheLookup::Miss => "Miss",
        }
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
        assert!(cache.get("/d").fresh().is_some());
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
        assert!(cache.get("/empty").fresh().is_some());
    }

    #[test]
    fn large_body_cacheable() {
        let cache = StaticCache::new();
        let big = Bytes::from(vec![0xFFu8; 1024 * 1024]);
        cache.insert("/big.bin", big.clone(), default_meta(), 3600, 0, 100);
        let hit = cache.get("/big.bin").fresh().unwrap();
        assert_eq!(hit.body, big);
    }

    #[test]
    fn l1_promotion() {
        let cache = StaticCache::new();
        cache.insert("/hot.js", Bytes::from("hot"), default_meta(), 3600, 0, 100);

        // First get: L2 hit + L1 promote
        assert!(cache.get("/hot.js").fresh().is_some());

        // Second get: should be L1 hit (no way to verify directly,
        // but we can verify correctness)
        let hit = cache.get("/hot.js").fresh().unwrap();
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
            etag: None,
            last_modified: None,
            stale_while_revalidate_secs: 0,
            must_revalidate: false,
        };
        cache.insert("/no-ct", Bytes::from("data"), meta, 3600, 0, 100);
        let hit = cache.get("/no-ct").fresh().unwrap();
        assert!(hit.meta.content_type.is_none());
    }

    #[test]
    fn preserves_status_code() {
        let cache = StaticCache::new();
        let meta = CachedMeta {
            content_type: None,
            content_encoding: None,
            status: StatusCode::NOT_MODIFIED,
            etag: None,
            last_modified: None,
            stale_while_revalidate_secs: 0,
            must_revalidate: false,
        };
        cache.insert("/304", Bytes::new(), meta, 3600, 0, 100);
        let hit = cache.get("/304").fresh().unwrap();
        assert_eq!(hit.meta.status, StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn hit_reports_freshness_as_max_age() {
        let cache = StaticCache::new();
        cache.insert("/a.css", Bytes::from("x"), default_meta(), 600, 0, 100);
        let hit = cache.get("/a.css").fresh().unwrap();
        assert_eq!(hit.max_age_secs, 600);
    }

    #[test]
    fn fresh_entry_has_zero_age() {
        let cache = StaticCache::new();
        cache.insert("/a.css", Bytes::from("x"), default_meta(), 600, 0, 100);
        let hit = cache.get("/a.css").fresh().unwrap();
        // Just inserted with no upstream age — Age must be ~0, never the lifetime.
        assert_eq!(hit.age_secs, 0);
    }

    #[test]
    fn initial_age_is_carried_into_age_header() {
        // Object arrived from the shield already 120s old (upstream Age: 120).
        let cache = StaticCache::new();
        cache.insert("/a.css", Bytes::from("x"), default_meta(), 600, 120, 100);
        let hit = cache.get("/a.css").fresh().unwrap();
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
        assert!(cache.get("/a.css").fresh().is_some()); // promote into L1
        let n = cache.purge_all();
        assert_eq!(n, 2);
        assert_eq!(cache.len(), 0);
        // L1 entry must be treated as stale after the generation bump
        assert!(cache.get("/a.css").fresh().is_none());
        assert!(cache.get("/b.css").fresh().is_none());
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
        assert!(cache.get("/assets/x.js").fresh().is_none());
        assert!(
            cache.get("/index.html").fresh().is_some(),
            "non-matching key survives"
        );
    }

    #[test]
    fn initial_age_shortens_lifetime() {
        // Freshness 100s but already 100s old on arrival → already stale.
        let cache = StaticCache::new();
        cache.insert("/stale", Bytes::from("x"), default_meta(), 100, 100, 100);
        assert!(
            cache.get("/stale").fresh().is_none(),
            "an object that arrives already past its lifetime must not be served"
        );
    }

    // ── Surrogate-Key tags ─────────────────────────────────────────────────

    fn hm(vals: &[&str]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for v in vals {
            h.append("surrogate-key", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn surrogate_keys_are_split_on_spaces_and_commas_across_header_lines_and_deduplicated() {
        let t = surrogate_keys(&hm(&["post-1 section:a", "post-1,user/7"])).unwrap();
        assert_eq!(t, ["post-1", "section:a", "user/7"]);
        assert!(surrogate_keys(&hyper::HeaderMap::new()).unwrap().is_empty());
    }

    #[test]
    fn tags_that_cannot_be_tracked_are_refused() {
        let many = (0..=MAX_TAGS_PER_ENTRY)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(surrogate_keys(&hm(&[&many])).is_err(), "too many tags");
        let ok = (0..MAX_TAGS_PER_ENTRY)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            surrogate_keys(&hm(&[&ok])).unwrap().len(),
            MAX_TAGS_PER_ENTRY
        );
        assert!(
            surrogate_keys(&hm(&[&"x".repeat(MAX_TAG_LEN + 1)])).is_err(),
            "too long"
        );
        assert!(surrogate_keys(&hm(&[&"x".repeat(MAX_TAG_LEN)])).is_ok());
        let mut h = hyper::HeaderMap::new();
        h.append(
            "surrogate-key",
            hyper::header::HeaderValue::from_bytes(b"caf\xe9").unwrap(),
        );
        assert!(surrogate_keys(&h).is_err(), "not plain ASCII");
    }

    fn tag(cache: &StaticCache, key: &str, tags: &[&str], epoch: u64) -> bool {
        let tags: Vec<String> = tags.iter().map(|t| t.to_string()).collect();
        cache.insert_tagged(
            key,
            Bytes::from_static(b"x"),
            default_meta(),
            3600,
            0,
            100_000,
            &tags,
            epoch,
        ) == TagStore::Stored
    }

    #[test]
    fn a_tag_purge_removes_every_entry_under_it_and_nothing_else() {
        let cache = StaticCache::new();
        let e = cache.tag_epoch();
        assert!(tag(&cache, "/a", &["post-1", "news"], e));
        assert!(tag(&cache, "/b", &["post-2", "news"], e));
        assert!(tag(&cache, "/c\u{1f}de", &["post-1"], e)); // a variant key
        assert!(tag(&cache, "/d", &[], e)); // untagged
        assert_eq!(cache.purge_tags(&["post-1"]), 2);
        let present = |k: &str| matches!(cache.get(k), CacheLookup::Fresh(_));
        assert!(!present("/a") && !present("/c\u{1f}de"));
        assert!(
            present("/b") && present("/d"),
            "other tags and untagged entries survive"
        );
        assert_eq!(
            cache.purge_tags(&["news"]),
            1,
            "/a was already gone; /b goes"
        );
        assert!(!present("/b") && present("/d"));
        assert_eq!(cache.purge_tags(&["never-used"]), 0);
    }

    #[test]
    fn a_response_fetched_before_a_purge_is_not_stored_after_it() {
        let cache = StaticCache::new();
        let before = cache.tag_epoch();
        cache.purge_tags(&["anything"]); // runs while the response is still in flight
        assert!(
            !tag(&cache, "/late", &["post-1"], before),
            "refused: it may predate the purge"
        );
        assert!(!matches!(cache.get("/late"), CacheLookup::Fresh(_)));
        // fetched after the purge: stored
        assert!(tag(&cache, "/late", &["post-1"], cache.tag_epoch()));
        // untagged responses are not affected by the epoch
        assert!(tag(&cache, "/plain", &[], before));
    }

    #[test]
    fn purge_all_clears_the_index_and_moves_the_epoch() {
        let cache = StaticCache::new();
        let e = cache.tag_epoch();
        assert!(tag(&cache, "/a", &["t"], e));
        cache.purge_all();
        assert_ne!(cache.tag_epoch(), e);
        assert!(!tag(&cache, "/b", &["t"], e));
        assert_eq!(cache.purge_tags(&["t"]), 0);
    }

    #[test]
    fn the_tag_index_is_bounded_and_makes_room_by_dropping_dead_references() {
        let cache = StaticCache::new();
        let e = cache.tag_epoch();
        for i in 0..MAX_TAGS {
            assert!(
                tag(&cache, &format!("/k{i}"), &[&format!("t{i}")], e),
                "{i}"
            );
        }
        // full of live entries: a new tag cannot be tracked, so the entry is refused
        assert!(!tag(&cache, "/overflow", &["brand-new"], e));
        // existing tags can still take more keys
        assert!(tag(&cache, "/more", &["t0"], e));
        // entries that went away free their index slots
        cache.purge_prefix("/k");
        assert!(
            tag(&cache, "/overflow", &["brand-new"], e),
            "dead references were pruned"
        );
    }

    #[test]
    fn replacing_a_keys_tags_drops_the_old_ones() {
        let cache = StaticCache::new();
        let e = cache.tag_epoch();
        assert!(tag(&cache, "/a", &["old"], e));
        assert!(tag(&cache, "/a", &["new"], e)); // the origin re-tagged it
        assert_eq!(
            cache.purge_tags(&["old"]),
            0,
            "an old tag must not purge the current response"
        );
        assert!(matches!(cache.get("/a"), CacheLookup::Fresh(_)));
        assert_eq!(cache.purge_tags(&["new"]), 1);
        // a hot key that rotates through more tags than the index holds never fills it
        let e = cache.tag_epoch(); // after the purge above
        for i in 0..(MAX_TAGS * 2) {
            assert!(
                tag(&cache, "/hot", &[&format!("rot{i}")], e),
                "rotation {i}"
            );
        }
        assert_eq!(cache.purge_tags(&["rot0"]), 0);
        assert_eq!(cache.purge_tags(&[&format!("rot{}", MAX_TAGS * 2 - 1)]), 1);
    }

    #[test]
    fn an_untagged_replacement_is_no_longer_reachable_by_the_old_tag() {
        let cache = StaticCache::new();
        let e = cache.tag_epoch();
        assert!(tag(&cache, "/a", &["t"], e));
        assert!(tag(&cache, "/a", &[], e)); // the origin stopped tagging it
        assert_eq!(cache.purge_tags(&["t"]), 0);
        assert!(matches!(cache.get("/a"), CacheLookup::Fresh(_)));
    }

    #[test]
    fn purging_one_tag_removes_the_key_from_its_other_tags_too() {
        let cache = StaticCache::new();
        let e = cache.tag_epoch();
        assert!(tag(&cache, "/a", &["x", "y"], e));
        assert_eq!(cache.purge_tags(&["x"]), 1);
        // the key is gone; "y" must not keep a reference that would purge a later entry
        let e = cache.tag_epoch();
        cache.insert(
            "/a",
            Bytes::from_static(b"fresh"),
            default_meta(),
            3600,
            0,
            100,
        );
        assert_eq!(
            cache.purge_tags(&["y"]),
            0,
            "a new untagged /a is not under y"
        );
        assert!(matches!(cache.get("/a"), CacheLookup::Fresh(_)));
        let _ = e;
    }

    #[test]
    fn a_revalidation_cannot_bring_back_an_entry_a_purge_removed() {
        let cache = StaticCache::new();
        let e = cache.tag_epoch();
        assert!(tag(&cache, "/r", &["t"], e));
        let revalidating = cache.tag_epoch(); // the 304 request starts here
        cache.purge_tags(&["t"]); // ... and the entry is purged meanwhile
        let refreshed = cache.refresh_checked(
            "/r",
            Bytes::from_static(b"old"),
            default_meta(),
            3600,
            0,
            100,
            revalidating,
        );
        assert!(!refreshed);
        assert!(
            !matches!(cache.get("/r"), CacheLookup::Fresh(_)),
            "still gone"
        );
        // started after the purge: allowed
        assert!(cache.refresh_checked(
            "/r",
            Bytes::from_static(b"v"),
            default_meta(),
            3600,
            0,
            100,
            cache.tag_epoch(),
        ));
    }

    #[test]
    fn a_full_index_drops_the_previous_entry_instead_of_leaving_it_unreachable() {
        let cache = StaticCache::new();
        let e = cache.tag_epoch();
        for i in 0..MAX_TAGS {
            assert!(tag(&cache, &format!("/k{i}"), &[&format!("t{i}")], e));
        }
        assert!(tag(&cache, "/old", &["t0"], e));
        let tags = vec!["brand-new".to_string()];
        let r = cache.insert_tagged(
            "/old",
            Bytes::from_static(b"x"),
            default_meta(),
            3600,
            0,
            100_000,
            &tags,
            e,
        );
        assert_eq!(r, TagStore::IndexFull);
        assert!(
            !matches!(cache.get("/old"), CacheLookup::Fresh(_)),
            "no entry a purge cannot reach"
        );
    }
    /// The cap must hold when several threads insert at once. Every evicting thread samples
    /// the same entries and picks the same victim; all but one of those removals find it
    /// already gone, and each thread then inserts anyway. The map used to grow by one entry
    /// per collision and never came back under the cap (#481: the soak's linear RSS growth).
    #[test]
    fn the_entry_cap_holds_under_concurrent_inserts() {
        const MAX: usize = 64;
        const THREADS: usize = 8;
        const PER_THREAD: usize = 4_000;
        let cache = std::sync::Arc::new(StaticCache::new());
        if cache.l2.is_none() {
            return; // single-core backend: thread-local map, nothing to race on
        }
        let start = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let (cache, start) = (cache.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    for i in 0..PER_THREAD {
                        cache.insert(
                            &format!("/t{t}/k{i}"),
                            Bytes::from_static(b"x"),
                            default_meta(),
                            3600,
                            0,
                            MAX,
                        );
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // A thread may be between its check and its insert, so the bound is the cap plus one
        // in-flight insert per thread, not the cap itself.
        assert!(
            cache.len() <= MAX + THREADS,
            "{} entries after {} inserts with a cap of {MAX}",
            cache.len(),
            THREADS * PER_THREAD
        );
    }

    /// A map that is over its cap (the cap was lowered by a reload) comes back under it,
    /// instead of staying over by evicting exactly one entry per insert.
    #[test]
    fn a_map_over_its_cap_shrinks_back() {
        let cache = StaticCache::new();
        for i in 0..200 {
            cache.insert(
                &format!("/a{i}"),
                Bytes::from_static(b"x"),
                default_meta(),
                3600,
                0,
                1000,
            );
        }
        assert_eq!(cache.len(), 200);
        for i in 0..200 {
            cache.insert(
                &format!("/b{i}"),
                Bytes::from_static(b"x"),
                default_meta(),
                3600,
                0,
                50,
            );
        }
        assert!(
            cache.len() <= 50,
            "{} entries with a cap of 50",
            cache.len()
        );
    }
    /// hyper parses response headers without copying: each value is a slice of the
    /// connection's read buffer. A cached entry that kept such a value kept the whole buffer
    /// alive (8 KiB or more per entry, found by the #481 heap profile). What the cache stores
    /// must own its bytes.
    #[test]
    fn a_stored_entry_does_not_keep_the_upstream_read_buffer_alive() {
        // The read buffer one upstream response was parsed from: head and body together.
        let read_buffer = Bytes::from(vec![b'a'; 8192]);
        let slice_of = |range: std::ops::Range<usize>| {
            HeaderValue::from_maybe_shared(read_buffer.slice(range)).unwrap()
        };
        let meta = CachedMeta {
            content_type: Some(slice_of(0..9)),
            content_encoding: Some(slice_of(10..14)),
            status: StatusCode::OK,
            etag: Some(slice_of(20..30)),
            last_modified: Some(slice_of(40..69)),
            stale_while_revalidate_secs: 0,
            must_revalidate: false,
        };
        assert!(
            !read_buffer.is_unique(),
            "the header values share the buffer"
        );
        let cache = StaticCache::new();
        cache.insert("/pinned", Bytes::from_static(b"body"), meta, 3600, 0, 10);
        assert!(
            read_buffer.is_unique(),
            "a cached entry still references the upstream read buffer"
        );
        // ... and the values themselves are unchanged.
        let CacheLookup::Fresh(hit) = cache.get("/pinned") else {
            panic!("stored entry is fresh");
        };
        assert_eq!(hit.meta.content_type.unwrap().as_bytes(), &[b'a'; 9][..]);
        assert_eq!(
            hit.meta.content_encoding.unwrap().as_bytes(),
            &[b'a'; 4][..]
        );
        assert_eq!(hit.meta.etag.unwrap().as_bytes(), &[b'a'; 10][..]);
        assert_eq!(hit.meta.last_modified.unwrap().as_bytes(), &[b'a'; 29][..]);
    }
    // ── The byte budget (#524) ───────────────────────────────────────────────

    /// A body of `len` bytes, cached for `ttl` seconds.
    fn put(cache: &StaticCache, key: &str, len: usize, ttl: u64) {
        cache.insert(key, Bytes::from(vec![7u8; len]), default_meta(), ttl, 0, 0);
    }

    fn stored(cache: &StaticCache, key: &str) -> bool {
        !matches!(cache.get(key), CacheLookup::Miss)
    }

    fn cost(key: &str, len: usize) -> u64 {
        (key.len() + len) as u64 + ENTRY_OVERHEAD_BYTES
    }

    #[test]
    fn the_default_budget_is_an_eighth_of_the_memory_and_never_tiny() {
        assert_eq!(default_budget_mb(16_384), 2_048);
        assert_eq!(default_budget_mb(512), 64, "a 512 MiB container");
        assert_eq!(default_budget_mb(256), 32);
        assert_eq!(default_budget_mb(100), 32, "the floor");
    }

    /// Both backends: the shared map, and the thread-local one a single-core machine uses.
    fn both_backends(budget: u64) -> [StaticCache; 2] {
        [
            StaticCache::with_byte_budget(budget),
            StaticCache::single_worker_with_byte_budget(budget),
        ]
    }

    #[test]
    fn the_cache_never_holds_more_than_its_budget() {
        // Room for four 1,000-byte bodies and not five.
        let budget = 4 * cost("/k0", 1_000) + 500;
        for cache in both_backends(budget) {
            // Later keys expire later: the ones stored first are the ones to go.
            for i in 0..10u64 {
                put(&cache, &format!("/k{i}"), 1_000, 100 + i);
                assert!(cache.bytes() <= budget, "after /k{i}: {}", cache.bytes());
                assert_eq!(cache.bytes(), cache.recount());
            }
            assert_eq!(cache.len(), 4);
            for i in 0..6 {
                assert!(!stored(&cache, &format!("/k{i}")), "/k{i} was evicted");
            }
            for i in 6..10 {
                assert!(
                    stored(&cache, &format!("/k{i}")),
                    "/k{i} is the newest four"
                );
            }
        }
    }

    #[test]
    fn one_large_response_makes_room_by_evicting_as_many_as_it_takes() {
        let budget = 40 * cost("/s00", 1_000);
        for cache in both_backends(budget) {
            for i in 0..40u64 {
                put(&cache, &format!("/s{i:02}"), 1_000, 100 + i);
            }
            assert_eq!(cache.len(), 40);
            // A body that costs as much as sixteen small ones and a bit: seventeen have to
            // go, in one insert, and no more than that.
            put(&cache, "/big", 20 * 1_000, 1_000);
            assert!(stored(&cache, "/big"), "room was made");
            assert!(cache.bytes() <= budget);
            assert_eq!(cache.bytes(), cache.recount());
            assert_eq!(cache.len(), 40 - 17 + 1);
            assert!(
                stored(&cache, "/s17"),
                "the eighteenth to expire was not needed"
            );
            assert!(!stored(&cache, "/s16"), "the seventeenth was");
            assert!(stored(&cache, "/s39"), "the ones expiring last stay");
            assert!(!stored(&cache, "/s00"), "the ones expiring first went");
        }
    }

    #[test]
    fn a_response_larger_than_the_budget_is_not_stored_and_evicts_nothing() {
        let budget = 10_000;
        for cache in both_backends(budget) {
            put(&cache, "/small", 1_000, 60);
            let skipped = || {
                crate::metrics::METRICS
                    .cache_budget_skipped
                    .load(std::sync::atomic::Ordering::Relaxed)
            };
            let before = skipped();
            put(&cache, "/huge", 10_000, 60); // its cost is over 10,000 with the key
            assert!(!stored(&cache, "/huge"));
            assert!(stored(&cache, "/small"), "nothing was evicted for it");
            assert!(skipped() > before, "and it is counted");
            assert_eq!(cache.bytes(), cost("/small", 1_000));
            // An entry under the same key is left as it was, not replaced and not removed.
            put(&cache, "/v", 100, 60);
            put(&cache, "/v", 20_000, 60);
            assert!(matches!(cache.get("/v"), CacheLookup::Fresh(h) if h.body.len() == 100));
        }
    }

    /// A revalidation re-stores the body the cache already holds. Its bytes are counted
    /// already: it must not evict others to make room for itself.
    #[test]
    fn storing_the_same_body_again_evicts_nothing() {
        let budget = 4 * cost("/k0", 1_000) + 100;
        for cache in both_backends(budget) {
            for i in 0..4u64 {
                put(&cache, &format!("/k{i}"), 1_000, 100 + i);
            }
            assert_eq!(cache.len(), 4);
            for _ in 0..3 {
                cache.refresh(
                    "/k1",
                    Bytes::from(vec![7u8; 1_000]),
                    default_meta(),
                    500,
                    0,
                    0,
                );
            }
            assert_eq!(cache.len(), 4, "the full cache kept all four");
            assert_eq!(cache.bytes(), cache.recount());
            // A smaller and then a larger body under the same key: the count follows.
            put(&cache, "/k1", 10, 500);
            assert_eq!(cache.bytes(), cache.recount());
            put(&cache, "/k1", 900, 500);
            assert_eq!(cache.bytes(), cache.recount());
            assert_eq!(cache.len(), 4);
        }
    }

    /// Replacing an entry with a larger one that expires soon: the room it needs comes from
    /// the other entries, not from the entry being replaced (whose bytes the new one takes
    /// over) and not from the new entry itself.
    #[test]
    fn a_larger_replacement_evicts_another_entry_and_is_itself_stored() {
        let budget = 2 * cost("/a", 1_000) + 500;
        for cache in both_backends(budget) {
            put(&cache, "/a", 1_000, 100);
            put(&cache, "/b", 1_000, 200);
            // 1,000 bytes more under "/a", and the first of the three to expire.
            put(&cache, "/a", 2_000, 1);
            assert!(
                matches!(cache.get("/a"), CacheLookup::Fresh(h) if h.body.len() == 2_000),
                "the replacement is stored"
            );
            assert!(!stored(&cache, "/b"), "the room came from the other entry");
            assert_eq!(cache.bytes(), cost("/a", 2_000));
            assert_eq!(cache.bytes(), cache.recount());
        }
    }

    /// Between the moment an insert reserves its room and the moment it stores, another
    /// thread can remove the entry it meant to replace (a purge, or an eviction of its own).
    /// The insert then adds its whole cost where it reserved the difference: it has to find
    /// that room after the fact, or the cache is left over its budget.
    #[test]
    fn an_entry_removed_between_reserve_and_store_does_not_leave_the_cache_over_budget() {
        let budget = 2 * cost("/a", 1_000) + 100;
        for cache in both_backends(budget) {
            put(&cache, "/a", 1_000, 100);
            put(&cache, "/b", 1_000, 200);
            // This thread: a slightly larger body for "/a" reserves the 50 bytes it adds.
            let key: Arc<str> = Arc::from("/a");
            let now = Instant::now();
            let entry = L2Entry {
                body: Bytes::from(vec![7u8; 1_050]),
                meta: default_meta(),
                inserted_at: now,
                expires_at: expiry_from(now, 400, 0),
                initial_age_secs: 0,
                freshness_secs: 400,
            };
            let new_cost = entry_cost(&key, &entry);
            let reserved = cache.make_room(&key, new_cost, 0, budget).expect("room");
            assert_eq!(reserved, 50);
            // Another thread: "/a" is purged, and "/c" stored in the room that left.
            assert!(cache.remove_key("/a"));
            put(&cache, "/c", 1_000, 300);
            assert!(stored(&cache, "/b") && stored(&cache, "/c"));
            // This thread again: it stores, replacing nothing.
            cache.store_reserved(key, entry, new_cost, reserved, budget);
            assert!(cache.bytes() <= budget, "{} > {budget}", cache.bytes());
            assert_eq!(cache.bytes(), cache.recount());
            assert!(stored(&cache, "/a"), "the new entry is kept");
            assert!(
                !stored(&cache, "/b"),
                "and the room came from the next to expire"
            );
            assert!(stored(&cache, "/c"));
        }
    }

    /// The same race, where the room cannot be found after the fact within the eviction one
    /// insert may do: the entry is given up. The budget is the thing that must hold.
    #[test]
    fn an_insert_that_lost_its_room_and_cannot_find_it_again_gives_the_entry_up() {
        const SMALL: usize = 2_000;
        let budget = SMALL as u64 * cost("/s0000", 4);
        for cache in both_backends(budget) {
            // A body of four fifths of the budget under "/a", re-stored by this thread: no
            // bytes to reserve, the ones it holds are counted.
            let big = (budget as usize) * 4 / 5;
            put(&cache, "/a", big, 1_000);
            let key: Arc<str> = Arc::from("/a");
            let now = Instant::now();
            let entry = L2Entry {
                body: Bytes::from(vec![7u8; big]),
                meta: default_meta(),
                inserted_at: now,
                expires_at: expiry_from(now, 1_000, 0),
                initial_age_secs: 0,
                freshness_secs: 1_000,
            };
            let new_cost = entry_cost(&key, &entry);
            let reserved = cache.make_room(&key, new_cost, 0, budget).expect("room");
            assert_eq!(reserved, 0);
            // Meanwhile "/a" is purged and its room is taken by small entries, many more
            // than one insert may evict.
            assert!(cache.remove_key("/a"));
            for i in 0..SMALL {
                put(&cache, &format!("/s{i:04}"), 4, 100);
            }
            assert!(cache.len() > 1_900);
            cache.store_reserved(key, entry, new_cost, reserved, budget);
            assert!(cache.bytes() <= budget, "{} > {budget}", cache.bytes());
            assert_eq!(cache.bytes(), cache.recount());
            assert!(!stored(&cache, "/a"), "given up, not kept over the budget");
        }
    }

    /// One insert does a bounded amount of eviction (EVICT_ROUNDS samples of EVICT_SAMPLE
    /// entries). When that is not enough room, the response is not stored: the budget is a
    /// bound, not a target. The attempts that follow find the room.
    #[test]
    fn when_one_insert_cannot_make_enough_room_nothing_is_stored_over_the_budget() {
        const SMALL: usize = 2_000;
        let per_entry = cost("/s0000", 4);
        let budget = SMALL as u64 * per_entry;
        for cache in both_backends(budget) {
            for i in 0..SMALL {
                put(&cache, &format!("/s{i:04}"), 4, 100);
            }
            assert_eq!(cache.len(), SMALL);
            // Four fifths of the budget in one body: 1,600 small entries would have to go,
            // and one insert evicts 512 at most.
            let big = (budget as usize) * 4 / 5;
            let skipped = || {
                crate::metrics::METRICS
                    .cache_budget_skipped
                    .load(std::sync::atomic::Ordering::Relaxed)
            };
            let before = skipped();
            put(&cache, "/big", big, 1_000);
            assert!(!stored(&cache, "/big"), "not stored at the first attempt");
            assert!(cache.bytes() <= budget, "{} > {budget}", cache.bytes());
            assert_eq!(cache.bytes(), cache.recount());
            assert!(skipped() > before, "and counted");
            assert!(cache.len() < SMALL, "the attempt did evict");
            let mut attempts = 1;
            while !stored(&cache, "/big") {
                attempts += 1;
                assert!(attempts < 10, "room was never made");
                put(&cache, "/big", big, 1_000);
                assert!(cache.bytes() <= budget);
            }
            assert_eq!(cache.bytes(), cache.recount());
        }
    }

    #[test]
    fn a_lower_budget_shrinks_the_cache_as_entries_are_stored() {
        let cache = StaticCache::with_byte_budget(0); // no budget
        for i in 0..200u64 {
            put(&cache, &format!("/k{i:03}"), 1_000, 100 + i);
        }
        assert_eq!(cache.len(), 200, "no budget: bounded by nothing here");
        let budget = 10 * cost("/k000", 1_000);
        cache
            .own_budget
            .as_ref()
            .unwrap()
            .store(budget, std::sync::atomic::Ordering::Relaxed);
        // One insert evicts a bounded amount, so it takes a few of them to come down.
        let mut inserts = 0;
        while cache.bytes() > budget {
            inserts += 1;
            assert!(inserts < 50, "the cache did not shrink: {}", cache.bytes());
            put(&cache, "/new", 1_000, 10_000);
        }
        assert!(cache.len() <= 10);
        assert_eq!(cache.bytes(), cache.recount());
    }

    #[test]
    fn every_way_out_of_the_cache_gives_its_bytes_back() {
        for cache in both_backends(0) {
            let fill = |cache: &StaticCache| {
                for i in 0..20 {
                    put(cache, &format!("/a/{i}\u{1f}"), 100 + i, 60);
                    put(cache, &format!("/b/{i}?q=1\u{1f}"), 300 + i, 60);
                }
                assert_eq!(cache.bytes(), cache.recount());
                assert!(cache.bytes() > 0);
            };
            fill(&cache);
            assert_eq!(cache.purge_prefix("/a/"), 20);
            assert_eq!(cache.bytes(), cache.recount());
            assert_eq!(cache.invalidate_path("/b/3"), 1);
            assert_eq!(cache.bytes(), cache.recount());
            assert_eq!(cache.purge_all(), 19);
            assert_eq!(cache.bytes(), 0);

            // By tag, and by the entry cap.
            let epoch = cache.tag_epoch();
            for i in 0..10 {
                cache.insert_tagged(
                    &format!("/t/{i}"),
                    Bytes::from(vec![1u8; 500]),
                    default_meta(),
                    60,
                    0,
                    0,
                    &["group".to_string()],
                    epoch,
                );
            }
            assert_eq!(cache.bytes(), cache.recount());
            assert_eq!(cache.purge_tags(&["group"]), 10);
            assert_eq!(cache.bytes(), 0);
            for i in 0..30u64 {
                cache.insert(
                    &format!("/c/{i}"),
                    Bytes::from(vec![1u8; 200]),
                    default_meta(),
                    60 + i,
                    0,
                    5, // max_entries
                );
            }
            assert_eq!(cache.len(), 5);
            assert_eq!(cache.bytes(), cache.recount());
        }
    }

    /// Threads storing at the same moment reserve their room before they look for it, so
    /// what is stored stays within the budget; and when they are done the count is exact.
    #[test]
    fn the_budget_holds_under_concurrent_inserts() {
        const THREADS: usize = 8;
        const BODY: usize = 4_000;
        let budget = 64 * cost("/t0/0000", BODY);
        let cache = std::sync::Arc::new(StaticCache::with_byte_budget(budget));
        let most_seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let (cache, most_seen) = (cache.clone(), most_seen.clone());
                std::thread::spawn(move || {
                    for i in 0..4_000u64 {
                        let key = format!("/t{t}/{i:04}");
                        cache.insert(
                            &key,
                            Bytes::from(vec![t as u8; BODY]),
                            default_meta(),
                            60 + (i % 50),
                            0,
                            0,
                        );
                        most_seen.fetch_max(cache.bytes(), std::sync::atomic::Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(cache.bytes(), cache.recount(), "the count is exact at rest");
        assert!(cache.bytes() <= budget, "{} > {budget}", cache.bytes());
        assert!(
            cache.len() > 32,
            "the cache is in use, not emptied: {}",
            cache.len()
        );
        // While they ran, the count never passed the budget by more than the reservations
        // of the other threads.
        let most = most_seen.load(std::sync::atomic::Ordering::Relaxed);
        let slack = THREADS as u64 * cost("/t0/0000", BODY);
        assert!(most <= budget + slack, "{most} > {budget} + {slack}");
    }

    /// A worker thread's own L1 cache is outside the budget, so it only takes small bodies.
    #[test]
    fn a_large_body_is_served_from_the_shared_store_and_not_kept_per_thread() {
        let cache = StaticCache::with_byte_budget(0);
        if cache.l2.is_none() {
            return; // a single-core machine has no L1 tier
        }
        put(&cache, "/small", L1_MAX_BODY_BYTES, 60);
        put(&cache, "/large", L1_MAX_BODY_BYTES + 1, 60);
        for key in ["/small", "/large"] {
            assert!(matches!(cache.get(key), CacheLookup::Fresh(_)));
            assert!(matches!(cache.get(key), CacheLookup::Fresh(_)), "and again");
        }
        let in_l1 = |key: &str| {
            L1.with(|l1| {
                l1.borrow()
                    .as_ref()
                    .is_some_and(|l1| l1.map.contains_key(key))
            })
        };
        assert!(in_l1("/small"), "a body at the cap is promoted");
        assert!(!in_l1("/large"), "one byte more and it is not");
    }

    mod byte_count_properties {
        use super::*;
        use proptest::prelude::*;

        #[derive(Clone, Debug)]
        enum Op {
            Put {
                key: u8,
                len: usize,
                ttl: u64,
                max_entries: usize,
            },
            PurgePrefix(u8),
            Invalidate(u8),
            PurgeAll,
        }

        fn any_op() -> impl Strategy<Value = Op> {
            prop_oneof![
                8 => (0u8..24, 0usize..3_000, 1u64..500, prop_oneof![Just(0usize), 4usize..12])
                    .prop_map(|(key, len, ttl, max_entries)| Op::Put { key, len, ttl, max_entries }),
                1 => (0u8..3).prop_map(Op::PurgePrefix),
                1 => (0u8..24).prop_map(Op::Invalidate),
                1 => Just(Op::PurgeAll),
            ]
        }

        fn key_of(n: u8) -> String {
            format!("/p{}/{n}\u{1f}", n % 3)
        }

        proptest! {
            /// Whatever is done to the cache, in whatever order and with or without a
            /// budget, the byte count equals the bytes of what it holds, and with a budget
            /// it never passes it.
            #[test]
            fn the_count_is_exact_and_the_budget_holds(
                ops in proptest::collection::vec(any_op(), 1..120),
                budget in prop_oneof![Just(0u64), 1_000u64..20_000],
                single_worker in any::<bool>(),
            ) {
                let cache = if single_worker {
                    StaticCache::single_worker_with_byte_budget(budget)
                } else {
                    StaticCache::with_byte_budget(budget)
                };
                for op in ops {
                    match op {
                        Op::Put { key, len, ttl, max_entries } => cache.insert(
                            &key_of(key),
                            Bytes::from(vec![0u8; len]),
                            default_meta(),
                            ttl,
                            0,
                            max_entries,
                        ),
                        Op::PurgePrefix(p) => { cache.purge_prefix(&format!("/p{p}/")); }
                        Op::Invalidate(k) => {
                            let key = key_of(k);
                            cache.invalidate_path(key.trim_end_matches('\u{1f}'));
                        }
                        Op::PurgeAll => { cache.purge_all(); }
                    }
                    prop_assert_eq!(cache.bytes(), cache.recount());
                    if budget > 0 {
                        prop_assert!(cache.bytes() <= budget);
                    }
                }
            }
        }
    }
}
