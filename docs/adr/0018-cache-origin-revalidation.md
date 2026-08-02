# ADR-0018: Cache origin-side revalidation (RFC 9111 §4.3)

- **Status**: accepted
- **Date**: 2026-07-31
- **Deciders**: fabriziosalmi
- **Tags**: cache, performance, rfc-9111, standards

## Context

zion's two-level cache (ADR-0003) served fresh entries and, on expiry,
**evicted and re-downloaded** the whole object. RFC 9111 §4.3 says a shared cache
SHOULD instead **revalidate** a stale entry with a conditional request and, on a
`304 Not Modified`, reuse the stored body — the common case for large, rarely-
changing static assets behind a validator. The validators were already stored
(`CachedMeta.etag` / `last_modified`, #262); only the revalidation flow was
missing. Issue #266 flagged this as the **riskiest** cache change because it
touches the perf-critical `get()` hot path and the singleflight machinery.

## Decision

### Lookup becomes three-valued

`StaticCache::get()` returns `CacheLookup { Fresh(CacheHit) | Stale(CacheHit) |
Miss }` instead of `Option<CacheHit>`. An expired entry is returned as **`Stale`
and kept in place** (not evicted) so the caller can revalidate and revive it. The
**L2 tier is the freshness authority**: the thread-local L1 still evicts its own
expired/stale-generation entries and returns a fresh hit only, so an L1 miss
falls through to L2, which decides Fresh vs Stale vs Miss. This keeps the change
off L1's zero-contention fast path.

`refresh(path, body, meta, freshness, age)` revives a stale entry by re-inserting
the **stored body** with a new lifetime — a 304 keeps the body, so this reuses
the battle-tested `insert` (L2 write + generation bump ⇒ L1 re-promotes) rather
than adding a second mutation path across all tiers.

### Dispatch flow (`handle_static_cache`)

On `Stale` **with a validator**, zion adds `If-None-Match`/`If-Modified-Since`
from the stored validators and reuses the existing origin-fetch + singleflight
path as a conditional GET:

- **`304`** → `refresh` the entry, signal singleflight waiters (they observe the
  revived fresh entry), serve the stored body as `X-Zion-Cache: REVALIDATED`,
  bump `zion_cache_revalidations`. No re-download.
- **`200`** (or any non-304) → new content: fall through to the normal
  store-and-serve, replacing the stale entry.
- **Origin error** (unreachable / transport failure) → **stale-if-error**
  (§4.2.4): serve the stored stale body as `X-Zion-Cache: STALE` rather than
  propagate the error — a flapping origin does not take cached content down.

A `Stale` entry with **no validator** falls through to a full fetch (a
conditional GET would be pointless). `only-if-cached` (§5.2.1.7) still serves
only a *fresh* entry (it must not contact the origin, so it cannot revalidate).

## Consequences

- **Positive**: standards-conformant revalidation; the origin↔zion transfer is
  saved on the 304 path; stale-if-error adds resilience to origin blips. Proven
  live end-to-end (MISS → HIT → REVALIDATED → HIT, `revalidations` counter moves,
  body served from cache on the 304).
- **Negative**: an expired entry now lingers (as `Stale`) until revalidated or
  capacity-evicted, instead of being dropped at expiry — a small memory-residency
  change, bounded by the existing sampled capacity eviction (it removes expired
  entries first under pressure).
- **Neutral**: full HTTP-date `If-Modified-Since` comparison and forwarding a
  *client's* conditional through a 304 revalidation to answer the client with 304
  too remain follow-ups; today a revalidated entry is served as a full `200`
  (`REVALIDATED`).

## Relationship to ADR-0003

A follow-up, not a supersession. ADR-0003 (two-level cache with generation) stays
`accepted`; its L1/L2/generation model is unchanged — this only makes expiry a
revalidation trigger instead of an eviction, using the same generation bump to
propagate a refresh.

## References

- ADR-0003 (two-level cache), RFC 9111 §4.3 / §4.2.4, RFC 9110 §13
- `src/cache.rs` (`CacheLookup`, `get`, `refresh`), `src/dispatch.rs`
  (`handle_static_cache`, `cache_response`, `add_conditional_headers`)
- `docs/config/caching.md` (Origin-side revalidation), issue #266
