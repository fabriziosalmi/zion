# ADR-0001: ArcSwap for config + TLS hot-reload

- **Status**: accepted
- **Date**: 2026-04-15 (retrofit; original implementation lands in Phase 1)
- **Tags**: hot-reload, concurrency, arc-swap

## Context

Zion is a single-process daemon serving 100K+ rps with a config file the
operator can edit at runtime: routes, upstreams, WAF profiles, listen ports.
A reload that *blocks* even a single request handler for the duration of a
file parse would visibly stall the request budget at our throughput target.
Reads happen on every request path; writes happen on a `notify`-driven
config-watcher task at human cadence.

The standard read-write trade-off picks were:

1. `RwLock<Snapshot>`: writers block readers and vice-versa.
2. `Arc<Mutex<Snapshot>>`: serializes everyone, even readers.
3. `crossbeam` epoch-based reclamation (EBR): correct but complex to wire.
4. `arc-swap::ArcSwap<Snapshot>`: single atomic pointer; readers pay one
   `load_full()` (Acquire load + refcount bump, ~5 ns); writers do an
   atomic store; old snapshots are reclaimed by the next epoch.

## Decision

Wrap every reload-affected snapshot in `ArcSwap<T>`:

- `AppState.config: Arc<ArcSwap<ResolvedAppConfig>>` — the routing table,
  WAF profiles, CORS, rate limits, XFF policy, listen addresses.
- `AppState.tls_acceptor: Arc<ArcSwap<TlsAcceptor>>` — TLS material and
  rustls-derived acceptor.

Each request's hot path begins with `let cfg = state.cfg();`, which calls
`load_full()` once and pins the `Arc<ResolvedAppConfig>` for the request's
lifetime. A reload mid-request never tears the snapshot.

## Consequences

- **Positive**: read cost is ~5 ns; readers never block. Reload is wait-free
  from the reader's perspective. The "request observes one snapshot for its
  whole lifetime" property is what enables [ADR-0003](0003-two-level-cache-with-generation.md)'s
  generation counter to be safe.
- **Positive**: parse + validate happens off-thread (`spawn_blocking`); only
  a successfully validated config swaps in. A bad reload leaves the previous
  state intact.
- **Negative**: the `Arc<ResolvedAppConfig>` lives until the slowest in-flight
  request completes. A multi-minute SSE stream will hold the *previous*
  config for that duration. This is bounded by our connection-level
  timeouts and acceptable.
- **Neutral**: every per-request branch reads `cfg.<field>` instead of
  the historical free-floating statics. We accepted that ergonomic shift
  for the hot-reload property.

## Alternatives considered

- **`tokio::sync::watch`** — semantics fit, but the `Receiver<T>`
  per-borrow API forces a `let g = rx.borrow();` ergonomics where the
  guard's lifetime drives the request handler's structure. ArcSwap's
  owned `Arc` is friendlier across `await` points.
- **`crossbeam::epoch`** — full EBR is correct but we'd own the epoch
  bookkeeping; ArcSwap's API encapsulates the same property in a much
  smaller surface.
- **Restart-only reload** (Nginx-style master/worker rotation) — zero
  in-process complexity, but operationally heavier and produces a
  measurable connection-drop window.

## References

- `arc-swap` crate: <https://docs.rs/arc-swap>
- `src/main.rs` `AppState::cfg` and the listener supervisor in
  `src/listener.rs`.
- [docs/deploy/hot-reload.md](../deploy/hot-reload.md) for the operator
  surface.
