// SPDX-License-Identifier: Apache-2.0
//! Tiny `metrics` shim for the `aimp_smoke` / `aimp_mesh` examples
//! (issue #69). The examples include `aimp_cp.rs` via `#[path = ...]`,
//! so calls inside it that reference `crate::metrics::METRICS` need a
//! resolver — the example crate's root has no `metrics` module.
//!
//! This stub matches the field layout `aimp_cp.rs` reads from
//! (`mesh_claims_*`, `mesh_score_lookups`, `mesh_gossip_bytes_*`)
//! and is otherwise inert: no rendering, no labels, just `AtomicU64`s
//! that absorb `fetch_add` calls.
//!
//! Why not just stub a no-op `crate::metrics::METRICS`? Because the
//! source uses `.fetch_add(...)` on each field — the *type* must
//! match `AtomicU64` at compile time. A trait-object shim would
//! require changing the source.
//!
//! Pattern matches `xdp/zion-xdp-prog/` and `aimp_xdp_sync.rs` —
//! examples deliberately keep their dependency surface minimal so
//! they ship in a microVM without zion's full module tree.

#![allow(dead_code)]

use std::sync::atomic::AtomicU64;

pub struct Metrics {
    pub mesh_claims_emitted: AtomicU64,
    pub mesh_claims_received: AtomicU64,
    pub mesh_claims_dropped_signature: AtomicU64,
    pub mesh_claims_dropped_replay: AtomicU64,
    pub mesh_claims_dropped_other: AtomicU64,
    pub mesh_claims_dropped_rate: AtomicU64,
    pub mesh_score_lookups: AtomicU64,
    pub mesh_gossip_bytes_in: AtomicU64,
    pub mesh_gossip_bytes_out: AtomicU64,
}

impl Metrics {
    const fn new() -> Self {
        Self {
            mesh_claims_emitted: AtomicU64::new(0),
            mesh_claims_received: AtomicU64::new(0),
            mesh_claims_dropped_signature: AtomicU64::new(0),
            mesh_claims_dropped_replay: AtomicU64::new(0),
            mesh_claims_dropped_other: AtomicU64::new(0),
            mesh_claims_dropped_rate: AtomicU64::new(0),
            mesh_score_lookups: AtomicU64::new(0),
            mesh_gossip_bytes_in: AtomicU64::new(0),
            mesh_gossip_bytes_out: AtomicU64::new(0),
        }
    }
}

pub static METRICS: Metrics = Metrics::new();
