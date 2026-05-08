//! AIMP → XDP reconciler (Track B3, "data plane wire").
//!
//! Mirrors the AIMP reputation map into the XDP `BLOCKED_V4` LPM-trie.
//! Each map update bumps a watch counter; this task wakes on the
//! counter, scans the reputation map, and inserts/removes XDP map
//! keys so the kernel-level filter reflects the latest gossip state.
//!
//! Single path: gossip → kernel-level drop on the NIC.
//!
//! Compiled only when **all three** features line up: control plane
//! (Track B), Linux, and the XDP loader (Track A). Lives in its own
//! file (rather than inside `aimp_cp.rs`) because the example crates
//! `examples/aimp_smoke.rs` and `examples/aimp_mesh.rs` embed
//! `aimp_cp.rs` via `#[path = "../src/aimp_cp.rs"]` and would otherwise
//! drag in `crate::xdp::*` references they cannot resolve.

#![cfg(all(target_os = "linux", feature = "xdp", feature = "sovereign-aimp"))]

use crate::aimp_cp::AimpControlPlane;
use crate::xdp::{Cidr4, XdpHandle};
use std::sync::Arc;

/// Spawn the reconciler task. Returns the JoinHandle so the boot path
/// can hold it for graceful shutdown if it ever cares; for now we
/// detach.
pub fn spawn(
    cp: AimpControlPlane,
    handle: Arc<XdpHandle>,
    block_threshold: f32,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut updates = cp.subscribe();
        let map = cp.reputation();
        loop {
            // Wait for the *next* version bump. `changed()` returns
            // immediately if there has been an update we haven't seen.
            if updates.changed().await.is_err() {
                break; // sender dropped → control plane shut down
            }

            // Scan all entries and reconcile with the XDP map. v0
            // implementation is O(N) per update, which is fine until
            // the map exceeds ~10k entries — at that point switch to
            // a delta-only API on the control plane.
            for entry in map.iter() {
                let (ip, rep) = entry.pair();
                let ip_v4 = match ip {
                    std::net::IpAddr::V4(v4) => *v4,
                    std::net::IpAddr::V6(_) => continue, // v0: IPv4 only
                };
                let cidr = Cidr4::host(ip_v4);
                // A score that fell back below threshold (e.g. a
                // downgrade from a peer who saw the IP behave) must
                // also remove the XDP entry — otherwise we keep
                // dropping packets from an IP that is no longer
                // collectively considered hostile.
                if rep.score >= block_threshold {
                    let _ = handle.add_blocked(cidr).await;
                } else {
                    let _ = handle.remove_blocked(cidr).await;
                }
            }
        }
    })
}
