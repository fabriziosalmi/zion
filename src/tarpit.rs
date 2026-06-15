// SPDX-License-Identifier: Apache-2.0
//! L7 tarpit — a bounded *held* response for flagged sources (issue #151).
//!
//! When tag-driven enforcement (#150) decides to deny a request — origin
//! class on the deny list, or AIMP mesh reputation past the threshold — the
//! default answer is a cheap `403`, which is cheap for the attacker too. The
//! tarpit turns that into a *held* connection: the flagged request is parked
//! for a bounded `hold` duration before the rejection is sent, so a backed
//! flood pays wall-clock and socket budget instead of getting an instant,
//! immediately-recyclable refusal.
//!
//! **Bounded.** A single global ceiling caps how many requests may be held
//! at once (`max_concurrent`); at the ceiling the tarpit *sheds* back to the
//! immediate rejection. A held request keeps the connection's global
//! `conn_limit` permit and per-IP slot for the whole hold, so the ceiling is
//! clamped at config-load to a small fraction (1/4) of the global connection
//! pool — the tarpit imposes cost on the attacker without pinning admission
//! for legitimate traffic. The ceiling counter is the `zion_tarpit_active`
//! gauge. Note: the ceiling counts in-flight held *requests* (HTTP/2 streams),
//! so under H2 a few connections can occupy many slots — size `max_concurrent`
//! with stream fan-out in mind. A per-IP sub-cap (to stop one source
//! monopolising the holding capacity) is a deferred follow-up.
//!
//! **Cost model** mirrors [`crate::connlimit`]: admission is a single CAS on
//! an atomic; a held connection is one parked tokio timer plus the open
//! socket, released by an RAII guard so the active gauge and held-time
//! counter stay correct even on early return or panic. Disabled (the
//! default) the enforcement deny path never calls in here at all.
#![cfg_attr(not(any(feature = "geo-ita", feature = "geo-eu")), allow(dead_code))]

use crate::metrics::METRICS;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// RAII guard for one held tarpit slot. While alive it counts against the
/// `active` ceiling; on drop it releases the slot and records how long the
/// connection was held. Borrows the counters so the core admission logic is
/// unit-testable against local atomics (production borrows the `'static`
/// [`METRICS`]).
pub struct TarpitGuard<'a> {
    active: &'a AtomicU64,
    held_ms_total: &'a AtomicU64,
    start: Instant,
}

impl Drop for TarpitGuard<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Release);
        let held = self.start.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.held_ms_total.fetch_add(held, Ordering::Relaxed);
    }
}

/// Core admission: claim one slot under `ceiling` by CAS-bumping `active`,
/// or `None` if already at the ceiling. `ceiling == 0` admits nothing.
/// Decoupled from [`METRICS`] so it is testable with local atomics.
fn enter<'a>(
    active: &'a AtomicU64,
    held_ms_total: &'a AtomicU64,
    ceiling: u32,
) -> Option<TarpitGuard<'a>> {
    let ceiling = ceiling as u64;
    let mut cur = active.load(Ordering::Relaxed);
    loop {
        if cur >= ceiling {
            return None;
        }
        match active.compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => {
                return Some(TarpitGuard {
                    active,
                    held_ms_total,
                    start: Instant::now(),
                })
            }
            Err(actual) => cur = actual,
        }
    }
}

/// Try to enter the tarpit under the global ceiling. `Some(guard)` → the
/// caller holds a slot (the gauge is already incremented) and should park
/// for the hold duration; the guard releases the slot and records the held
/// time on drop. `None` → the ceiling is full; the caller must shed to an
/// immediate rejection.
pub fn try_enter(ceiling: u32) -> Option<TarpitGuard<'static>> {
    enter(
        &METRICS.tarpit_active,
        &METRICS.tarpit_held_ms_total,
        ceiling,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_admits_then_sheds() {
        let active = AtomicU64::new(0);
        let held = AtomicU64::new(0);
        let g1 = enter(&active, &held, 2);
        let g2 = enter(&active, &held, 2);
        assert!(g1.is_some() && g2.is_some());
        assert_eq!(active.load(Ordering::Relaxed), 2);
        // At the ceiling → shed (no slot).
        assert!(enter(&active, &held, 2).is_none());
        assert_eq!(active.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn drop_releases_slot() {
        let active = AtomicU64::new(0);
        let held = AtomicU64::new(0);
        {
            let _g = enter(&active, &held, 1).unwrap();
            assert_eq!(active.load(Ordering::Relaxed), 1);
            // Second is shed while the first is held.
            assert!(enter(&active, &held, 1).is_none());
        } // guard drops here → slot released, held time recorded
        assert_eq!(active.load(Ordering::Relaxed), 0);
        // Freed → admits again.
        assert!(enter(&active, &held, 1).is_some());
    }

    #[test]
    fn ceiling_zero_sheds_everything() {
        let active = AtomicU64::new(0);
        let held = AtomicU64::new(0);
        assert!(enter(&active, &held, 0).is_none());
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    // Lock in the CAS invariant under real contention: the active count must
    // never exceed the ceiling, and must return to zero once every guard is
    // dropped. Guards against a future "simplification" (e.g. fetch_add +
    // post-check) that would transiently overshoot.
    #[test]
    fn ceiling_never_exceeded_under_contention() {
        use std::sync::Arc;
        use std::thread;
        const CEILING: u32 = 8;
        const THREADS: usize = 16;
        const ITERS: usize = 2_000;
        let active = Arc::new(AtomicU64::new(0));
        let held = Arc::new(AtomicU64::new(0));
        let max_seen = Arc::new(AtomicU64::new(0));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let active = Arc::clone(&active);
                let held = Arc::clone(&held);
                let max_seen = Arc::clone(&max_seen);
                thread::spawn(move || {
                    for _ in 0..ITERS {
                        if let Some(_g) = enter(&active, &held, CEILING) {
                            // Observe occupancy while holding the slot.
                            let now = active.load(Ordering::Relaxed);
                            max_seen.fetch_max(now, Ordering::Relaxed);
                            // `_g` drops here, releasing the slot.
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(
            max_seen.load(Ordering::Relaxed) <= CEILING as u64,
            "active exceeded ceiling under contention: {} > {}",
            max_seen.load(Ordering::Relaxed),
            CEILING
        );
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }
}
