// SPDX-License-Identifier: Apache-2.0
//! Upstream health checking — types and query function.
//!
//! Health state is shared with the request path via `HealthMap`
//! so unhealthy upstreams return 503 immediately.
//!
//! The background ping loop is in main.rs (inlined for simpler
//! Arc lifetime management with AppState).

use fnv::FnvHashMap;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;

/// Threshold for Gray Failures (2000 ms)
const GRAY_FAILURE_THRESHOLD_US: u64 = 2_000_000;

// ── Adaptive recovery (decorrelated-jitter backoff) ──────────────────────
// When an upstream is DOWN we re-probe on a decorrelated-jitter schedule
// (AWS / Marc Brooker) instead of the old fixed 30s interval, so a recovered
// origin is picked back up in sub-second-to-few-seconds rather than up to 30s.
// A HEALTHY upstream stays on the unchanged STEADY cadence — zero happy-path
// regression. See main.rs prober loop. State lives as two atomics below so it
// rides reload.rs's Arc-reuse merge for free.

/// Min/base DOWN re-probe delay and the floor of every decorrelated draw —
/// never probe a recovering origin faster than this (protects a struggling one).
pub const PROBE_BASE_US: u64 = 100_000; // 100 ms
/// Ceiling for a DOWN upstream's re-probe delay (a long outage is still
/// detected within this bound; ~10× the old dead-origin poll rate).
pub const PROBE_CAP_US: u64 = 3_000_000; // 3 s
/// Decorrelated-jitter growth multiplier (E[next] = 2 × prev).
pub const PROBE_MULT: u64 = 3;
/// Steady re-probe cadence for HEALTHY upstreams — deliberately unchanged from
/// the historical fixed interval so steady-state origin probe load is identical.
pub const STEADY_US: u64 = 30_000_000; // 30 s

/// Per-upstream health state.
pub struct UpstreamHealth {
    pub healthy: AtomicBool,
    pub latency_us: std::sync::atomic::AtomicU64,
    /// Current decorrelated-jitter DOWN delay (µs); reset to `PROBE_BASE_US`
    /// the moment a probe succeeds. Prober-private — the request path never
    /// reads it, so `select_best_upstream`/`is_healthy` stay lock-free.
    pub backoff_us: std::sync::atomic::AtomicU64,
    /// Absolute monotonic deadline (µs since the prober's base `Instant`) of the
    /// next probe. `0` == due immediately (fresh boot / freshly added upstream).
    pub next_probe_at_us: std::sync::atomic::AtomicU64,
}

impl UpstreamHealth {
    /// Update latency using Exponentially Weighted Moving Average (alpha = 0.125).
    /// Uses compare_exchange loop to prevent lost updates under concurrent access.
    pub fn update_latency(&self, new_lat: u64) {
        loop {
            let current = self.latency_us.load(Relaxed);
            let ewma = if current == 0 {
                new_lat
            } else {
                (new_lat + 7 * current) / 8
            };
            match self
                .latency_us
                .compare_exchange_weak(current, ewma, Relaxed, Relaxed)
            {
                Ok(_) => break,
                Err(_) => continue, // retry with fresh value
            }
        }
    }

    /// Construct a fresh upstream entry: healthy, unknown latency, backoff at
    /// the base, due to probe immediately.
    pub fn new_healthy() -> Self {
        UpstreamHealth {
            healthy: AtomicBool::new(true),
            latency_us: std::sync::atomic::AtomicU64::new(0),
            backoff_us: std::sync::atomic::AtomicU64::new(PROBE_BASE_US),
            next_probe_at_us: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Advance the probe schedule after a probe completes. `now_us` is
    /// `base.elapsed().as_micros()` from the prober's monotonic base `Instant`.
    /// A success resets the backoff to base and re-probes on the STEADY cadence;
    /// a failure draws the next decorrelated-jitter delay and grows the backoff.
    pub fn reschedule(&self, healthy: bool, now_us: u64) {
        let delay = if healthy {
            self.backoff_us.store(PROBE_BASE_US, Relaxed);
            STEADY_US
        } else {
            let prev = self.backoff_us.load(Relaxed);
            let next = next_down_delay(prev);
            self.backoff_us.store(next, Relaxed);
            next
        };
        self.next_probe_at_us
            .store(now_us.saturating_add(delay), Relaxed);
    }
}

/// Decorrelated jitter: `min(CAP, rand_in(BASE..=prev*MULT))`. The `BASE` floor
/// guarantees we never hammer a recovering origin faster than 100ms; the draw
/// stays fully decorrelated step-to-step so a pool that died together (or
/// future mesh replicas) desynchronise their recovery probes instead of
/// stampeding back in lockstep. Pure arithmetic + one `fastrand` draw —
/// nowhere near the request hot path.
#[inline]
pub fn next_down_delay(prev_us: u64) -> u64 {
    // BASE <= CAP always (compile-time consts), so clamp cannot panic.
    let ceil = prev_us
        .saturating_mul(PROBE_MULT)
        .clamp(PROBE_BASE_US, PROBE_CAP_US);
    fastrand::u64(PROBE_BASE_US..=ceil).min(PROBE_CAP_US)
}

/// Shared health state — keyed by upstream URL.
/// FnvHashMap for O(1) lookup (upstream URLs are short strings).
pub type HealthMap = Arc<FnvHashMap<String, Arc<UpstreamHealth>>>;

/// Check if a specific upstream URL is healthy.
/// Returns true if the upstream is not tracked (conservative: allow traffic).
///
/// Currently the dispatch pipeline calls `select_best_upstream` which
/// implicitly checks health while picking a candidate, so this single-URL
/// helper has no callers in production code. Kept as a documented building
/// block of the health module — the unit tests below pin its semantics, and
/// removing it would force the next caller to reimplement the same fallback
/// (untracked → healthy) by hand.
#[allow(dead_code)]
#[inline]
pub fn is_healthy(health_map: &HealthMap, upstream_url: &str) -> bool {
    match health_map.get(upstream_url) {
        Some(up) => up.healthy.load(Relaxed),
        None => true, // not tracked → assume healthy
    }
}

/// Select the best upstream among a list of candidates based on health and lowest latency.
pub fn select_best_upstream<'a>(health_map: &HealthMap, urls: &'a [String]) -> Option<&'a String> {
    if urls.is_empty() {
        return None;
    }

    let mut best_url = None;
    let mut min_latency = u64::MAX;

    for url in urls {
        match health_map.get(url) {
            Some(up) => {
                if up.healthy.load(Relaxed) {
                    let lat = up.latency_us.load(Relaxed);
                    // Gray Failure Circuit Breaker: Ignore nodes with EWMA > 2000ms
                    if lat < GRAY_FAILURE_THRESHOLD_US && lat < min_latency {
                        min_latency = lat;
                        best_url = Some(url);
                    }
                }
            }
            None => {
                // Untracked assumes 0 latency so it's prioritized (optimistic approach)
                if min_latency > 0 {
                    min_latency = 0;
                    best_url = Some(url);
                }
            }
        }
    }

    // Fallback if all valid nodes are in "gray failure" but technically "UP":
    // pick one anyway rather than 503ing immediately if we must.
    if best_url.is_none() {
        for url in urls {
            if let Some(up) = health_map.get(url) {
                if up.healthy.load(Relaxed) {
                    return Some(url);
                }
            }
        }
    }

    best_url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untracked_upstream_is_healthy() {
        let map: HealthMap = Arc::new(FnvHashMap::default());
        assert!(is_healthy(&map, "http://unknown:8080"));
    }

    #[test]
    fn tracked_healthy_upstream() {
        let mut map = FnvHashMap::default();
        map.insert(
            "http://backend:8080".to_string(),
            Arc::new(UpstreamHealth {
                healthy: AtomicBool::new(true),
                latency_us: std::sync::atomic::AtomicU64::new(0),
                ..UpstreamHealth::new_healthy()
            }),
        );
        let hm: HealthMap = Arc::new(map);
        assert!(is_healthy(&hm, "http://backend:8080"));
    }

    #[test]
    fn tracked_unhealthy_upstream() {
        let mut map = FnvHashMap::default();
        map.insert(
            "http://backend:8080".to_string(),
            Arc::new(UpstreamHealth {
                healthy: AtomicBool::new(false),
                latency_us: std::sync::atomic::AtomicU64::new(0),
                ..UpstreamHealth::new_healthy()
            }),
        );
        let hm: HealthMap = Arc::new(map);
        assert!(!is_healthy(&hm, "http://backend:8080"));
    }

    #[test]
    fn health_state_toggle() {
        let mut map = FnvHashMap::default();
        map.insert(
            "http://api:3000".to_string(),
            Arc::new(UpstreamHealth {
                healthy: AtomicBool::new(true),
                latency_us: std::sync::atomic::AtomicU64::new(0),
                ..UpstreamHealth::new_healthy()
            }),
        );
        let hm: HealthMap = Arc::new(map);
        assert!(is_healthy(&hm, "http://api:3000"));
        hm.get("http://api:3000")
            .unwrap()
            .healthy
            .store(false, Relaxed);
        assert!(!is_healthy(&hm, "http://api:3000"));
    }

    #[test]
    fn test_gray_failure_circuit_breaker() {
        let mut map = FnvHashMap::default();
        map.insert(
            "http://slow:8080".to_string(),
            Arc::new(UpstreamHealth {
                healthy: AtomicBool::new(true),
                latency_us: std::sync::atomic::AtomicU64::new(3_000_000), // > 2000ms
                ..UpstreamHealth::new_healthy()
            }),
        );
        map.insert(
            "http://fast:8080".to_string(),
            Arc::new(UpstreamHealth {
                healthy: AtomicBool::new(true),
                latency_us: std::sync::atomic::AtomicU64::new(50_000), // 50ms
                ..UpstreamHealth::new_healthy()
            }),
        );

        let hm: HealthMap = Arc::new(map);
        let urls = vec![
            "http://slow:8080".to_string(),
            "http://fast:8080".to_string(),
        ];

        let best = select_best_upstream(&hm, &urls);
        assert_eq!(best, Some(&"http://fast:8080".to_string()));
    }

    #[test]
    fn test_ewma_latency_update() {
        let up = UpstreamHealth {
            healthy: AtomicBool::new(true),
            latency_us: std::sync::atomic::AtomicU64::new(0),
            ..UpstreamHealth::new_healthy()
        };
        up.update_latency(100);
        assert_eq!(up.latency_us.load(Relaxed), 100); // initial
        up.update_latency(900);
        assert_eq!(up.latency_us.load(Relaxed), 200); // (900 + 7*100) / 8 = 200
    }

    // ── Adaptive recovery backoff ────────────────────────────────────────

    #[test]
    fn next_down_delay_respects_floor_and_cap() {
        // The decorrelated draw must always land within [BASE, CAP] for any
        // prior value — fastrand is real, but the ENVELOPE is deterministic.
        for &prev in &[0u64, PROBE_BASE_US, 1_000_000, PROBE_CAP_US, u64::MAX] {
            for _ in 0..1000 {
                let d = next_down_delay(prev);
                assert!(
                    (PROBE_BASE_US..=PROBE_CAP_US).contains(&d),
                    "delay {d} out of [{PROBE_BASE_US}, {PROBE_CAP_US}] for prev={prev}"
                );
            }
        }
    }

    #[test]
    fn next_down_delay_saturates_at_cap_no_overflow() {
        // prev*MULT must not overflow (saturating_mul) and the draw stays bounded
        // even at u64::MAX — guards the 1.82 build against UB-free overflow panics.
        for _ in 0..1000 {
            let d = next_down_delay(u64::MAX);
            assert!((PROBE_BASE_US..=PROBE_CAP_US).contains(&d));
        }
    }

    #[test]
    fn reschedule_success_resets_backoff_and_uses_steady() {
        let up = UpstreamHealth::new_healthy();
        up.backoff_us.store(2_000_000, Relaxed); // pretend mid-walk
        up.reschedule(true, 1_000_000);
        assert_eq!(
            up.backoff_us.load(Relaxed),
            PROBE_BASE_US,
            "success resets backoff"
        );
        assert_eq!(
            up.next_probe_at_us.load(Relaxed),
            1_000_000 + STEADY_US,
            "healthy upstream re-probes on the STEADY cadence"
        );
    }

    #[test]
    fn reschedule_failure_advances_within_bounds() {
        let up = UpstreamHealth::new_healthy();
        let mut now = 0u64;
        for _ in 0..50 {
            up.reschedule(false, now);
            let delay = up.next_probe_at_us.load(Relaxed) - now;
            assert!(
                (PROBE_BASE_US..=PROBE_CAP_US).contains(&delay),
                "DOWN re-probe delay {delay} out of [{PROBE_BASE_US}, {PROBE_CAP_US}]"
            );
            assert!(
                up.backoff_us.load(Relaxed) <= PROBE_CAP_US,
                "backoff never exceeds cap"
            );
            now += delay;
        }
    }
}
