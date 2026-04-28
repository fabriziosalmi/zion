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

/// Per-upstream health state.
pub struct UpstreamHealth {
    pub healthy: AtomicBool,
    pub latency_us: std::sync::atomic::AtomicU64,
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
}

/// Shared health state — keyed by upstream URL.
/// FnvHashMap for O(1) lookup (upstream URLs are short strings).
pub type HealthMap = Arc<FnvHashMap<String, Arc<UpstreamHealth>>>;

/// Check if a specific upstream URL is healthy.
/// Returns true if the upstream is not tracked (conservative: allow traffic).
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
            }),
        );
        map.insert(
            "http://fast:8080".to_string(),
            Arc::new(UpstreamHealth {
                healthy: AtomicBool::new(true),
                latency_us: std::sync::atomic::AtomicU64::new(50_000), // 50ms
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
        };
        up.update_latency(100);
        assert_eq!(up.latency_us.load(Relaxed), 100); // initial
        up.update_latency(900);
        assert_eq!(up.latency_us.load(Relaxed), 200); // (900 + 7*100) / 8 = 200
    }
}
