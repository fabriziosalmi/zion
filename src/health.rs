//! Upstream health checking — types and query function.
//!
//! Health state is shared with the request path via `HealthMap`
//! so unhealthy upstreams return 503 immediately.
//!
//! The background ping loop is in main.rs (inlined for simpler
//! Arc lifetime management with AppState).

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;

/// Per-upstream health state.
pub struct UpstreamHealth {
    pub url: String,
    pub healthy: AtomicBool,
}

/// Shared health state — keyed by upstream URL.
/// The request path uses this to check if an upstream is healthy.
pub type HealthMap = Arc<Vec<UpstreamHealth>>;

/// Check if a specific upstream URL is healthy.
/// Returns true if the upstream is not tracked (conservative: allow traffic).
#[inline]
pub fn is_healthy(health_map: &HealthMap, upstream_url: &str) -> bool {
    for up in health_map.iter() {
        if up.url == upstream_url {
            return up.healthy.load(Relaxed);
        }
    }
    true // not tracked → assume healthy
}
