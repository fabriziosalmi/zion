//! Zion metrics — lock-free atomic counters + latency histograms, Prometheus text format.
//! Zero-dependency, zero-alloc on the hot path (only atomic increments).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════
// LATENCY HISTOGRAM (lock-free, power-of-2 buckets)
// ═══════════════════════════════════════════════════════════════════

/// HDR-lite histogram with 16 power-of-2 buckets covering 1ms → 32s.
/// Each bucket is an atomic counter. Thread-safe, lock-free, zero-alloc.
///
/// Bucket boundaries (ms): 1, 2, 4, 8, 16, 32, 64, 128, 256, 512,
///                         1024, 2048, 4096, 8192, 16384, 32768, +Inf
pub struct LatencyHistogram {
    /// 16 cumulative buckets + overflow
    buckets: [AtomicU64; 17],
    /// Running sum in microseconds (for computing mean)
    sum_us: AtomicU64,
    /// Total observation count
    count: AtomicU64,
}

/// Upper bounds in microseconds for each bucket (1ms, 2ms, 4ms ... 32s)
const BUCKET_BOUNDS_US: [u64; 16] = [
    1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000,
    256_000, 512_000, 1_024_000, 2_048_000, 4_096_000, 8_192_000,
    16_384_000, 32_768_000,
];

/// Upper bounds as seconds for Prometheus le= labels
const BUCKET_BOUNDS_SEC: [f64; 16] = [
    0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128,
    0.256, 0.512, 1.024, 2.048, 4.096, 8.192, 16.384, 32.768,
];

impl LatencyHistogram {
    pub const fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), // +Inf
            ],
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record a duration observation. O(1), lock-free, zero-alloc.
    #[inline]
    pub fn observe(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.sum_us.fetch_add(us, Relaxed);
        self.count.fetch_add(1, Relaxed);

        // Find the first bucket whose upper bound >= observed value
        let idx = BUCKET_BOUNDS_US.iter()
            .position(|&bound| us <= bound)
            .unwrap_or(16); // +Inf bucket

        // Increment this bucket AND all subsequent buckets (cumulative)
        for i in idx..17 {
            self.buckets[i].fetch_add(1, Relaxed);
        }
    }

    /// Render Prometheus histogram lines for a given metric name.
    pub fn render(&self, name: &str, help: &str) -> String {
        let mut out = format!(
            "# HELP {} {}\n# TYPE {} histogram\n",
            name, help, name
        );

        for (i, &bound) in BUCKET_BOUNDS_SEC.iter().enumerate() {
            out.push_str(&format!(
                "{}_bucket{{le=\"{}\"}} {}\n",
                name, bound, self.buckets[i].load(Relaxed)
            ));
        }
        out.push_str(&format!(
            "{}_bucket{{le=\"+Inf\"}} {}\n",
            name, self.buckets[16].load(Relaxed)
        ));
        out.push_str(&format!(
            "{}_sum {:.6}\n{}_count {}\n",
            name, self.sum_us.load(Relaxed) as f64 / 1_000_000.0,
            name, self.count.load(Relaxed)
        ));
        out
    }
}

// ═══════════════════════════════════════════════════════════════════
// GLOBAL METRICS
// ═══════════════════════════════════════════════════════════════════

/// Global metrics — all atomic, all lock-free.
pub struct Metrics {
    // Counters
    pub requests_total: AtomicU64,
    pub requests_2xx: AtomicU64,
    pub requests_4xx: AtomicU64,
    pub requests_5xx: AtomicU64,
    pub waf_denied: AtomicU64,
    pub rate_limited: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub websocket_upgrades: AtomicU64,
    pub connections_total: AtomicU64,
    pub tls_handshake_errors: AtomicU64,
    // Gauges
    pub active_connections: AtomicI64,
    // Histograms
    pub request_duration: LatencyHistogram,
    pub upstream_duration: LatencyHistogram,
    pub tls_handshake_duration: LatencyHistogram,
}

impl Metrics {
    pub const fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_2xx: AtomicU64::new(0),
            requests_4xx: AtomicU64::new(0),
            requests_5xx: AtomicU64::new(0),
            waf_denied: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            websocket_upgrades: AtomicU64::new(0),
            connections_total: AtomicU64::new(0),
            tls_handshake_errors: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            request_duration: LatencyHistogram::new(),
            upstream_duration: LatencyHistogram::new(),
            tls_handshake_duration: LatencyHistogram::new(),
        }
    }

    /// Record a completed request by status code class.
    #[inline]
    pub fn record_status(&self, status: u16) {
        self.requests_total.fetch_add(1, Relaxed);
        match status {
            200..=299 => { self.requests_2xx.fetch_add(1, Relaxed); }
            400..=499 => { self.requests_4xx.fetch_add(1, Relaxed); }
            500..=599 => { self.requests_5xx.fetch_add(1, Relaxed); }
            _ => {}
        }
    }

    /// Render Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = format!(
            "# HELP zion_requests_total Total HTTP requests processed.\n\
             # TYPE zion_requests_total counter\n\
             zion_requests_total {}\n\
             # HELP zion_requests_by_status Requests by status class.\n\
             # TYPE zion_requests_by_status counter\n\
             zion_requests_by_status{{class=\"2xx\"}} {}\n\
             zion_requests_by_status{{class=\"4xx\"}} {}\n\
             zion_requests_by_status{{class=\"5xx\"}} {}\n\
             # HELP zion_waf_denied Requests denied by WAF.\n\
             # TYPE zion_waf_denied counter\n\
             zion_waf_denied {}\n\
             # HELP zion_rate_limited Requests denied by rate limiter.\n\
             # TYPE zion_rate_limited counter\n\
             zion_rate_limited {}\n\
             # HELP zion_cache_hits Cache hits (served from RAM).\n\
             # TYPE zion_cache_hits counter\n\
             zion_cache_hits {}\n\
             # HELP zion_cache_misses Cache misses (fetched from upstream).\n\
             # TYPE zion_cache_misses counter\n\
             zion_cache_misses {}\n\
             # HELP zion_websocket_upgrades WebSocket upgrades completed.\n\
             # TYPE zion_websocket_upgrades counter\n\
             zion_websocket_upgrades {}\n\
             # HELP zion_connections_total Total TLS connections accepted.\n\
             # TYPE zion_connections_total counter\n\
             zion_connections_total {}\n\
             # HELP zion_tls_handshake_errors Failed TLS handshakes.\n\
             # TYPE zion_tls_handshake_errors counter\n\
             zion_tls_handshake_errors {}\n\
             # HELP zion_active_connections Currently active TLS connections.\n\
             # TYPE zion_active_connections gauge\n\
             zion_active_connections {}\n",
            self.requests_total.load(Relaxed),
            self.requests_2xx.load(Relaxed),
            self.requests_4xx.load(Relaxed),
            self.requests_5xx.load(Relaxed),
            self.waf_denied.load(Relaxed),
            self.rate_limited.load(Relaxed),
            self.cache_hits.load(Relaxed),
            self.cache_misses.load(Relaxed),
            self.websocket_upgrades.load(Relaxed),
            self.connections_total.load(Relaxed),
            self.tls_handshake_errors.load(Relaxed),
            self.active_connections.load(Relaxed),
        );

        // Histograms
        out.push_str(&self.request_duration.render(
            "zion_request_duration_seconds",
            "Total request duration (client → response sent).",
        ));
        out.push_str(&self.upstream_duration.render(
            "zion_upstream_duration_seconds",
            "Time spent waiting for upstream response.",
        ));
        out.push_str(&self.tls_handshake_duration.render(
            "zion_tls_handshake_duration_seconds",
            "TLS handshake duration.",
        ));

        out
    }
}

/// Global static metrics instance.
pub static METRICS: Metrics = Metrics::new();

/// RAII guard for tracking active connections.
/// Increments on creation, decrements on drop.
pub struct ConnectionGuard;

impl ConnectionGuard {
    #[inline]
    pub fn new() -> Self {
        METRICS.active_connections.fetch_add(1, Relaxed);
        Self
    }
}

impl Drop for ConnectionGuard {
    #[inline]
    fn drop(&mut self) {
        METRICS.active_connections.fetch_sub(1, Relaxed);
    }
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_observe_1ms() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_millis(1));
        assert_eq!(h.count.load(Relaxed), 1);
        assert_eq!(h.sum_us.load(Relaxed), 1000);
        // 1ms falls in bucket[0] (le=0.001), so bucket[0..=16] all get +1
        assert_eq!(h.buckets[0].load(Relaxed), 1);
        assert_eq!(h.buckets[16].load(Relaxed), 1); // +Inf always cumulative
    }

    #[test]
    fn histogram_observe_500ms() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_millis(500));
        assert_eq!(h.count.load(Relaxed), 1);
        // 500ms = 500_000us → bucket bound 512_000us (index 9)
        assert_eq!(h.buckets[8].load(Relaxed), 0);  // le=0.256 → no
        assert_eq!(h.buckets[9].load(Relaxed), 1);  // le=0.512 → yes
        assert_eq!(h.buckets[16].load(Relaxed), 1);
    }

    #[test]
    fn histogram_observe_overflow() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_secs(60)); // 60s > 32.768s
        // Should only be in +Inf bucket
        for i in 0..16 {
            assert_eq!(h.buckets[i].load(Relaxed), 0, "bucket {} should be 0", i);
        }
        assert_eq!(h.buckets[16].load(Relaxed), 1);
    }

    #[test]
    fn histogram_cumulative_multiple() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_millis(1));   // 1000us <= 1000us → bucket 0
        h.observe(Duration::from_millis(10));  // 10000us: 8000 < 10000 <= 16000 → bucket 4
        h.observe(Duration::from_millis(100)); // 100000us: 64000 < 100000 <= 128000 → bucket 6
        assert_eq!(h.count.load(Relaxed), 3);
        // Cumulative: observe increments from target bucket through +Inf
        // 1ms → bucket[0..=16] all get +1
        // 10ms → bucket[4..=16] all get +1
        // 100ms → bucket[7..=16] all get +1  (100000us: 64000 < 100000 <= 128000 → bucket 7)
        assert_eq!(h.buckets[0].load(Relaxed), 1);  // only 1ms
        assert_eq!(h.buckets[3].load(Relaxed), 1);  // only 1ms (10ms is in bucket 4)
        assert_eq!(h.buckets[4].load(Relaxed), 2);  // 1ms + 10ms
        assert_eq!(h.buckets[6].load(Relaxed), 2);  // 1ms + 10ms (100ms is in bucket 7)
        assert_eq!(h.buckets[7].load(Relaxed), 3);  // all 3
        assert_eq!(h.buckets[16].load(Relaxed), 3); // +Inf = all 3
    }

    #[test]
    fn histogram_render_contains_buckets() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_millis(5));
        let out = h.render("test_metric", "A test metric.");
        assert!(out.contains("# TYPE test_metric histogram"));
        assert!(out.contains("test_metric_bucket{le=\"+Inf\"} 1"));
        assert!(out.contains("test_metric_count 1"));
        assert!(out.contains("test_metric_sum"));
    }

    #[test]
    fn histogram_sum_accuracy() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_micros(1500)); // 1.5ms
        h.observe(Duration::from_micros(2500)); // 2.5ms
        assert_eq!(h.sum_us.load(Relaxed), 4000); // 4ms total
    }

    #[test]
    fn connection_guard_increments_and_decrements() {
        let before = METRICS.active_connections.load(Relaxed);
        {
            let _g = ConnectionGuard::new();
            assert_eq!(METRICS.active_connections.load(Relaxed), before + 1);
        }
        assert_eq!(METRICS.active_connections.load(Relaxed), before);
    }

    #[test]
    fn record_status_classes() {
        let m = Metrics::new();
        m.record_status(200);
        m.record_status(201);
        m.record_status(404);
        m.record_status(500);
        assert_eq!(m.requests_total.load(Relaxed), 4);
        assert_eq!(m.requests_2xx.load(Relaxed), 2);
        assert_eq!(m.requests_4xx.load(Relaxed), 1);
        assert_eq!(m.requests_5xx.load(Relaxed), 1);
    }

    #[test]
    fn full_render_contains_all_sections() {
        let m = Metrics::new();
        m.record_status(200);
        m.request_duration.observe(Duration::from_millis(10));
        let out = m.render();
        assert!(out.contains("zion_requests_total 1"));
        assert!(out.contains("zion_active_connections 0"));
        assert!(out.contains("zion_request_duration_seconds_bucket"));
        assert!(out.contains("zion_upstream_duration_seconds_bucket"));
        assert!(out.contains("zion_tls_handshake_duration_seconds_bucket"));
    }
}
