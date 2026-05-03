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
    /// 16 non-cumulative (differential) buckets + overflow.
    /// Each bucket stores only the count for that exact range.
    /// Cumulative sums are computed in render() (1x/sec, not 200K/sec).
    /// This reduces observe() from 17 atomics to 3.
    buckets: [AtomicU64; 17],
    /// Running sum in microseconds (for computing mean)
    sum_us: AtomicU64,
    /// Total observation count
    count: AtomicU64,
}

/// Upper bounds in microseconds for each bucket (1ms, 2ms, 4ms ... 32s)
const BUCKET_BOUNDS_US: [u64; 16] = [
    1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 512_000, 1_024_000,
    2_048_000, 4_096_000, 8_192_000, 16_384_000, 32_768_000,
];

/// Upper bounds as seconds for Prometheus le= labels
const BUCKET_BOUNDS_SEC: [f64; 16] = [
    0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256, 0.512, 1.024, 2.048, 4.096,
    8.192, 16.384, 32.768,
];

impl LatencyHistogram {
    pub const fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0), // +Inf
            ],
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Approximate quantile in microseconds. Uses the non-cumulative power-of-2
    /// buckets — resolution is 2x per step (1, 2, 4, 8, … 32 768 ms), so the
    /// returned value is the upper bound of the bucket containing the q-th
    /// observation. Good enough for live TUI display; not for SLO math.
    /// Returns 0 when no observations have been recorded.
    ///
    /// Accumulates bucket counts on the fly since buckets are stored
    /// differentially (each only counts its own range). This runs at
    /// TUI/scrape cadence (~1/sec), never on the hot path.
    pub fn quantile_us(&self, q: f64) -> u64 {
        let count = self.count.load(Relaxed);
        if count == 0 {
            return 0;
        }
        let q = q.clamp(0.0, 1.0);
        let target = ((count as f64) * q).ceil().max(1.0) as u64;
        let mut cumulative = 0u64;
        for (i, b) in self.buckets.iter().take(16).enumerate() {
            cumulative += b.load(Relaxed);
            if cumulative >= target {
                return BUCKET_BOUNDS_US[i];
            }
        }
        // All target observations are in the +Inf bucket — return double the
        // last finite bound so the TUI can show ">32s" without lying.
        BUCKET_BOUNDS_US[15] * 2
    }

    /// Record a duration observation. O(1), lock-free, zero-alloc.
    /// Only 3 atomic ops per observation (was 17 with cumulative buckets).
    #[inline]
    pub fn observe(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.sum_us.fetch_add(us, Relaxed);
        self.count.fetch_add(1, Relaxed);

        // Find the first bucket whose upper bound >= observed value
        let idx = BUCKET_BOUNDS_US
            .iter()
            .position(|&bound| us <= bound)
            .unwrap_or(16); // +Inf bucket

        // Non-cumulative: increment only the target bucket.
        // Cumulative sums computed in render() (once per scrape, not per request).
        self.buckets[idx].fetch_add(1, Relaxed);
    }

    /// Render Prometheus histogram lines. Zero-alloc using BytesMut/itoa/ryu.
    pub fn render(&self, name: &str, help: &str, out: &mut bytes::BytesMut) {
        out.extend_from_slice(b"# HELP ");
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b" ");
        out.extend_from_slice(help.as_bytes());
        out.extend_from_slice(b"\n# TYPE ");
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b" histogram\n");

        let mut itoa_buf = itoa::Buffer::new();
        let mut ryu_buf = ryu::Buffer::new();

        // Load non-cumulative bucket counts and compute cumulative sums
        // for Prometheus output. This runs once per scrape (~1/15s), not per request.
        let mut cumulative = 0u64;
        for (i, &bound) in BUCKET_BOUNDS_SEC.iter().enumerate() {
            cumulative += self.buckets[i].load(Relaxed);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"_bucket{le=\"");
            out.extend_from_slice(ryu_buf.format(bound).as_bytes());
            out.extend_from_slice(b"\"} ");
            out.extend_from_slice(itoa_buf.format(cumulative).as_bytes());
            out.extend_from_slice(b"\n");
        }

        cumulative += self.buckets[16].load(Relaxed);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"_bucket{le=\"+Inf\"} ");
        out.extend_from_slice(itoa_buf.format(cumulative).as_bytes());
        out.extend_from_slice(b"\n");

        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"_sum ");
        out.extend_from_slice(
            ryu_buf
                .format(self.sum_us.load(Relaxed) as f64 / 1_000_000.0)
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"_count ");
        out.extend_from_slice(itoa_buf.format(self.count.load(Relaxed)).as_bytes());
        out.extend_from_slice(b"\n");
    }
}

// ═══════════════════════════════════════════════════════════════════
// SHARDED COUNTER (reduces cache-line bouncing on high-core systems)
// ═══════════════════════════════════════════════════════════════════

#[repr(align(64))]
struct CounterShard {
    val: AtomicU64,
}

/// A 16-way sharded lock-free counter to prevent false sharing and
/// atomic contention on the hottest paths (e.g., requests_total, cache_hits).
pub struct ShardedCounter {
    shards: [CounterShard; 16],
}

impl ShardedCounter {
    pub const fn new() -> Self {
        Self {
            shards: [
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
                CounterShard {
                    val: AtomicU64::new(0),
                },
            ],
        }
    }

    #[inline]
    pub fn fetch_add(&self, n: u64, order: std::sync::atomic::Ordering) {
        // Fast thread-local hash for shard assignment
        thread_local! {
            static SHARD_IDX: usize = {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&std::thread::current().id(), &mut hasher);
                (std::hash::Hasher::finish(&hasher) % 16) as usize
            };
        }
        let idx = SHARD_IDX.with(|&i| i);
        self.shards[idx].val.fetch_add(n, order);
    }

    pub fn load(&self, order: std::sync::atomic::Ordering) -> u64 {
        let mut sum = 0;
        for shard in &self.shards {
            sum += shard.val.load(order);
        }
        sum
    }
}

// ═══════════════════════════════════════════════════════════════════
// GLOBAL METRICS
// ═══════════════════════════════════════════════════════════════════

/// Global metrics — all atomic, all lock-free.
pub struct Metrics {
    // Sharded Counters (Hot path)
    pub requests_total: ShardedCounter,
    pub requests_2xx: ShardedCounter,
    pub requests_4xx: ShardedCounter,
    pub requests_5xx: ShardedCounter,
    pub waf_denied: ShardedCounter,
    /// WAF "would block" simulations: route was in `waf_shadow=true` mode,
    /// the WAF matched a pattern, but we let the request through anyway.
    /// Lets operators measure migration-from-nginx false-positive rate
    /// without blocking real traffic. Increments alongside a `logging::warn`.
    pub waf_shadow_would_block: ShardedCounter,
    pub rate_limited: ShardedCounter,
    pub cache_hits: ShardedCounter,
    pub cache_misses: ShardedCounter,

    // Global Counters (Cold Path or connection-level)
    pub websocket_upgrades: AtomicU64,
    pub connections_total: AtomicU64,
    pub tls_handshake_errors: AtomicU64,

    // Gauges
    pub active_connections: AtomicI64,

    // Histograms
    pub request_duration: LatencyHistogram,
    pub upstream_duration: LatencyHistogram,
    pub tls_handshake_duration: LatencyHistogram,

    // Caching for Prometheus Output — single ArcSwap for atomicity.
    // Stores (timestamp_secs, rendered_bytes) as one atomic unit to prevent
    // readers seeing a fresh timestamp with a stale buffer.
    pub cached_render: arc_swap::ArcSwap<(u64, bytes::Bytes)>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: ShardedCounter::new(),
            requests_2xx: ShardedCounter::new(),
            requests_4xx: ShardedCounter::new(),
            requests_5xx: ShardedCounter::new(),
            waf_denied: ShardedCounter::new(),
            waf_shadow_would_block: ShardedCounter::new(),
            rate_limited: ShardedCounter::new(),
            cache_hits: ShardedCounter::new(),
            cache_misses: ShardedCounter::new(),
            websocket_upgrades: AtomicU64::new(0),
            connections_total: AtomicU64::new(0),
            tls_handshake_errors: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            request_duration: LatencyHistogram::new(),
            upstream_duration: LatencyHistogram::new(),
            tls_handshake_duration: LatencyHistogram::new(),
            cached_render: arc_swap::ArcSwap::from_pointee((0u64, bytes::Bytes::new())),
        }
    }

    /// Record a completed request by status code class.
    #[inline]
    pub fn record_status(&self, status: u16) {
        self.requests_total.fetch_add(1, Relaxed);
        match status {
            200..=299 => {
                self.requests_2xx.fetch_add(1, Relaxed);
            }
            400..=499 => {
                self.requests_4xx.fetch_add(1, Relaxed);
            }
            500..=599 => {
                self.requests_5xx.fetch_add(1, Relaxed);
            }
            _ => {}
        }
    }

    /// Render Prometheus text exposition format. Lock-free cached.
    pub fn render(&self) -> bytes::Bytes {
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Lock-free cache check: single atomic load of (ts, bytes) for consistency
        let cached = self.cached_render.load_full();
        if cached.0 == now_sec {
            return cached.1.clone();
        }

        // Preallocate estimated capacity to avoid reallocations
        let mut out = bytes::BytesMut::with_capacity(4096);
        let mut itoa_buf = itoa::Buffer::new();

        out.extend_from_slice(
            b"# HELP zion_requests_total Total HTTP requests processed.\n\
                                # TYPE zion_requests_total counter\n\
                                zion_requests_total ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.requests_total.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        // Hot-reload generation. Bumped on every successful zion.toml
        // reload; lets dashboards alert on "no recent reload" or detect
        // unexpected reload storms.
        out.extend_from_slice(
            b"# HELP zion_config_generation Successful zion.toml hot-reloads since process start.\n\
                                # TYPE zion_config_generation counter\n\
                                zion_config_generation ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(crate::reload::current_generation())
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_requests_by_status Requests by status class.\n\
                                # TYPE zion_requests_by_status counter\n\
                                zion_requests_by_status{class=\"2xx\"} ",
        );
        out.extend_from_slice(itoa_buf.format(self.requests_2xx.load(Relaxed)).as_bytes());
        out.extend_from_slice(b"\nzion_requests_by_status{class=\"4xx\"} ");
        out.extend_from_slice(itoa_buf.format(self.requests_4xx.load(Relaxed)).as_bytes());
        out.extend_from_slice(b"\nzion_requests_by_status{class=\"5xx\"} ");
        out.extend_from_slice(itoa_buf.format(self.requests_5xx.load(Relaxed)).as_bytes());
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_waf_denied Requests denied by WAF.\n\
                                # TYPE zion_waf_denied counter\n\
                                zion_waf_denied ",
        );
        out.extend_from_slice(itoa_buf.format(self.waf_denied.load(Relaxed)).as_bytes());
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_waf_shadow_would_block Requests the WAF would have denied if shadow mode were off.\n\
                                # TYPE zion_waf_shadow_would_block counter\n\
                                zion_waf_shadow_would_block ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.waf_shadow_would_block.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_rate_limited Requests denied by rate limiter.\n\
                                # TYPE zion_rate_limited counter\n\
                                zion_rate_limited ",
        );
        out.extend_from_slice(itoa_buf.format(self.rate_limited.load(Relaxed)).as_bytes());
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_cache_hits Cache hits (served from RAM).\n\
                                # TYPE zion_cache_hits counter\n\
                                zion_cache_hits ",
        );
        out.extend_from_slice(itoa_buf.format(self.cache_hits.load(Relaxed)).as_bytes());
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_cache_misses Cache misses (fetched from upstream).\n\
                                # TYPE zion_cache_misses counter\n\
                                zion_cache_misses ",
        );
        out.extend_from_slice(itoa_buf.format(self.cache_misses.load(Relaxed)).as_bytes());
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_websocket_upgrades WebSocket upgrades completed.\n\
                                # TYPE zion_websocket_upgrades counter\n\
                                zion_websocket_upgrades ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.websocket_upgrades.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_connections_total Total TLS connections accepted.\n\
                                # TYPE zion_connections_total counter\n\
                                zion_connections_total ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.connections_total.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_tls_handshake_errors Failed TLS handshakes.\n\
                                # TYPE zion_tls_handshake_errors counter\n\
                                zion_tls_handshake_errors ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.tls_handshake_errors.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_active_connections Currently active TLS connections.\n\
                                # TYPE zion_active_connections gauge\n\
                                zion_active_connections ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.active_connections.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        self.request_duration.render(
            "zion_request_duration_seconds",
            "Total request duration (client -> response sent).",
            &mut out,
        );
        self.upstream_duration.render(
            "zion_upstream_duration_seconds",
            "Time spent waiting for upstream response.",
            &mut out,
        );
        self.tls_handshake_duration.render(
            "zion_tls_handshake_duration_seconds",
            "TLS handshake duration.",
            &mut out,
        );

        let b: bytes::Bytes = out.into();

        // Lock-free atomic cache update (ts + bytes as one unit)
        self.cached_render
            .store(std::sync::Arc::new((now_sec, b.clone())));

        b
    }
}

/// Global static metrics instance.
pub static METRICS: std::sync::LazyLock<Metrics> = std::sync::LazyLock::new(Metrics::new);

/// Process start time, captured by main() before the runtime starts.
/// Used by the JSON snapshot endpoint to expose uptime.
pub static START_INSTANT: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

#[inline]
pub fn record_start() {
    let _ = START_INSTANT.get_or_init(std::time::Instant::now);
}

#[inline]
pub fn uptime_secs() -> u64 {
    START_INSTANT
        .get()
        .map(|i| i.elapsed().as_secs())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════
// JSON SNAPSHOT (consumed by `zion top` and external tools)
// ═══════════════════════════════════════════════════════════════════

/// One row in the upstream health table — what the TUI shows per upstream.
#[derive(serde::Serialize)]
pub struct UpstreamRow<'a> {
    pub url: &'a str,
    pub healthy: bool,
    pub latency_us: u64,
}

/// Build a JSON snapshot of the live state of Zion. Consumed by `zion top`,
/// dashboards, and any external observability tool that wants something
/// richer than the Prometheus text format.
///
/// Cost: one allocation for the output `Bytes`. Snapshot is built fresh on
/// every call (no caching) since the TUI polls at sub-second cadence and we
/// want to surface the live counter values, not a 1-second-old cached blob.
pub fn snapshot_json(
    platform: &crate::bootstrap::Platform,
    upstreams: &[UpstreamRow<'_>],
) -> bytes::Bytes {
    use serde_json::json;

    let m = &METRICS;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let payload = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp_ms": now_ms,
        "uptime_secs": uptime_secs(),
        // Monotonic counter bumped once per successful zion.toml
        // hot-reload. Lets the operator confirm a reload landed and
        // see *which* snapshot a given request would currently use.
        "config_generation": crate::reload::current_generation(),
        "platform": {
            "os": platform.os,
            "arch": platform.arch,
            "cores": platform.cpu_cores,
            "ram_mb": platform.ram_mb,
            "tier": platform.tier().label(),
            "tier_score": platform.tier_score(),
            "projected_kreqs_cached": platform.projected_kreqs_cached(),
            "projected_kreqs_dynamic": platform.projected_kreqs_dynamic(),
            // Live calibration: raw AES-128-GCM seal ops/sec/core, in K.
            // None when ZION_BOOT_FAST=1 was set or aws-lc-rs failed.
            "aes_kops_per_core": platform.aes_kops_per_core,
            "aes_kops_total": platform.aes_kops_total(),
            "calibration_us": platform.calibration_us,
            "has_aes_ni": platform.has_aes_ni,
            "has_sha256": platform.has_sha256,
            "has_avx2": platform.has_avx2,
            "has_neon": platform.has_neon,
            "has_so_reuseport": platform.has_so_reuseport,
            "has_tcp_fastopen": platform.has_tcp_fastopen,
            "has_tcp_quickack": platform.has_tcp_quickack,
            "worker_threads": platform.worker_threads,
            "conn_limit": platform.conn_limit,
        },
        "metrics": {
            "requests_total": m.requests_total.load(Relaxed),
            "requests_2xx": m.requests_2xx.load(Relaxed),
            "requests_4xx": m.requests_4xx.load(Relaxed),
            "requests_5xx": m.requests_5xx.load(Relaxed),
            "waf_denied": m.waf_denied.load(Relaxed),
            "waf_shadow_would_block": m.waf_shadow_would_block.load(Relaxed),
            "rate_limited": m.rate_limited.load(Relaxed),
            "cache_hits": m.cache_hits.load(Relaxed),
            "cache_misses": m.cache_misses.load(Relaxed),
            "websocket_upgrades": m.websocket_upgrades.load(Relaxed),
            "active_connections": m.active_connections.load(Relaxed),
            "connections_total": m.connections_total.load(Relaxed),
            "tls_handshake_errors": m.tls_handshake_errors.load(Relaxed),
            "request_p50_us": m.request_duration.quantile_us(0.50),
            "request_p95_us": m.request_duration.quantile_us(0.95),
            "request_p99_us": m.request_duration.quantile_us(0.99),
            "upstream_p50_us": m.upstream_duration.quantile_us(0.50),
            "upstream_p95_us": m.upstream_duration.quantile_us(0.95),
            "upstream_p99_us": m.upstream_duration.quantile_us(0.99),
            "tls_p50_us": m.tls_handshake_duration.quantile_us(0.50),
            "tls_p95_us": m.tls_handshake_duration.quantile_us(0.95),
        },
        "upstreams": upstreams,
    });

    let out = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    bytes::Bytes::from(out)
}

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
        // 1ms falls in bucket[0] (le=0.001) — non-cumulative, only bucket[0] incremented
        assert_eq!(h.buckets[0].load(Relaxed), 1);
        assert_eq!(h.buckets[1].load(Relaxed), 0); // not cumulative
        assert_eq!(h.buckets[16].load(Relaxed), 0); // +Inf only if > 32s
    }

    #[test]
    fn histogram_observe_500ms() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_millis(500));
        assert_eq!(h.count.load(Relaxed), 1);
        // 500ms = 500_000us → bucket bound 512_000us (index 9) — non-cumulative
        assert_eq!(h.buckets[8].load(Relaxed), 0); // le=0.256 → no
        assert_eq!(h.buckets[9].load(Relaxed), 1); // le=0.512 → yes
        assert_eq!(h.buckets[10].load(Relaxed), 0); // not cumulative
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
    fn histogram_differential_multiple() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_millis(1)); // 1000us <= 1000us → bucket 0
        h.observe(Duration::from_millis(10)); // 10000us: 8000 < 10000 <= 16000 → bucket 4
        h.observe(Duration::from_millis(100)); // 100000us: 64000 < 100000 <= 128000 → bucket 7
        assert_eq!(h.count.load(Relaxed), 3);
        // Non-cumulative: each bucket only counts its own range
        assert_eq!(h.buckets[0].load(Relaxed), 1); // 1ms only
        assert_eq!(h.buckets[4].load(Relaxed), 1); // 10ms only
        assert_eq!(h.buckets[7].load(Relaxed), 1); // 100ms only
        assert_eq!(h.buckets[16].load(Relaxed), 0); // no overflow
                                                    // Verify render() produces correct cumulative output
        let mut buf = bytes::BytesMut::new();
        h.render("test", "test", &mut buf);
        let out = String::from_utf8(buf.to_vec()).unwrap();
        // le=0.001 should be 1 (just 1ms)
        assert!(out.contains("test_bucket{le=\"0.001\"} 1"));
        // le=0.016 should be 2 (1ms + 10ms)
        assert!(out.contains("test_bucket{le=\"0.016\"} 2"));
        // le=+Inf should be 3 (all)
        assert!(out.contains("test_bucket{le=\"+Inf\"} 3"));
    }

    #[test]
    fn histogram_render_contains_buckets() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_millis(5));
        let mut buf = bytes::BytesMut::new();
        h.render("test_metric", "A test metric.", &mut buf);
        let out = String::from_utf8(buf.to_vec()).unwrap();
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
        let out_bytes = m.render();
        let out = String::from_utf8(out_bytes.to_vec()).unwrap();
        assert!(out.contains("zion_requests_total 1"));
        assert!(out.contains("zion_active_connections 0"));
        assert!(out.contains("zion_request_duration_seconds_bucket"));
        assert!(out.contains("zion_upstream_duration_seconds_bucket"));
        assert!(out.contains("zion_tls_handshake_duration_seconds_bucket"));
    }
}
