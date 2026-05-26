// SPDX-License-Identifier: Apache-2.0
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
///
/// **Exemplars (OpenMetrics).** Each bucket optionally carries the *latest*
/// observation seen as an OpenMetrics exemplar — the trace ID, the observed
/// value, and the wall-clock timestamp. Stored as a `[AtomicU64; 4]` per
/// bucket: `[trace_id_hi, trace_id_lo, value_us, ts_ms]`. A zero trace_id
/// means "no exemplar" and the renderer omits the line.
///
/// We update *unconditionally* on each observe, not at a sample rate — the
/// cost is 4 relaxed stores (already cache-warm from the bucket increment),
/// and overwriting always-keeps-latest is exactly the OpenMetrics
/// recommended behaviour for "the most recent slow request" use case.
pub struct LatencyHistogram {
    /// 16 non-cumulative (differential) buckets + overflow.
    /// Each bucket stores only the count for that exact range.
    /// Cumulative sums are computed in render() (1x/sec, not 200K/sec).
    /// This reduces observe() from 17 atomics to 3.
    buckets: [AtomicU64; 17],
    /// Per-bucket latest exemplar.
    ///   [trace_id_hi, trace_id_lo, value_us, ts_ms]
    /// trace_id_hi == 0 && trace_id_lo == 0  ⇒  no exemplar.
    exemplars: [[AtomicU64; 4]; 17],
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
        // Both arrays are length 17. Rust does not yet const-init [T; N] from
        // a closure, but `[const { ... }; 17]` works for AtomicU64.
        Self {
            buckets: [const { AtomicU64::new(0) }; 17],
            exemplars: [const {
                [
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                ]
            }; 17],
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
        self.observe_inner(duration, None);
    }

    /// Record an observation and bind it to an OpenMetrics exemplar (the
    /// 16-byte trace ID of the request that produced it). The bucket the
    /// observation falls into stores the trace ID + value + wall-clock
    /// timestamp, atomically overwriting whatever was there before. Exposed
    /// at scrape time as `# {trace_id="..."} value timestamp`.
    ///
    /// Always-write (vs sampled) is intentional: the marginal cost is 4
    /// relaxed stores already on a cache line we just touched, and
    /// "latest slow request per bucket" is the workflow this is built for.
    #[inline]
    pub fn observe_with_trace(&self, duration: Duration, trace_id: [u8; 16]) {
        // Treat all-zero trace ID as "no exemplar available" so we don't
        // emit garbage when the trace context is invalid/missing.
        let opt = if trace_id.iter().all(|&b| b == 0) {
            None
        } else {
            Some(trace_id)
        };
        self.observe_inner(duration, opt);
    }

    #[inline]
    fn observe_inner(&self, duration: Duration, trace_id: Option<[u8; 16]>) {
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

        if let Some(tid) = trace_id {
            // Pack the 16-byte trace ID into two u64s (big-endian — matches
            // the on-the-wire hex serialization order).
            let hi = u64::from_be_bytes([
                tid[0], tid[1], tid[2], tid[3], tid[4], tid[5], tid[6], tid[7],
            ]);
            let lo = u64::from_be_bytes([
                tid[8], tid[9], tid[10], tid[11], tid[12], tid[13], tid[14], tid[15],
            ]);
            let ts_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            // Order matters for readers: write trace_id atoms first, value
            // and ts last. A scraper racing with a writer can at worst
            // observe a stale (trace, value, ts) triple, never a torn ID.
            // We accept the unlikely race — exemplars are observability,
            // not invariants.
            let slot = &self.exemplars[idx];
            slot[0].store(hi, Relaxed);
            slot[1].store(lo, Relaxed);
            slot[2].store(us, Relaxed);
            slot[3].store(ts_ms, Relaxed);
        }
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
            // OpenMetrics exemplar: only emit when the slot is populated.
            // The trailing newline goes after the optional exemplar so a
            // single bucket line is one logical record.
            self.render_exemplar(i, &mut itoa_buf, &mut ryu_buf, out);
            out.extend_from_slice(b"\n");
        }

        cumulative += self.buckets[16].load(Relaxed);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"_bucket{le=\"+Inf\"} ");
        out.extend_from_slice(itoa_buf.format(cumulative).as_bytes());
        self.render_exemplar(16, &mut itoa_buf, &mut ryu_buf, out);
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

    /// Append the OpenMetrics exemplar suffix for `bucket_idx`, or nothing
    /// if the slot is empty. Format (without leading space):
    ///   `# {trace_id="<hex>"} <value_seconds> <unix_seconds_with_ms>`
    /// per OpenMetrics §3.3 "Exemplars".
    fn render_exemplar(
        &self,
        bucket_idx: usize,
        itoa_buf: &mut itoa::Buffer,
        ryu_buf: &mut ryu::Buffer,
        out: &mut bytes::BytesMut,
    ) {
        let slot = &self.exemplars[bucket_idx];
        let hi = slot[0].load(Relaxed);
        let lo = slot[1].load(Relaxed);
        if hi == 0 && lo == 0 {
            return; // no exemplar recorded
        }
        let value_us = slot[2].load(Relaxed);
        let ts_ms = slot[3].load(Relaxed);

        // Render trace_id as 32 lowercase hex digits.
        out.extend_from_slice(b" # {trace_id=\"");
        let mut hex = [0u8; 32];
        write_hex_u64_be(hi, &mut hex[0..16]);
        write_hex_u64_be(lo, &mut hex[16..32]);
        out.extend_from_slice(&hex);
        out.extend_from_slice(b"\"} ");
        // Value in seconds (ryu always emits a finite f64).
        out.extend_from_slice(ryu_buf.format(value_us as f64 / 1_000_000.0).as_bytes());
        out.extend_from_slice(b" ");
        // Unix timestamp in seconds with millisecond precision.
        // OpenMetrics expects a single decimal number — render as integer.fractional.
        let secs = ts_ms / 1_000;
        let ms = ts_ms % 1_000;
        out.extend_from_slice(itoa_buf.format(secs).as_bytes());
        out.extend_from_slice(b".");
        // Pad to 3 digits.
        if ms < 10 {
            out.extend_from_slice(b"00");
        } else if ms < 100 {
            out.extend_from_slice(b"0");
        }
        out.extend_from_slice(itoa_buf.format(ms).as_bytes());
    }
}

/// Render a `u64` as 16 lowercase hex chars (big-endian). Caller-owned
/// buffer; `dst.len() == 16` is the invariant.
#[inline]
fn write_hex_u64_be(v: u64, dst: &mut [u8]) {
    debug_assert_eq!(dst.len(), 16);
    const LUT: &[u8; 16] = b"0123456789abcdef";
    for i in 0..8 {
        let b = (v >> (56 - i * 8)) as u8;
        dst[i * 2] = LUT[(b >> 4) as usize];
        dst[i * 2 + 1] = LUT[(b & 0x0F) as usize];
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

    // ── Mesh observability (issue #69) ──────────────────────────────
    // Always-on counters (zero on builds without `--features
    // sovereign-aimp`, so operators can grep for the same metric name
    // regardless of which build their distro produced).
    /// Successful local emits — bumped in `aimp_cp::publish_block`.
    pub mesh_claims_emitted: AtomicU64,
    /// Inbound envelopes that *passed* the merge policy gates.
    pub mesh_claims_received: AtomicU64,
    /// Inbound envelopes rejected on signature verification.
    pub mesh_claims_dropped_signature: AtomicU64,
    /// Inbound envelopes rejected as duplicates (seen-sig replay filter).
    pub mesh_claims_dropped_replay: AtomicU64,
    /// Inbound envelopes rejected for other reasons (ts skew,
    /// malformed, revocation by non-original source). Generic bucket
    /// — `cargo run --release -- doctor` exposes a finer split.
    pub mesh_claims_dropped_other: AtomicU64,
    /// Inbound envelopes dropped by the per-source rate-cap (#71). A
    /// flooding source trips this before signature verification.
    pub mesh_claims_dropped_rate: AtomicU64,
    /// Dispatcher hits that found a mesh score for the client IP.
    pub mesh_score_lookups: AtomicU64,
    /// Total bytes received on the gossip socket (decoded or not).
    pub mesh_gossip_bytes_in: AtomicU64,
    /// Total bytes sent on the gossip socket.
    pub mesh_gossip_bytes_out: AtomicU64,

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
            mesh_claims_emitted: AtomicU64::new(0),
            mesh_claims_received: AtomicU64::new(0),
            mesh_claims_dropped_signature: AtomicU64::new(0),
            mesh_claims_dropped_replay: AtomicU64::new(0),
            mesh_claims_dropped_other: AtomicU64::new(0),
            mesh_claims_dropped_rate: AtomicU64::new(0),
            mesh_score_lookups: AtomicU64::new(0),
            mesh_gossip_bytes_in: AtomicU64::new(0),
            mesh_gossip_bytes_out: AtomicU64::new(0),
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

        // ── Mesh observability (issue #69) ──
        // Always rendered so operators can `grep zion_mesh_` regardless
        // of build features. Counters are zero on builds without
        // `--features sovereign-aimp` — same posture as the WAF
        // counters on routes that don't have a WAF profile.
        out.extend_from_slice(
            b"# HELP zion_mesh_claims_emitted_total Mesh claims published from this node.\n\
                                # TYPE zion_mesh_claims_emitted_total counter\n\
                                zion_mesh_claims_emitted_total ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_claims_emitted.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_mesh_claims_received_total Mesh claims received and merged into local state.\n\
                                # TYPE zion_mesh_claims_received_total counter\n\
                                zion_mesh_claims_received_total ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_claims_received.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_mesh_claims_dropped_total Inbound mesh envelopes rejected, by reason.\n\
                                # TYPE zion_mesh_claims_dropped_total counter\nzion_mesh_claims_dropped_total{reason=\"signature\"} ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_claims_dropped_signature.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\nzion_mesh_claims_dropped_total{reason=\"replay\"} ");
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_claims_dropped_replay.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\nzion_mesh_claims_dropped_total{reason=\"other\"} ");
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_claims_dropped_other.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\nzion_mesh_claims_dropped_total{reason=\"rate\"} ");
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_claims_dropped_rate.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_mesh_score_lookups_total Dispatcher hits that found a mesh score for the client IP.\n\
                                # TYPE zion_mesh_score_lookups_total counter\n\
                                zion_mesh_score_lookups_total ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_score_lookups.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_mesh_gossip_bytes_in_total Total bytes received on the gossip socket.\n\
                                # TYPE zion_mesh_gossip_bytes_in_total counter\n\
                                zion_mesh_gossip_bytes_in_total ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_gossip_bytes_in.load(Relaxed))
                .as_bytes(),
        );
        out.extend_from_slice(b"\n");

        out.extend_from_slice(
            b"# HELP zion_mesh_gossip_bytes_out_total Total bytes sent on the gossip socket.\n\
                                # TYPE zion_mesh_gossip_bytes_out_total counter\n\
                                zion_mesh_gossip_bytes_out_total ",
        );
        out.extend_from_slice(
            itoa_buf
                .format(self.mesh_gossip_bytes_out.load(Relaxed))
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

        // Observability counters (panics, audit events, trace stats) live
        // in their own module to avoid coupling the metrics renderer to
        // tracing internals.
        crate::observability::render_counters(&mut out);

        // Sovereign per-class classification counters (Track D — replaces
        // the previous per-request `format!` call site in dispatch.rs).
        // Only rendered when the feature is compiled in.
        #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
        {
            out.extend_from_slice(
                b"# HELP zion_sovereign_classifications_total Per-class IP \
classifications since process start.\n# TYPE zion_sovereign_classifications_total counter\n",
            );
            for (label, count) in crate::sovereign::classification_counts() {
                out.extend_from_slice(b"zion_sovereign_classifications_total{class=\"");
                out.extend_from_slice(label.as_bytes());
                out.extend_from_slice(b"\"} ");
                out.extend_from_slice(itoa_buf.format(count).as_bytes());
                out.extend_from_slice(b"\n");
            }
        }

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
            // NUMA topology — 1 unless built with `--features numa-aware`
            // on a multi-socket Linux box (issue #50).
            "numa_nodes": platform.numa_nodes,
            // Whether the running kernel supports io_uring rw surface
            // (≥ 5.19). Independent of build features — even non-Linux
            // hosts surface this, always as `false`. (issue #51)
            "has_io_uring_rw_kernel": platform.has_io_uring_rw_kernel,
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
            assert_eq!(h.buckets[i].load(Relaxed), 0, "bucket {i} should be 0");
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
    fn exemplar_emitted_when_observed_with_trace() {
        let h = LatencyHistogram::new();
        let trace_id = [
            0x0a, 0xf7, 0x65, 0x19, 0x16, 0xcd, 0x43, 0xdd, 0x84, 0x48, 0xeb, 0x21, 0x1c, 0x80,
            0x31, 0x9c,
        ];
        h.observe_with_trace(Duration::from_micros(1500), trace_id);
        let mut buf = bytes::BytesMut::new();
        h.render("xm", "exemplar test", &mut buf);
        let out = String::from_utf8(buf.to_vec()).unwrap();
        // The 1.5ms observation lands in the le="0.002" bucket.
        // OpenMetrics format: bucket value + " # {trace_id=\"…\"} <s> <ts>".
        assert!(
            out.contains(r#"# {trace_id="0af7651916cd43dd8448eb211c80319c"}"#),
            "expected exemplar with hex-encoded trace ID, got:\n{out}"
        );
    }

    #[test]
    fn exemplar_omitted_when_no_trace_provided() {
        let h = LatencyHistogram::new();
        h.observe(Duration::from_millis(5));
        let mut buf = bytes::BytesMut::new();
        h.render("xm", "no exemplar test", &mut buf);
        let out = String::from_utf8(buf.to_vec()).unwrap();
        assert!(
            !out.contains("trace_id="),
            "rendered no-exemplar bucket should not contain trace_id, got:\n{out}"
        );
    }

    #[test]
    fn exemplar_zero_trace_id_treated_as_none() {
        let h = LatencyHistogram::new();
        h.observe_with_trace(Duration::from_millis(5), [0u8; 16]);
        let mut buf = bytes::BytesMut::new();
        h.render("xm", "zero trace test", &mut buf);
        let out = String::from_utf8(buf.to_vec()).unwrap();
        assert!(
            !out.contains("trace_id="),
            "all-zero trace ID is invalid per W3C; must not be emitted as exemplar"
        );
    }

    #[test]
    fn exemplar_overwrites_with_latest() {
        let h = LatencyHistogram::new();
        let mut tid_a = [0u8; 16];
        tid_a[0] = 0xaa;
        let mut tid_b = [0u8; 16];
        tid_b[0] = 0xbb;
        h.observe_with_trace(Duration::from_micros(1500), tid_a);
        h.observe_with_trace(Duration::from_micros(1500), tid_b); // same bucket
        let mut buf = bytes::BytesMut::new();
        h.render("xm", "overwrite test", &mut buf);
        let out = String::from_utf8(buf.to_vec()).unwrap();
        assert!(
            out.contains("trace_id=\"bb"),
            "newer exemplar must overwrite older one in the same bucket, got:\n{out}"
        );
        assert!(!out.contains("trace_id=\"aa"));
    }

    #[test]
    fn exemplar_hex_lowercase_only() {
        let h = LatencyHistogram::new();
        let trace_id = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        h.observe_with_trace(Duration::from_micros(1500), trace_id);
        let mut buf = bytes::BytesMut::new();
        h.render("xm", "lowercase test", &mut buf);
        let out = String::from_utf8(buf.to_vec()).unwrap();
        assert!(out.contains(r#"trace_id="ffeeddccbbaa99887766554433221100""#));
        // Sanity: no uppercase hex letters anywhere in the trace_id label.
        let trace_section = &out[out.find("trace_id=\"").unwrap()..];
        let end = trace_section.find('"').unwrap()
            + 1
            + trace_section[trace_section.find('"').unwrap() + 1..]
                .find('"')
                .unwrap();
        let label = &trace_section[..=end];
        for c in "ABCDEF".chars() {
            assert!(!label.contains(c), "uppercase hex in {label}");
        }
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
