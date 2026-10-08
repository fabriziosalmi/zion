// SPDX-License-Identifier: Apache-2.0
//! Circuit breaker for an upstream (opt-in, `[upstream.<name>] circuit_breaker`).
//!
//! The health prober notices a dead upstream on its own schedule (30 s when healthy);
//! until it does, every request to a failing single-upstream route waits for the origin
//! and then fails. The breaker reacts in-band: it watches the outcomes of real requests
//! over a sliding window and, when the failure rate crosses a threshold, REJECTS requests
//! at once (503 + `Retry-After`) for a cool-down, instead of piling more load on an origin
//! that is struggling and making every client wait for an answer that will be an error.
//!
//! States:
//!   * closed     — traffic flows; outcomes are counted per second over `window_secs`;
//!   * open       — until `open_secs` have passed, every request is rejected;
//!   * half-open  — after the cool-down ONE request is let through as a probe and given a
//!     [`ProbeToken`]; only the outcome reported WITH that token closes the circuit (counters
//!     reset) or re-opens it. Every other request is rejected while the probe is out, and an
//!     outcome without the token (a request admitted before the trip that finishes late, or
//!     an abandoned probe's late answer after a replacement was issued) is ignored. A probe
//!     that never reports back is abandoned after [`PROBE_TIMEOUT_MS`] so the circuit cannot
//!     stick.
//!
//! A failure is a `502`, `503` or `504` (what a refused connection, a timeout or an overloaded
//! origin become); a `500` is the application's own bug on one endpoint, not a sick upstream,
//! and 4xx are the client's. The decision uses the failure *rate* and a minimum number of
//! requests, so a quiet upstream is never tripped by a single error.
//!
//! The state machine takes the time as an argument so it can be tested without sleeping.

use arc_swap::ArcSwapOption;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// Longest window the counters can hold.
pub const MAX_WINDOW_SECS: u32 = crate::config::MAX_BREAKER_WINDOW_SECS;
/// How long a half-open probe may stay out before another request may take its place.
pub const PROBE_TIMEOUT_MS: u64 = 30_000;

/// Milliseconds since the first call in this process (monotonic).
pub fn now_ms() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Thresholds for one upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakerCfg {
    /// Open when at least this percentage of the requests in the window failed.
    pub error_rate_pct: u32,
    /// ...and at least this many requests were seen in it.
    pub min_requests: u32,
    /// Sliding window, in seconds (1..=60).
    pub window_secs: u32,
    /// How long the circuit stays open before a probe is allowed, in seconds.
    pub open_secs: u32,
}

impl From<&crate::config::CircuitBreakerConfig> for BreakerCfg {
    fn from(c: &crate::config::CircuitBreakerConfig) -> Self {
        BreakerCfg {
            error_rate_pct: c.error_rate_pct,
            min_requests: c.min_requests,
            window_secs: c.window_secs,
            open_secs: c.open_secs,
        }
    }
}

/// Proof that a request holds the half-open probe slot; hand it back with the outcome.
#[derive(Debug, PartialEq, Eq)]
pub struct ProbeToken(u64);

/// What `check` decided for a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    /// Closed (or no breaker configured): send it.
    Allow,
    /// Half-open: this request is the probe; report its outcome with this token.
    Probe(ProbeToken),
    /// Open: answer 503 now; try again in about this long.
    Reject { retry_after_ms: u64 },
}

#[derive(Default)]
struct Bucket {
    epoch_s: AtomicU64,
    ok: AtomicU32,
    fail: AtomicU32,
}

pub struct Breaker {
    cfg: ArcSwapOption<BreakerCfg>,
    buckets: [Bucket; MAX_WINDOW_SECS as usize],
    /// 0 = closed; otherwise the time (ms) the cool-down ends.
    open_until_ms: AtomicU64,
    /// 0 = no probe out; otherwise the time (ms) the outstanding probe is given up on.
    probe_deadline_ms: AtomicU64,
    /// Id of the probe currently holding the slot (0 = none) and the id counter.
    probe_owner: AtomicU64,
    probe_ids: AtomicU64,
    trips: AtomicU64,
    rejected: AtomicU64,
}

impl Default for Breaker {
    fn default() -> Self {
        Self::new()
    }
}

impl Breaker {
    pub fn new() -> Self {
        Self {
            cfg: ArcSwapOption::empty(),
            buckets: std::array::from_fn(|_| Bucket::default()),
            open_until_ms: AtomicU64::new(0),
            probe_deadline_ms: AtomicU64::new(0),
            probe_owner: AtomicU64::new(0),
            probe_ids: AtomicU64::new(0),
            trips: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    /// Apply (or remove) the thresholds. Used at build time and again on a reload, since the
    /// health entry (and so this breaker, with its history) survives a reload.
    pub fn configure(&self, cfg: Option<BreakerCfg>) {
        let changed = self.cfg.load().as_deref() != cfg.as_ref();
        self.cfg.store(cfg.map(Arc::new));
        if changed {
            self.reset();
        }
    }

    pub fn is_configured(&self) -> bool {
        self.cfg.load().is_some()
    }

    /// The thresholds currently applied.
    pub fn cfg(&self) -> Option<BreakerCfg> {
        self.cfg.load().as_deref().cloned()
    }

    fn reset(&self) {
        self.open_until_ms.store(0, Relaxed);
        self.probe_deadline_ms.store(0, Relaxed);
        self.probe_owner.store(0, Relaxed);
        for b in &self.buckets {
            b.epoch_s.store(0, Relaxed);
            b.ok.store(0, Relaxed);
            b.fail.store(0, Relaxed);
        }
    }

    /// Decide for one request at `now_ms`.
    pub fn check(&self, now_ms: u64) -> Check {
        if self.cfg.load().is_none() {
            return Check::Allow;
        }
        let until = self.open_until_ms.load(Relaxed);
        if until == 0 {
            return Check::Allow;
        }
        if now_ms < until {
            self.rejected.fetch_add(1, Relaxed);
            return Check::Reject {
                retry_after_ms: until - now_ms,
            };
        }
        // Cool-down over: half-open. One request takes the probe slot.
        let deadline = self.probe_deadline_ms.load(Relaxed);
        if now_ms >= deadline
            && self
                .probe_deadline_ms
                .compare_exchange(deadline, now_ms + PROBE_TIMEOUT_MS, Relaxed, Relaxed)
                .is_ok()
        {
            let id = self.probe_ids.fetch_add(1, Relaxed) + 1;
            self.probe_owner.store(id, Relaxed);
            return Check::Probe(ProbeToken(id));
        }
        self.rejected.fetch_add(1, Relaxed);
        Check::Reject {
            retry_after_ms: 1000,
        }
    }

    /// Record the outcome of a request that was let through. `probe` is the token `check`
    /// handed to this request if it was the half-open probe, `None` otherwise.
    pub fn record(&self, ok: bool, now_ms: u64, probe: Option<ProbeToken>) {
        let guard = self.cfg.load();
        let Some(cfg) = guard.as_deref() else { return };
        if self.open_until_ms.load(Relaxed) != 0 {
            // Open or half-open. Only the probe's own outcome means anything: take its slot
            // (so it counts once) and resolve the circuit. Everything else — a request
            // admitted before the trip finishing late, a replaced probe answering late — is
            // ignored.
            let Some(ProbeToken(id)) = probe else { return };
            if self
                .probe_owner
                .compare_exchange(id, 0, Relaxed, Relaxed)
                .is_err()
            {
                return;
            }
            if ok {
                self.reset(); // closed again, with a clean slate
            } else {
                self.open_until_ms
                    .store(now_ms + u64::from(cfg.open_secs) * 1000, Relaxed);
                self.probe_deadline_ms.store(0, Relaxed);
                self.trips.fetch_add(1, Relaxed);
            }
            return;
        }
        let sec = now_ms / 1000;
        let window = u64::from(cfg.window_secs.clamp(1, MAX_WINDOW_SECS));
        let b = &self.buckets[(sec % u64::from(MAX_WINDOW_SECS)) as usize];
        if b.epoch_s.swap(sec, Relaxed) != sec {
            b.ok.store(0, Relaxed);
            b.fail.store(0, Relaxed);
        }
        if ok {
            b.ok.fetch_add(1, Relaxed);
            return;
        }
        b.fail.fetch_add(1, Relaxed);
        // evaluate on failures only: the happy path stays two atomics
        let (mut total, mut fail) = (0u64, 0u64);
        for bk in &self.buckets {
            let e = bk.epoch_s.load(Relaxed);
            if e + window > sec && e <= sec {
                let (o, f) = (
                    u64::from(bk.ok.load(Relaxed)),
                    u64::from(bk.fail.load(Relaxed)),
                );
                total += o + f;
                fail += f;
            }
        }
        if total >= u64::from(cfg.min_requests)
            && fail * 100 >= u64::from(cfg.error_rate_pct) * total
        {
            self.open_until_ms
                .store(now_ms + u64::from(cfg.open_secs) * 1000, Relaxed);
            self.probe_deadline_ms.store(0, Relaxed);
            self.probe_owner.store(0, Relaxed);
            self.trips.fetch_add(1, Relaxed);
        }
    }

    /// True while the circuit is open or half-open (the `zion_upstream_circuit_open` gauge).
    pub fn is_open(&self) -> bool {
        self.cfg.load().is_some() && self.open_until_ms.load(Relaxed) != 0
    }

    pub fn trips(&self) -> u64 {
        self.trips.load(Relaxed)
    }

    pub fn rejected(&self) -> u64 {
        self.rejected.load(Relaxed)
    }
}

/// Is `status` a failure for the breaker's purposes?
pub fn is_failure(status: u16) -> bool {
    matches!(status, 502..=504)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BreakerCfg {
        BreakerCfg {
            error_rate_pct: 50,
            min_requests: 10,
            window_secs: 10,
            open_secs: 30,
        }
    }

    fn breaker() -> Breaker {
        let b = Breaker::new();
        b.configure(Some(cfg()));
        b
    }

    /// `n_ok` successes then `n_fail` failures, all within the same second at `t_ms`.
    fn feed(b: &Breaker, t_ms: u64, n_ok: u32, n_fail: u32) {
        for _ in 0..n_ok {
            b.record(true, t_ms, None);
        }
        for _ in 0..n_fail {
            b.record(false, t_ms, None);
        }
    }

    #[test]
    fn an_unconfigured_breaker_never_interferes() {
        let b = Breaker::new();
        feed(&b, 1000, 0, 1000);
        assert_eq!(b.check(1000), Check::Allow);
        assert!(!b.is_open() && b.trips() == 0);
    }

    #[test]
    fn it_opens_at_the_threshold_and_not_before() {
        let b = breaker();
        feed(&b, 1_000, 0, 9); // 100% failing but only 9 requests: below min_requests
        assert_eq!(b.check(1_000), Check::Allow);
        feed(&b, 1_000, 0, 1); // the 10th request: now it counts
        assert!(b.is_open());
        assert_eq!(
            b.check(1_000),
            Check::Reject {
                retry_after_ms: 30_000
            }
        );
        assert_eq!(b.trips(), 1);
    }

    #[test]
    fn the_rate_matters_not_the_count() {
        let b = breaker();
        feed(&b, 1_000, 60, 4); // 4 / 64 = 6% failures: healthy
        assert_eq!(b.check(1_000), Check::Allow);
        let b = breaker();
        feed(&b, 1_000, 5, 5); // 50% of 10: at the threshold
        assert!(b.is_open());
        let b = breaker();
        feed(&b, 1_000, 6, 4); // 40% of 10: below it
        assert!(!b.is_open());
    }

    #[test]
    fn old_outcomes_slide_out_of_the_window() {
        let b = breaker();
        feed(&b, 1_000, 0, 9); // second 1
                               // 12 s later (window is 10 s) the 9 failures no longer count
        feed(&b, 13_000, 0, 1);
        assert!(
            !b.is_open(),
            "one failure in a fresh window is not an outbreak"
        );
        // but failures spread over the last ten seconds still add up
        let b = breaker();
        for s in 1..=9u64 {
            b.record(false, s * 1000, None);
        }
        b.record(false, 9_999, None);
        assert!(
            b.is_open(),
            "10 failures over 9 seconds, all inside one 10 s window"
        );
    }

    fn probe(b: &Breaker, now: u64) -> ProbeToken {
        match b.check(now) {
            Check::Probe(t) => t,
            other => panic!("expected a probe at {now}, got {other:?}"),
        }
    }

    #[test]
    fn half_open_lets_exactly_one_probe_through_and_its_success_closes() {
        let b = breaker();
        feed(&b, 1_000, 0, 10);
        assert!(
            matches!(b.check(20_000), Check::Reject { .. }),
            "still cooling down"
        );
        let t = probe(&b, 31_000); // cool-down over at 31 000
        assert!(
            matches!(b.check(31_001), Check::Reject { .. }),
            "only one probe at a time"
        );
        assert!(matches!(b.check(31_500), Check::Reject { .. }));
        b.record(true, 31_700, Some(t));
        assert!(!b.is_open());
        assert_eq!(b.check(31_800), Check::Allow);
        // a clean slate: the old failures are forgotten
        feed(&b, 32_000, 0, 9);
        assert!(!b.is_open());
    }

    #[test]
    fn a_failed_probe_reopens_for_a_full_cool_down() {
        let b = breaker();
        feed(&b, 1_000, 0, 10);
        let t = probe(&b, 31_000);
        b.record(false, 31_200, Some(t));
        assert!(b.is_open());
        assert_eq!(
            b.check(31_300),
            Check::Reject {
                retry_after_ms: 29_900
            }
        );
        assert_eq!(b.trips(), 2);
        // and the next probe comes after the new cool-down
        probe(&b, 61_300);
    }

    #[test]
    fn a_probe_that_never_reports_back_does_not_stick_the_circuit() {
        let b = breaker();
        feed(&b, 1_000, 0, 10);
        let _lost = probe(&b, 31_000);
        assert!(matches!(b.check(40_000), Check::Reject { .. }));
        // PROBE_TIMEOUT_MS later another request may try
        probe(&b, 31_000 + PROBE_TIMEOUT_MS);
    }

    #[test]
    fn only_the_probe_that_holds_the_slot_can_resolve_the_circuit() {
        // a request admitted before the trip that finishes after the cool-down is not the probe
        let b = breaker();
        feed(&b, 1_000, 0, 10);
        b.record(true, 1_500, None);
        assert!(
            b.is_open(),
            "an in-flight success during the cool-down changes nothing"
        );
        b.record(true, 40_000, None);
        assert!(
            b.is_open(),
            "...nor does one that finishes after it: it holds no token"
        );
        b.record(false, 40_000, None);
        assert_eq!(
            b.trips(),
            1,
            "...and a late failure does not re-open or re-count"
        );

        // an abandoned probe answering late, after a replacement was issued, is ignored
        let b = breaker();
        feed(&b, 1_000, 0, 10);
        let old = probe(&b, 31_000);
        let new = probe(&b, 31_000 + PROBE_TIMEOUT_MS); // the old one was given up on
        b.record(true, 61_100, Some(old));
        assert!(
            b.is_open(),
            "the replaced probe's late success must not close the circuit"
        );
        b.record(true, 61_200, Some(new));
        assert!(!b.is_open(), "the current probe's outcome does");

        // a token resolves the circuit once only
        let b = breaker();
        feed(&b, 1_000, 0, 10);
        let t = probe(&b, 31_000);
        let t2 = ProbeToken(t.0);
        b.record(false, 31_100, Some(t));
        assert_eq!(b.trips(), 2);
        b.record(false, 31_200, Some(t2));
        assert_eq!(
            b.trips(),
            2,
            "a second report with the same token counts for nothing"
        );
    }

    #[test]
    fn only_502_503_504_count_as_failures() {
        for s in [200u16, 204, 301, 400, 401, 403, 404, 429, 500, 501] {
            assert!(!is_failure(s), "{s}");
        }
        for s in [502u16, 503, 504] {
            assert!(is_failure(s), "{s}");
        }
    }

    #[test]
    fn reconfiguring_resets_history_but_the_same_config_does_not() {
        let b = breaker();
        feed(&b, 1_000, 0, 9);
        b.configure(Some(cfg())); // a reload with unchanged thresholds
        feed(&b, 1_000, 0, 1);
        assert!(b.is_open(), "history survived an unchanged reload");
        let mut other = cfg();
        other.open_secs = 5;
        b.configure(Some(other));
        assert!(!b.is_open(), "new thresholds start clean");
        b.configure(None);
        feed(&b, 2_000, 0, 100);
        assert!(
            !b.is_open() && b.check(2_000) == Check::Allow,
            "removed: off"
        );
    }
}
