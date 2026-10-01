// SPDX-License-Identifier: Apache-2.0
//! Load balancing and passive health for a multi-endpoint upstream pool.
//!
//! Two things the 30-second active prober cannot do:
//!
//! 1. **Choose a member by what real traffic shows.** The prober's latency is refreshed every
//!    30 s and the old rule ("lowest probe latency") sends everything to whichever member was
//!    fastest half a minute ago, then flips all at once: herding. [`pick`] uses *power of two
//!    choices*: take two random members and send the request to the one with the lower
//!    `(in_flight + 1) × peak_ewma_latency`, where the latency is measured on real requests and
//!    reacts to a spike at once (peak EWMA) but forgets it slowly. That spreads load in
//!    proportion to speed, never piles on a member that is already busy, and needs no
//!    coordination beyond two atomic loads.
//! 2. **Eject a member that is failing in-band** (outlier detection). A member whose failure
//!    rate (502/503/504 or a transport error) over a sliding window is at or above a threshold,
//!    and is an outlier against the rest of the pool, is taken out of rotation for a cool-down
//!    that grows with consecutive ejections. It is never done to the whole pool (a pool-wide
//!    outage is not an outlier, and removing every member helps nobody) and a cap bounds how many
//!    members can be out at once.
//!
//! Everything takes the time as an argument, so it is tested without sleeping.

use crate::health::HealthMap;
use arc_swap::ArcSwapOption;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

const WINDOW_SLOTS: usize = 60;

/// Passive health settings for one pool (`[upstream.x] outlier_detection`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutlierCfg {
    /// Eject a member when at least this percentage of its requests in the window failed.
    pub error_rate_pct: u32,
    /// ...and it saw at least this many requests in it.
    pub min_requests: u32,
    /// Sliding window, seconds (1..=60).
    pub window_secs: u32,
    /// Base ejection time, seconds; multiplied by the member's consecutive ejections (max ×10).
    pub eject_secs: u32,
    /// Never have more than this percentage of the pool ejected at once (1..=100).
    pub max_ejected_pct: u32,
}

/// How a request is assigned to a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// Power of two choices on in-flight × peak-EWMA latency (default).
    #[default]
    P2c,
    /// The previous behaviour: the member with the lowest probe latency.
    LowestLatency,
}

#[derive(Default)]
struct Slot {
    epoch_s: AtomicU64,
    ok: AtomicU32,
    fail: AtomicU32,
}

/// Live state of one member, kept next to its health entry.
pub struct MemberStats {
    /// Requests currently waiting for this member's response headers.
    inflight: AtomicU32,
    /// Peak-EWMA of the time to response headers, microseconds (0 = no sample yet).
    ewma_us: AtomicU64,
    slots: [Slot; WINDOW_SLOTS],
    /// 0 = in rotation; otherwise the time (ms) the ejection ends.
    ejected_until_ms: AtomicU64,
    consecutive_ejections: AtomicU32,
    ejections: AtomicU64,
    outlier: ArcSwapOption<OutlierCfg>,
    /// Set for members of a pool of two or more (the only ones these metrics describe).
    pool_member: std::sync::atomic::AtomicBool,
}

impl Default for MemberStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Peak-EWMA decay per sample: a spike is adopted at once, a recovery is averaged in at this
/// weight, so one fast response does not erase the memory of a slow period.
const EWMA_DECAY_NUM: u64 = 7;
const EWMA_DECAY_DEN: u64 = 8;
/// Latency assumed for a member with no sample yet: small, so a new member gets traffic.
const UNKNOWN_LATENCY_US: u64 = 1_000;

impl MemberStats {
    pub fn new() -> Self {
        Self {
            inflight: AtomicU32::new(0),
            ewma_us: AtomicU64::new(0),
            slots: std::array::from_fn(|_| Slot::default()),
            ejected_until_ms: AtomicU64::new(0),
            consecutive_ejections: AtomicU32::new(0),
            ejections: AtomicU64::new(0),
            outlier: ArcSwapOption::empty(),
            pool_member: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn set_pool_member(&self, yes: bool) {
        self.pool_member.store(yes, Relaxed);
    }

    pub fn is_pool_member(&self) -> bool {
        self.pool_member.load(Relaxed)
    }

    /// Apply (or remove) outlier detection; re-applied on every reload.
    pub fn configure_outlier(&self, cfg: Option<OutlierCfg>) {
        let changed = self.outlier.load().as_deref() != cfg.as_ref();
        self.outlier.store(cfg.map(Arc::new));
        if changed {
            self.ejected_until_ms.store(0, Relaxed);
            self.consecutive_ejections.store(0, Relaxed);
            for s in &self.slots {
                s.epoch_s.store(0, Relaxed);
                s.ok.store(0, Relaxed);
                s.fail.store(0, Relaxed);
            }
        }
    }

    pub fn outlier_cfg(&self) -> Option<OutlierCfg> {
        self.outlier.load().as_deref().cloned()
    }

    /// A request is now waiting on this member; dropping the guard says it is no longer.
    pub fn begin(&self) -> InFlight<'_> {
        self.inflight.fetch_add(1, Relaxed);
        InFlight(self)
    }

    pub fn inflight(&self) -> u32 {
        self.inflight.load(Relaxed)
    }

    pub fn ewma_us(&self) -> u64 {
        self.ewma_us.load(Relaxed)
    }

    pub fn ejections(&self) -> u64 {
        self.ejections.load(Relaxed)
    }

    pub fn is_ejected(&self, now_ms: u64) -> bool {
        let until = self.ejected_until_ms.load(Relaxed);
        until != 0 && now_ms < until
    }

    /// Fold one response-header latency into the peak EWMA.
    pub fn observe_latency(&self, sample_us: u64) {
        let sample = sample_us.max(1);
        let mut cur = self.ewma_us.load(Relaxed);
        loop {
            let next = if cur == 0 || sample >= cur {
                sample // first sample, or a spike: adopt immediately
            } else {
                (cur * EWMA_DECAY_NUM + sample) / EWMA_DECAY_DEN
            };
            match self
                .ewma_us
                .compare_exchange_weak(cur, next, Relaxed, Relaxed)
            {
                Ok(_) => return,
                Err(seen) => cur = seen,
            }
        }
    }

    /// The load score used by [`pick`]: lower is better. Falls back to the probe latency
    /// (`probe_us`) until real traffic has produced a sample.
    pub fn score(&self, probe_us: u64) -> u64 {
        let lat = match self.ewma_us.load(Relaxed) {
            0 if probe_us > 0 => probe_us,
            0 => UNKNOWN_LATENCY_US,
            v => v,
        };
        (u64::from(self.inflight.load(Relaxed)) + 1).saturating_mul(lat)
    }

    /// Record one request's outcome in the failure window.
    fn record_outcome(&self, ok: bool, now_ms: u64, window: u64) {
        let sec = now_ms / 1000;
        let s = &self.slots[(sec % WINDOW_SLOTS as u64) as usize];
        if s.epoch_s.swap(sec, Relaxed) != sec {
            s.ok.store(0, Relaxed);
            s.fail.store(0, Relaxed);
        }
        let _ = window;
        if ok {
            s.ok.fetch_add(1, Relaxed);
        } else {
            s.fail.fetch_add(1, Relaxed);
        }
    }

    /// (requests, failures) in the last `window` seconds.
    fn window_totals(&self, now_ms: u64, window: u64) -> (u64, u64) {
        let sec = now_ms / 1000;
        let (mut total, mut fail) = (0u64, 0u64);
        for s in &self.slots {
            let e = s.epoch_s.load(Relaxed);
            if e + window > sec && e <= sec {
                let (o, f) = (
                    u64::from(s.ok.load(Relaxed)),
                    u64::from(s.fail.load(Relaxed)),
                );
                total += o + f;
                fail += f;
            }
        }
        (total, fail)
    }
}

/// Guard returned by [`MemberStats::begin`].
pub struct InFlight<'a>(&'a MemberStats);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Relaxed);
    }
}

/// Probe latency at or above which a healthy member is treated as a gray failure.
const GRAY_FAILURE_US: u64 = 2_000_000;

/// Choose a member of `urls` for one request. `rand(n)` returns a uniform index below `n`.
/// `None` only when there is no member at all or every member is down.
pub fn pick<'a>(
    health: &HealthMap,
    urls: &'a [String],
    algorithm: Algorithm,
    now_ms: u64,
    rand: &mut dyn FnMut(usize) -> usize,
) -> Option<&'a String> {
    // Tiers, best first: (healthy, not gray, not ejected) → (healthy, not ejected) →
    // (healthy). The last tier is a panic mode: ejecting must never be what returns a 503.
    let eligible = |tier: u8| -> Vec<&'a String> {
        urls.iter()
            .filter(|u| match health.get(u.as_str()) {
                None => true, // untracked: optimistic
                Some(h) => {
                    h.healthy.load(Relaxed)
                        && (tier >= 2 || !h.pool.is_ejected(now_ms))
                        && (tier >= 1 || h.latency_us.load(Relaxed) < GRAY_FAILURE_US)
                }
            })
            .collect()
    };
    let mut c = eligible(0);
    if c.is_empty() {
        c = eligible(1);
    }
    if c.is_empty() {
        c = eligible(2);
    }
    match c.len() {
        0 => None,
        1 => Some(c[0]),
        n => match algorithm {
            Algorithm::LowestLatency => c
                .iter()
                .min_by_key(|u| {
                    health
                        .get(u.as_str())
                        .map_or(0, |h| h.latency_us.load(Relaxed))
                })
                .copied(),
            Algorithm::P2c => {
                let i = rand(n);
                let mut j = rand(n - 1);
                if j >= i {
                    j += 1; // distinct
                }
                let score = |u: &&String| {
                    health
                        .get(u.as_str())
                        .map_or(0, |h| h.pool.score(h.latency_us.load(Relaxed)))
                };
                if score(&c[j]) < score(&c[i]) {
                    Some(c[j])
                } else {
                    Some(c[i])
                }
            }
        },
    }
}

/// Report the outcome of a request that went to `url`, and eject it if it has become an outlier
/// of `urls`. `latency_us` is the time to response headers (None for a transport error).
pub fn report(
    health: &HealthMap,
    urls: &[String],
    url: &str,
    ok: bool,
    latency_us: Option<u64>,
    now_ms: u64,
) {
    let Some(me) = health.get(url) else { return };
    if let Some(l) = latency_us {
        me.pool.observe_latency(l);
    }
    let guard = me.pool.outlier.load();
    let Some(cfg) = guard.as_deref() else { return };
    let window = u64::from(cfg.window_secs.clamp(1, WINDOW_SLOTS as u32));
    if me.pool.is_ejected(now_ms) {
        return; // already out: in-flight stragglers say nothing new
    }
    me.pool.record_outcome(ok, now_ms, window);
    if ok {
        // a success after an ejection has expired starts the member's streak over
        if me.pool.ejected_until_ms.load(Relaxed) != 0 {
            me.pool.ejected_until_ms.store(0, Relaxed);
        }
        return;
    }
    let (total, fail) = me.pool.window_totals(now_ms, window);
    if total < u64::from(cfg.min_requests) || fail * 100 < u64::from(cfg.error_rate_pct) * total {
        return;
    }
    // An outlier, not an outage: some other member must be doing clearly better.
    let mut others = 0u32;
    let mut better = 0u32;
    let mut ejected = 0u32;
    for u in urls {
        if u == url {
            continue;
        }
        let Some(h) = health.get(u.as_str()) else {
            continue;
        };
        others += 1;
        if h.pool.is_ejected(now_ms) {
            ejected += 1;
            continue;
        }
        let (t, f) = h.pool.window_totals(now_ms, window);
        // "better": it has traffic and fewer than half as many failures, relatively
        if t > 0 && f * 100 * total < fail * 100 * t / 2 {
            better += 1;
        }
    }
    if others == 0 || better == 0 {
        return; // alone, or the whole pool is failing together
    }
    // cap: at most max_ejected_pct of the pool (counting this one) out at once
    let size = others + 1;
    if (ejected + 1) * 100 > cfg.max_ejected_pct * size {
        return;
    }
    let streak = me
        .pool
        .consecutive_ejections
        .fetch_add(1, Relaxed)
        .saturating_add(1)
        .min(10);
    me.pool.ejections.fetch_add(1, Relaxed);
    me.pool.ejected_until_ms.store(
        now_ms + u64::from(cfg.eject_secs) * 1000 * u64::from(streak),
        Relaxed,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::UpstreamHealth;

    fn pool_of(n: usize) -> (HealthMap, Vec<String>) {
        let urls: Vec<String> = (0..n).map(|i| format!("http://m{i}:80")).collect();
        let mut map = fnv::FnvHashMap::default();
        for u in &urls {
            let h = UpstreamHealth::new_healthy();
            h.pool.set_pool_member(true);
            h.pool.configure_outlier(Some(cfg()));
            map.insert(u.clone(), Arc::new(h));
        }
        (Arc::new(map), urls)
    }

    fn cfg() -> OutlierCfg {
        OutlierCfg {
            error_rate_pct: 50,
            min_requests: 10,
            window_secs: 10,
            eject_secs: 30,
            max_ejected_pct: 50,
        }
    }

    fn stats<'a>(h: &'a HealthMap, u: &str) -> &'a MemberStats {
        &h.get(u).unwrap().pool
    }

    /// A scripted "random" source.
    fn script(v: &'static [usize]) -> impl FnMut(usize) -> usize {
        let mut i = 0;
        move |n| {
            let r = v[i % v.len()] % n;
            i += 1;
            r
        }
    }

    // ── peak EWMA ──────────────────────────────────────────────────────────

    #[test]
    fn a_spike_is_adopted_at_once_and_forgotten_slowly() {
        let s = MemberStats::new();
        s.observe_latency(10_000);
        assert_eq!(s.ewma_us(), 10_000, "first sample");
        s.observe_latency(200_000);
        assert_eq!(
            s.ewma_us(),
            200_000,
            "a slower sample replaces it immediately"
        );
        s.observe_latency(10_000);
        assert_eq!(
            s.ewma_us(),
            (200_000 * 7 + 10_000) / 8,
            "a faster one is averaged in"
        );
        for _ in 0..3 {
            s.observe_latency(10_000);
        }
        assert!(
            s.ewma_us() > 100_000,
            "three fast samples do not erase the memory of a slow period"
        );
        for _ in 0..60 {
            s.observe_latency(10_000);
        }
        assert!(s.ewma_us() < 12_000, "but it does recover");
    }

    #[test]
    fn score_is_load_times_latency_with_sane_fallbacks() {
        let s = MemberStats::new();
        assert_eq!(s.score(0), UNKNOWN_LATENCY_US, "no sample, no probe: small");
        assert_eq!(s.score(40_000), 40_000, "falls back to the probe latency");
        s.observe_latency(5_000);
        let _a = s.begin();
        let _b = s.begin();
        assert_eq!(s.inflight(), 2);
        assert_eq!(
            s.score(40_000),
            3 * 5_000,
            "(in_flight + 1) × measured latency"
        );
        drop(_a);
        assert_eq!(s.inflight(), 1);
    }

    // ── selection ──────────────────────────────────────────────────────────

    #[test]
    fn p2c_takes_the_less_loaded_of_two() {
        let (h, urls) = pool_of(3);
        stats(&h, &urls[0]).observe_latency(10_000);
        stats(&h, &urls[1]).observe_latency(10_000);
        stats(&h, &urls[2]).observe_latency(10_000);
        let _busy: Vec<_> = (0..5).map(|_| stats(&h, &urls[0]).begin()).collect();
        // sampled pair is always (m0, m1): the idle one wins
        let mut r = script(&[0, 0]); // i = 0, then j = 0 → bumped past i to 1
        assert_eq!(pick(&h, &urls, Algorithm::P2c, 0, &mut r), Some(&urls[1]));
    }

    #[test]
    fn busy_and_slow_members_get_less_traffic_in_proportion() {
        let (h, urls) = pool_of(3);
        stats(&h, &urls[0]).observe_latency(10_000); // fast
        stats(&h, &urls[1]).observe_latency(10_000); // fast
        stats(&h, &urls[2]).observe_latency(100_000); // 10x slower
        let mut rng = fastrand::Rng::with_seed(7);
        let mut r = |n: usize| rng.usize(..n);
        let mut counts = [0u32; 3];
        for _ in 0..6000 {
            let u = pick(&h, &urls, Algorithm::P2c, 0, &mut r).unwrap();
            counts[urls.iter().position(|x| x == u).unwrap()] += 1;
        }
        assert!(
            counts[2] < counts[0] / 3 && counts[2] < counts[1] / 3,
            "slow member share: {counts:?}"
        );
        assert!(
            counts[0] > 1500 && counts[1] > 1500,
            "the fast ones share the rest: {counts:?}"
        );
    }

    #[test]
    fn it_does_not_herd_onto_the_single_fastest_member() {
        // Probe latencies differ by 1-2%: the old rule sent EVERY request to the first. With
        // requests in flight (as under real load) P2C spreads them.
        let (h, urls) = pool_of(3);
        for (i, u) in urls.iter().enumerate() {
            h.get(u)
                .unwrap()
                .latency_us
                .store(10_000 + i as u64 * 100, Relaxed);
        }
        let mut rng = fastrand::Rng::with_seed(1);
        let mut r = |n: usize| rng.usize(..n);
        let mut counts = [0u32; 3];
        let mut outstanding = std::collections::VecDeque::new();
        for _ in 0..3000 {
            let u = pick(&h, &urls, Algorithm::P2c, 0, &mut r).unwrap();
            let idx = urls.iter().position(|x| x == u).unwrap();
            counts[idx] += 1;
            outstanding.push_back(stats(&h, u).begin());
            if outstanding.len() > 9 {
                outstanding.pop_front(); // a response completed
            }
        }
        assert!(
            counts.iter().all(|&c| c > 700),
            "every member carries a real share: {counts:?}"
        );
        let mut r = |_n: usize| 0;
        assert_eq!(
            pick(&h, &urls, Algorithm::LowestLatency, 0, &mut r),
            Some(&urls[0]),
            "the escape hatch keeps the previous behaviour"
        );
    }

    #[test]
    fn down_gray_and_ejected_members_are_avoided_but_never_cause_a_503() {
        let (h, urls) = pool_of(3);
        let mut r = script(&[0, 0, 1, 1, 2, 2]);
        h.get(&urls[0]).unwrap().healthy.store(false, Relaxed);
        for _ in 0..30 {
            assert_ne!(
                pick(&h, &urls, Algorithm::P2c, 0, &mut r),
                Some(&urls[0]),
                "down"
            );
        }
        h.get(&urls[1])
            .unwrap()
            .latency_us
            .store(3_000_000, Relaxed); // gray
        for _ in 0..30 {
            assert_eq!(
                pick(&h, &urls, Algorithm::P2c, 0, &mut r),
                Some(&urls[2]),
                "only m2 is fully fit"
            );
        }
        // eject m2: the gray-but-up m1 is next best
        h.get(&urls[2])
            .unwrap()
            .pool
            .ejected_until_ms
            .store(10_000, Relaxed);
        assert_eq!(pick(&h, &urls, Algorithm::P2c, 0, &mut r), Some(&urls[1]));
        // everything healthy is ejected: panic mode serves anyway rather than 503
        h.get(&urls[1])
            .unwrap()
            .pool
            .ejected_until_ms
            .store(10_000, Relaxed);
        assert!(
            pick(&h, &urls, Algorithm::P2c, 0, &mut r).is_some(),
            "ejection alone never empties the pool"
        );
        // every member down: nothing to pick
        for u in &urls {
            h.get(u).unwrap().healthy.store(false, Relaxed);
        }
        assert_eq!(pick(&h, &urls, Algorithm::P2c, 0, &mut r), None);
    }

    // ── outlier detection ──────────────────────────────────────────────────

    fn feed(h: &HealthMap, urls: &[String], who: usize, ok: bool, n: u32, now: u64) {
        for _ in 0..n {
            report(h, urls, &urls[who], ok, Some(1_000), now);
        }
    }

    #[test]
    fn a_failing_member_is_ejected_while_the_rest_are_fine() {
        let (h, urls) = pool_of(3);
        feed(&h, &urls, 1, true, 30, 1_000);
        feed(&h, &urls, 2, true, 30, 1_000);
        feed(&h, &urls, 0, false, 9, 1_000); // 9 requests: under min_requests
        assert!(!stats(&h, &urls[0]).is_ejected(1_000));
        feed(&h, &urls, 0, false, 1, 1_000); // the 10th: 100% failing
        assert!(stats(&h, &urls[0]).is_ejected(1_000));
        assert_eq!(stats(&h, &urls[0]).ejections(), 1);
        assert!(!stats(&h, &urls[1]).is_ejected(1_000) && !stats(&h, &urls[2]).is_ejected(1_000));
        // out for eject_secs, then back
        assert!(stats(&h, &urls[0]).is_ejected(30_999));
        assert!(
            !stats(&h, &urls[0]).is_ejected(31_001),
            "re-admitted after the cool-down"
        );
    }

    #[test]
    fn a_pool_wide_outage_is_not_an_outlier() {
        let (h, urls) = pool_of(3);
        for who in 0..3 {
            feed(&h, &urls, who, false, 40, 1_000);
        }
        assert!(
            (0..3).all(|i| !stats(&h, &urls[i]).is_ejected(1_000)),
            "everyone failing together is the upstream's problem, not one member's"
        );
    }

    #[test]
    fn the_rate_matters_not_the_count() {
        let (h, urls) = pool_of(2);
        feed(&h, &urls, 1, true, 50, 1_000);
        feed(&h, &urls, 0, true, 60, 1_000);
        feed(&h, &urls, 0, false, 5, 1_000); // 5 of 65: healthy
        assert!(!stats(&h, &urls[0]).is_ejected(1_000));
    }

    #[test]
    fn at_most_the_configured_share_of_the_pool_is_ejected() {
        let (h, urls) = pool_of(4); // max 50% => 2 of 4
        feed(&h, &urls, 3, true, 50, 1_000); // one clearly healthy member
        for who in 0..3 {
            feed(&h, &urls, who, false, 20, 1_000);
        }
        let out = (0..4)
            .filter(|&i| stats(&h, &urls[i]).is_ejected(1_000))
            .count();
        assert_eq!(out, 2, "the cap holds: 2 of 4");
        assert!(!stats(&h, &urls[3]).is_ejected(1_000));
    }

    #[test]
    fn consecutive_ejections_last_longer() {
        let (h, urls) = pool_of(2);
        feed(&h, &urls, 1, true, 100, 1_000);
        feed(&h, &urls, 0, false, 10, 1_000);
        assert!(stats(&h, &urls[0]).is_ejected(1_000));
        let first = stats(&h, &urls[0]).ejected_until_ms.load(Relaxed) - 1_000;
        assert_eq!(first, 30_000);
        // back in, fails again at once (a success would have reset the streak)
        let later = 40_000;
        feed(&h, &urls, 1, true, 100, later);
        feed(&h, &urls, 0, false, 10, later);
        let second = stats(&h, &urls[0]).ejected_until_ms.load(Relaxed) - later;
        assert_eq!(second, 60_000, "the second ejection is twice as long");
        assert_eq!(stats(&h, &urls[0]).ejections(), 2);
    }

    #[test]
    fn a_member_without_outlier_config_is_never_ejected() {
        let (h, urls) = pool_of(2);
        for u in &urls {
            h.get(u).unwrap().pool.configure_outlier(None);
        }
        feed(&h, &urls, 1, true, 50, 1_000);
        feed(&h, &urls, 0, false, 100, 1_000);
        assert!(!stats(&h, &urls[0]).is_ejected(1_000));
        // but its latency is still tracked for P2C
        assert!(stats(&h, &urls[0]).ewma_us() > 0);
    }

    #[test]
    fn old_failures_slide_out_of_the_window() {
        let (h, urls) = pool_of(2);
        feed(&h, &urls, 1, true, 100, 1_000);
        feed(&h, &urls, 0, false, 9, 1_000);
        feed(&h, &urls, 1, true, 100, 13_000);
        feed(&h, &urls, 0, false, 1, 13_000); // the nine are 12 s old: outside the window
        assert!(!stats(&h, &urls[0]).is_ejected(13_000));
    }

    #[test]
    fn reconfiguring_clears_the_slate() {
        let (h, urls) = pool_of(2);
        feed(&h, &urls, 1, true, 100, 1_000);
        feed(&h, &urls, 0, false, 10, 1_000);
        assert!(stats(&h, &urls[0]).is_ejected(1_000));
        h.get(&urls[0]).unwrap().pool.configure_outlier(Some(cfg())); // unchanged: kept
        assert!(stats(&h, &urls[0]).is_ejected(1_000));
        let mut other = cfg();
        other.eject_secs = 5;
        h.get(&urls[0]).unwrap().pool.configure_outlier(Some(other));
        assert!(
            !stats(&h, &urls[0]).is_ejected(1_000),
            "new thresholds start clean"
        );
    }
}
