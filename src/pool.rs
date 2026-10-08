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
use std::sync::{Arc, Mutex};

/// Serializes the "should this member be ejected?" decision across every pool in the process:
/// the cap (`max_ejected_pct`) is a property of a whole pool, so checking how many members are
/// out and ejecting one must be a single step. It is only taken after a member has already
/// crossed its failure threshold, so it is off the normal request path.
static EJECT_LOCK: Mutex<()> = Mutex::new(());

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

impl From<crate::config::LoadBalancing> for Algorithm {
    fn from(l: crate::config::LoadBalancing) -> Self {
        match l {
            crate::config::LoadBalancing::P2c => Algorithm::P2c,
            crate::config::LoadBalancing::LowestLatency => Algorithm::LowestLatency,
        }
    }
}

impl From<&crate::config::OutlierDetectionConfig> for OutlierCfg {
    fn from(c: &crate::config::OutlierDetectionConfig) -> Self {
        OutlierCfg {
            error_rate_pct: c.error_rate_pct,
            min_requests: c.min_requests,
            window_secs: c.window_secs,
            eject_secs: c.eject_secs,
            max_ejected_pct: c.max_ejected_pct,
        }
    }
}

/// One second of outcomes. The epoch and both counters live behind one lock, so rolling a slot
/// over to a new second can never lose or misattribute a concurrent update.
#[derive(Clone, Copy, Default)]
struct Slot {
    epoch_s: u64,
    ok: u32,
    fail: u32,
}

/// Live state of one member, kept next to its health entry.
pub struct MemberStats {
    /// Requests currently waiting for this member's response headers.
    inflight: AtomicU32,
    /// Peak-EWMA of the time to response headers and when it was last updated, in ONE word so
    /// the pair can only change together: estimate in the high 32 bits (microseconds, saturating;
    /// 0 = no estimate), update time in the low 32 bits (ms of the pool clock, wrapping). The
    /// estimate is *aged* when read (see [`decayed`]), not only when a sample arrives.
    ewma: AtomicU64,
    slots: Mutex<[Slot; WINDOW_SLOTS]>,
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
fn pack_ewma(est_us: u64, at_ms: u64) -> u64 {
    (est_us.min(u64::from(u32::MAX)) << 32) | (at_ms & 0xffff_ffff)
}

/// The estimate in `word`, aged to `now_ms`.
fn aged_estimate(word: u64, now_ms: u64) -> u64 {
    let age = (now_ms as u32).wrapping_sub(word as u32);
    decayed(word >> 32, u64::from(age))
}

/// A latency estimate loses half its value every this long without a new sample. Without that, a
/// member that was once slow (or came back from an ejection) kept its old estimate for good: at
/// low load it was never picked again, so it never got the sample that would correct it.
const EWMA_HALF_LIFE_MS: u64 = 5_000;

/// `v` after `dt_ms` without a sample: halved every [`EWMA_HALF_LIFE_MS`], with a straight line
/// between the halvings (integer arithmetic, no floats on the request path).
fn decayed(v: u64, dt_ms: u64) -> u64 {
    let halvings = dt_ms / EWMA_HALF_LIFE_MS;
    if halvings >= 40 {
        return 0;
    }
    let v = v >> halvings;
    v - v * (dt_ms % EWMA_HALF_LIFE_MS) / (2 * EWMA_HALF_LIFE_MS)
}

/// Latency assumed for a member with no sample yet: small, so a new member gets traffic.
const UNKNOWN_LATENCY_US: u64 = 1_000;

impl MemberStats {
    pub fn new() -> Self {
        Self {
            inflight: AtomicU32::new(0),
            ewma: AtomicU64::new(0),
            slots: Mutex::new([Slot::default(); WINDOW_SLOTS]),
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
            *self.lock_slots() = [Slot::default(); WINDOW_SLOTS];
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

    /// The latency estimate as of `now_ms`, aged by the time since its last sample (0 = none).
    pub fn ewma_us(&self, now_ms: u64) -> u64 {
        aged_estimate(self.ewma.load(Relaxed), now_ms)
    }

    pub fn ejections(&self) -> u64 {
        self.ejections.load(Relaxed)
    }

    pub fn is_ejected(&self, now_ms: u64) -> bool {
        let until = self.ejected_until_ms.load(Relaxed);
        until != 0 && now_ms < until
    }

    /// Fold one response-header latency, taken at `now_ms`, into the peak EWMA. The estimate it
    /// is folded into is the *aged* one, so a member that has been quiet for a while is judged
    /// on the new sample rather than on stale history.
    pub fn observe_latency(&self, sample_us: u64, now_ms: u64) {
        let sample = sample_us.max(1).min(u64::from(u32::MAX));
        let mut word = self.ewma.load(Relaxed);
        loop {
            let base = aged_estimate(word, now_ms);
            let next = if base == 0 || sample >= base {
                sample // first sample, or a spike: adopt immediately
            } else {
                (base * EWMA_DECAY_NUM + sample) / EWMA_DECAY_DEN
            };
            match self
                .ewma
                .compare_exchange_weak(word, pack_ewma(next, now_ms), Relaxed, Relaxed)
            {
                Ok(_) => return,
                Err(seen) => word = seen,
            }
        }
    }

    fn lock_slots(&self) -> std::sync::MutexGuard<'_, [Slot; WINDOW_SLOTS]> {
        // The data is plain counters: a poisoned lock is still usable.
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record one request's outcome in the failure window.
    fn record_outcome(&self, ok: bool, now_ms: u64) {
        let sec = now_ms / 1000;
        let mut slots = self.lock_slots();
        let s = &mut slots[(sec % WINDOW_SLOTS as u64) as usize];
        if s.epoch_s != sec {
            *s = Slot {
                epoch_s: sec,
                ..Slot::default()
            };
        }
        if ok {
            s.ok = s.ok.saturating_add(1);
        } else {
            s.fail = s.fail.saturating_add(1);
        }
    }

    /// (requests, failures) in the last `window` seconds.
    fn window_totals(&self, now_ms: u64, window: u64) -> (u64, u64) {
        let sec = now_ms / 1000;
        let (mut total, mut fail) = (0u64, 0u64);
        for s in self.lock_slots().iter() {
            if s.epoch_s + window > sec && s.epoch_s <= sec {
                total += u64::from(s.ok) + u64::from(s.fail);
                fail += u64::from(s.fail);
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

/// True when `b` should get the request rather than `a`. Each side is its load times its latency
/// estimate, with one refinement: a member with **no estimate** (new, ejected and back, or quiet for
/// so long that its estimate has faded) is assumed to be as fast as the other candidate until it
/// has been measured, so the two compete on load alone. Scoring it with a fixed guess instead made
/// it lose to any peer faster than the guess and stay unmeasured.
fn b_is_better(
    a: Option<&crate::health::UpstreamHealth>,
    b: Option<&crate::health::UpstreamHealth>,
    now_ms: u64,
) -> bool {
    let (a, b) = match (a, b) {
        (Some(a), Some(b)) => (a, b),
        (None, _) => return false, // an untracked member is optimistic: it wins
        (_, None) => return true,
    };
    let (ea, eb) = (a.pool.ewma_us(now_ms), b.pool.ewma_us(now_ms));
    let (la, lb) = match (ea, eb) {
        (0, 0) => (
            fallback_latency(a.latency_us.load(Relaxed)),
            fallback_latency(b.latency_us.load(Relaxed)),
        ),
        (0, v) => (v, v),
        (v, 0) => (v, v),
        (x, y) => (x, y),
    };
    let load = |h: &crate::health::UpstreamHealth| u64::from(h.pool.inflight()) + 1;
    load(b).saturating_mul(lb) < load(a).saturating_mul(la)
}

/// Latency to assume for a member with no estimate, when its peer has none either.
fn fallback_latency(probe_us: u64) -> u64 {
    if probe_us > 0 {
        probe_us
    } else {
        UNKNOWN_LATENCY_US
    }
}

/// Choose a member of `urls` for one request. `rand(n)` returns a uniform index below `n`.
/// `None` only when there is no member at all or every member is down.
pub fn pick<'a>(
    health: &HealthMap,
    urls: &'a [String],
    algorithm: Algorithm,
    now_ms: u64,
    rand: &mut dyn FnMut(usize) -> usize,
) -> Option<&'a String> {
    if algorithm == Algorithm::P2c && urls.len() >= 2 {
        // Constant work and no allocation: draw two distinct members at random and keep them
        // if they are fully eligible. Only a pool with few eligible members (down, gray or
        // ejected ones) falls through to the exhaustive scan below.
        let fully_eligible = |u: &String| match health.get(u.as_str()) {
            None => true,
            Some(h) => {
                h.healthy.load(Relaxed)
                    && !h.pool.is_ejected(now_ms)
                    && h.latency_us.load(Relaxed) < GRAY_FAILURE_US
            }
        };
        let n = urls.len();
        let first = (0..4).map(|_| rand(n)).find(|&i| fully_eligible(&urls[i]));
        if let Some(i) = first {
            let second = (0..4)
                .map(|_| {
                    let j = rand(n - 1);
                    if j >= i {
                        j + 1
                    } else {
                        j
                    }
                })
                .find(|&j| fully_eligible(&urls[j]));
            if let Some(j) = second {
                return Some(
                    if b_is_better(
                        health.get(urls[i].as_str()).map(|h| &**h),
                        health.get(urls[j].as_str()).map(|h| &**h),
                        now_ms,
                    ) {
                        &urls[j]
                    } else {
                        &urls[i]
                    },
                );
            }
        }
    }
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
                if b_is_better(
                    health.get(c[i].as_str()).map(|h| &**h),
                    health.get(c[j].as_str()).map(|h| &**h),
                    now_ms,
                ) {
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
        me.pool.observe_latency(l, now_ms);
    }
    let guard = me.pool.outlier.load();
    let Some(cfg) = guard.as_deref() else { return };
    let window = u64::from(cfg.window_secs.clamp(1, WINDOW_SLOTS as u32));
    if me.pool.is_ejected(now_ms) {
        return; // already out: in-flight stragglers say nothing new
    }
    me.pool.record_outcome(ok, now_ms);
    if ok {
        // a success after an ejection has expired starts the member's streak over
        if me.pool.ejected_until_ms.load(Relaxed) != 0 {
            me.pool.ejected_until_ms.store(0, Relaxed);
            me.pool.consecutive_ejections.store(0, Relaxed);
        }
        return;
    }
    let (total, fail) = me.pool.window_totals(now_ms, window);
    if total < u64::from(cfg.min_requests) || fail * 100 < u64::from(cfg.error_rate_pct) * total {
        return;
    }
    // The decision reads other members' state and ends in an ejection: do it as one step.
    let _decision = EJECT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if me.pool.is_ejected(now_ms) {
        return; // another request ejected it while this one waited
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
    // It gets no traffic while it is out, so its old estimate would only go stale: forget it, and
    // measure it afresh when it returns.
    me.pool.ewma.store(0, Relaxed);
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
        s.observe_latency(10_000, 0);
        assert_eq!(s.ewma_us(0), 10_000, "first sample");
        s.observe_latency(200_000, 0);
        assert_eq!(
            s.ewma_us(0),
            200_000,
            "a slower sample replaces it immediately"
        );
        s.observe_latency(10_000, 0);
        assert_eq!(
            s.ewma_us(0),
            (200_000 * 7 + 10_000) / 8,
            "a faster one is averaged in"
        );
        for _ in 0..3 {
            s.observe_latency(10_000, 0);
        }
        assert!(
            s.ewma_us(0) > 100_000,
            "three fast samples do not erase the memory of a slow period"
        );
        for _ in 0..60 {
            s.observe_latency(10_000, 0);
        }
        assert!(s.ewma_us(0) < 12_000, "but it does recover");
    }

    #[test]
    fn a_member_with_no_estimate_competes_with_its_peers_latency_not_a_fixed_guess() {
        let mk = || UpstreamHealth::new_healthy();
        let (a, b) = (mk(), mk());
        // no estimate on either side: the probe latency decides, then the fixed fallback
        a.latency_us.store(40_000, Relaxed);
        b.latency_us.store(1_000, Relaxed);
        assert!(b_is_better(Some(&a), Some(&b), 0));
        assert!(!b_is_better(Some(&b), Some(&a), 0));
        // a is measured (200 us, a very fast backend), b is not: b is assumed as fast, so the two
        // compete on load alone: equal load keeps a, one request in flight on a hands b the next
        a.pool.observe_latency(200, 0);
        assert!(
            !b_is_better(Some(&a), Some(&b), 0),
            "tie: keep the first draw"
        );
        let _busy = a.pool.begin();
        assert!(
            b_is_better(Some(&a), Some(&b), 0),
            "a is busier: the unmeasured member gets it"
        );
        // both measured: load x latency as before
        b.pool.observe_latency(5_000, 0);
        assert!(!b_is_better(Some(&a), Some(&b), 0), "b is 25x slower");
        // an untracked member is optimistic
        assert!(b_is_better(Some(&a), None, 0));
        assert!(!b_is_better(None, Some(&a), 0));
    }

    #[test]
    fn p2c_takes_the_less_loaded_of_two() {
        let (h, urls) = pool_of(3);
        stats(&h, &urls[0]).observe_latency(10_000, 0);
        stats(&h, &urls[1]).observe_latency(10_000, 0);
        stats(&h, &urls[2]).observe_latency(10_000, 0);
        let _busy: Vec<_> = (0..5).map(|_| stats(&h, &urls[0]).begin()).collect();
        // sampled pair is always (m0, m1): the idle one wins
        let mut r = script(&[0, 0]); // i = 0, then j = 0 → bumped past i to 1
        assert_eq!(pick(&h, &urls, Algorithm::P2c, 0, &mut r), Some(&urls[1]));
    }

    #[test]
    fn busy_and_slow_members_get_less_traffic_in_proportion() {
        let (h, urls) = pool_of(3);
        stats(&h, &urls[0]).observe_latency(10_000, 0); // fast
        stats(&h, &urls[1]).observe_latency(10_000, 0); // fast
        stats(&h, &urls[2]).observe_latency(100_000, 0); // 10x slower
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
        assert!(stats(&h, &urls[0]).ewma_us(1_000) > 0);
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

    #[test]
    fn a_success_after_an_ejection_starts_the_streak_over() {
        let (h, urls) = pool_of(2);
        feed(&h, &urls, 1, true, 100, 1_000);
        feed(&h, &urls, 0, false, 10, 1_000);
        assert!(stats(&h, &urls[0]).is_ejected(1_000));
        // back after the cool-down, and it serves a request correctly
        feed(&h, &urls, 0, true, 1, 40_000);
        assert_eq!(
            stats(&h, &urls[0]).consecutive_ejections.load(Relaxed),
            0,
            "a recovered member is not a repeat offender"
        );
        // so the next ejection is the base length again, not doubled
        feed(&h, &urls, 1, true, 100, 100_000);
        feed(&h, &urls, 0, false, 30, 100_000);
        let len = stats(&h, &urls[0]).ejected_until_ms.load(Relaxed) - 100_000;
        assert_eq!(len, 30_000);
    }

    #[test]
    fn concurrent_failures_cannot_push_the_pool_past_its_cap() {
        for round in 0..200 {
            let (h, urls) = pool_of(4); // max 50% => 2 of 4
            feed(&h, &urls, 3, true, 50, 1_000);
            // three members cross the failure threshold at the same moment
            for who in 0..3 {
                feed(&h, &urls, who, false, 9, 1_000);
            }
            let gate = std::sync::Barrier::new(3);
            std::thread::scope(|sc| {
                for who in 0..3 {
                    let (h, urls, gate) = (&h, &urls, &gate);
                    sc.spawn(move || {
                        gate.wait();
                        report(h, urls, &urls[who], false, Some(1_000), 1_000);
                    });
                }
            });
            let out = (0..4)
                .filter(|&i| stats(&h, &urls[i]).is_ejected(1_000))
                .count();
            assert!(out <= 2, "round {round}: {out} of 4 ejected, cap is 2");
        }
    }

    #[test]
    fn concurrent_outcomes_across_a_second_boundary_are_all_counted() {
        let s = MemberStats::new();
        std::thread::scope(|sc| {
            for t in 0..8u64 {
                let s = &s;
                sc.spawn(move || {
                    for k in 0..2_000u64 {
                        // every thread keeps crossing second boundaries
                        s.record_outcome(k % 3 != 0, 5_000 + (k + t) % 2 * 1_000);
                    }
                });
            }
        });
        let (total, fail) = s.window_totals(6_000, 10);
        assert_eq!(total, 16_000, "no outcome lost to a slot roll-over");
        assert!(fail > 0 && fail < total);
    }

    #[test]
    fn the_constant_work_path_never_picks_an_ejected_member() {
        let (h, urls) = pool_of(4);
        feed(&h, &urls, 3, true, 100, 1_000);
        feed(&h, &urls, 0, false, 10, 1_000);
        assert!(stats(&h, &urls[0]).is_ejected(1_000));
        // the "random" source keeps offering the ejected member first
        let mut r = script(&[0, 0, 0, 0, 1, 2, 0, 3]);
        for _ in 0..50 {
            let got = pick(&h, &urls, Algorithm::P2c, 1_000, &mut r).unwrap();
            assert_ne!(got, &urls[0]);
        }
    }

    // ── the latency estimate ages ──────────────────────────────────────────

    #[test]
    fn the_estimate_halves_every_half_life_and_eventually_vanishes() {
        let hl = EWMA_HALF_LIFE_MS;
        assert_eq!(decayed(80_000, 0), 80_000);
        assert_eq!(decayed(80_000, hl), 40_000);
        assert_eq!(decayed(80_000, 2 * hl), 20_000);
        let mid = decayed(80_000, hl / 2); // between 1 and 1/2, never above either bound
        assert!((56_000..=60_000).contains(&mid), "{mid}");
        assert!(decayed(80_000, 10 * hl) < 100);
        assert_eq!(decayed(80_000, 40 * hl), 0);
        assert_eq!(decayed(0, 5 * hl), 0);
        // monotonic: never increases with time
        let mut last = u64::MAX;
        for t in (0..60 * hl).step_by(997) {
            let v = decayed(1_000_000, t);
            assert!(v <= last);
            last = v;
        }
    }

    #[test]
    fn a_member_that_was_once_slow_is_not_starved_for_good_at_low_load() {
        let (h, urls) = pool_of(2);
        stats(&h, &urls[0]).observe_latency(500_000, 0); // one slow spike
        let mut r = script(&[0, 1]);
        // soon after: the other member is steadily faster, so the slow one is (rightly) avoided
        stats(&h, &urls[1]).observe_latency(2_000, 1_000);
        for _ in 0..20 {
            assert_eq!(
                pick(&h, &urls, Algorithm::P2c, 1_000, &mut r),
                Some(&urls[1])
            );
        }
        // a minute later with no traffic to it, the spike is forgotten: it is tried again
        stats(&h, &urls[1]).observe_latency(2_000, 60_000);
        let picked_slow = (0..20)
            .filter(|_| pick(&h, &urls, Algorithm::P2c, 60_000, &mut r) == Some(&urls[0]))
            .count();
        assert!(
            picked_slow > 0,
            "a member judged on a minute-old spike must get traffic again"
        );
        // and one fresh sample puts it back in proper competition
        stats(&h, &urls[0]).observe_latency(2_500, 60_000);
        assert!(
            stats(&h, &urls[0]).ewma_us(60_000) < 3_000,
            "judged on the new sample, not the old spike"
        );
    }

    #[test]
    fn a_new_sample_is_folded_into_the_aged_estimate_not_the_stale_one() {
        let s = MemberStats::new();
        s.observe_latency(500_000, 0);
        s.observe_latency(2_000, 100_000); // 100 s later
        assert_eq!(s.ewma_us(100_000), 2_000, "the 500 ms spike is long gone");
        s.observe_latency(500_000, 100_000);
        assert_eq!(
            s.ewma_us(100_000),
            500_000,
            "a new spike is still adopted at once"
        );
    }

    #[test]
    fn an_ejected_member_is_measured_afresh_when_it_returns() {
        let (h, urls) = pool_of(2);
        stats(&h, &urls[0]).observe_latency(300_000, 1_000);
        feed(&h, &urls, 1, true, 100, 1_000);
        feed(&h, &urls, 0, false, 10, 1_000);
        assert!(stats(&h, &urls[0]).is_ejected(1_000));
        assert_eq!(
            stats(&h, &urls[0]).ewma_us(1_000),
            0,
            "its old estimate is dropped on ejection"
        );
    }

    #[test]
    fn the_estimate_and_its_timestamp_live_in_one_word() {
        let w = pack_ewma(123_456, 7_890);
        assert_eq!((w >> 32, w as u32), (123_456, 7_890));
        assert_eq!(
            pack_ewma(u64::MAX, 1) >> 32,
            u64::from(u32::MAX),
            "saturates, never wraps"
        );
        assert_eq!(
            pack_ewma(1 << 33, 1) >> 32,
            u64::from(u32::MAX),
            "a 2^33 us estimate saturates too"
        );
        // age is computed across the 32-bit millisecond wrap
        let near_wrap = pack_ewma(80_000, u64::from(u32::MAX) - 1_000);
        assert_eq!(
            aged_estimate(near_wrap, u64::from(u32::MAX) + 1),
            decayed(80_000, 1_001)
        );
        // concurrent observers always leave a coherent pair: constant samples keep the estimate
        // at that sample whatever the interleaving and the (wrapping) clock
        let s = MemberStats::new();
        std::thread::scope(|sc| {
            for t in 0..8u64 {
                let s = &s;
                sc.spawn(move || {
                    for k in 0..5_000u64 {
                        s.observe_latency(10_000, (k * 8 + t) * 3);
                    }
                });
            }
        });
        let at = u64::from(s.ewma.load(Relaxed) as u32);
        assert_eq!(s.ewma_us(at), 10_000, "a coherent (estimate, time) pair");
    }
}
