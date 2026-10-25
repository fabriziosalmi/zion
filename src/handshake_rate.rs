// SPDX-License-Identifier: Apache-2.0
//! Per-IP new-TLS-handshake rate limiter — the handshake-CPU-exhaustion lever (#718).
//!
//! `conn_per_ip` (see `connlimit.rs`) caps how many connections a source holds open at once;
//! this caps how *fast* a source may start new handshakes. The expensive part of a TLS 1.3
//! handshake is the server signature, so a client that connects, handshakes and closes in a loop
//! makes zion pay that signature every time while paying almost nothing itself (measured: one IP
//! drove ~4 cores with an RSA-2048 certificate, #718). Enforced at accept, before the handshake,
//! so a rejected attempt costs one map probe and an immediate close — no crypto, nothing held.
//!
//! A token bucket per key expresses the two cases the issue settled: a sustained `rate` per second
//! (the bucket refills at that rate) plus a `burst` allowance (the bucket's capacity), so a
//! thundering herd behind one CGNAT IP clears while a flood is cut. `rate == 0` disables the limit
//! and never touches the map. IPv6 is keyed per /64 (a single subscriber is handed a whole /64, so
//! per-address keying would be trivially evaded); IPv4 is keyed per full address.

use dashmap::DashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

/// Above this many tracked keys, a new key triggers a sweep of fully-refilled (idle) buckets
/// before it is inserted; if the table is still full of active buckets afterwards the new attempt
/// is admitted without being tracked, so the table itself can never grow without bound and become
/// the DoS target. 128k entries is far above any real client population and a few MiB of memory.
const MAX_TRACKED: usize = 131_072;

/// The rate-limit key for a peer: the full IPv4 address, or the /64 prefix of an IPv6 address
/// (the low 64 bits zeroed).
fn key_for(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in octets.iter_mut().skip(8) {
                *b = 0;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// A token bucket's state: `tokens` available right now, as of `last`.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// Tokens this bucket would hold at `now` given `rate`/s and `cap`, without mutating.
    fn tokens_at(&self, now: Instant, rate: f64, cap: f64) -> f64 {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        (self.tokens + elapsed * rate).min(cap)
    }
}

/// Tracks a token bucket per source key. Lives in `AppState` across hot-reloads (it tracks live
/// behaviour, not config); the `rate` and `burst` are read from the config snapshot at each accept,
/// so retuning the limit takes effect on new attempts without disturbing anything.
#[derive(Default)]
pub struct PerIpHandshakeRate {
    buckets: DashMap<IpAddr, Bucket>,
}

impl PerIpHandshakeRate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit one handshake attempt from `ip` under `rate` per second with a `burst` capacity, as
    /// of `now`. `rate == 0` disables the limit (always admits, never touches the map). Returns
    /// `true` to admit, `false` to reject (caller closes the socket).
    pub fn admit_at(&self, ip: IpAddr, rate: u32, burst: u32, now: Instant) -> bool {
        if rate == 0 {
            return true;
        }
        let cap = burst.max(1) as f64;
        let refill = rate as f64;
        let key = key_for(ip);

        // Bounded table: when a new key would push past the cap, first drop buckets that have
        // fully refilled (indistinguishable from absent — a fresh bucket starts full), then, if
        // the table is still full of in-debt (active) buckets, admit without tracking rather than
        // grow unbounded. Only pays this on a genuinely new key under table pressure.
        if self.buckets.len() >= MAX_TRACKED && !self.buckets.contains_key(&key) {
            self.buckets
                .retain(|_, b| b.tokens_at(now, refill, cap) < cap);
            if self.buckets.len() >= MAX_TRACKED {
                return true;
            }
        }

        let mut entry = self.buckets.entry(key).or_insert(Bucket {
            tokens: cap,
            last: now,
        });
        let b = entry.value_mut();
        b.tokens = b.tokens_at(now, refill, cap);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Admit one attempt as of this instant. See [`admit_at`](Self::admit_at).
    #[inline]
    pub fn admit(&self, ip: IpAddr, rate: u32, burst: u32) -> bool {
        self.admit_at(ip, rate, burst, Instant::now())
    }

    /// Number of distinct keys currently tracked. Used by tests.
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rate_zero_is_disabled_and_untracked() {
        let r = PerIpHandshakeRate::new();
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(r.admit_at(ip("1.2.3.4"), 0, 0, now));
        }
        assert_eq!(r.tracked(), 0, "a disabled limit must not allocate");
    }

    #[test]
    fn burst_is_allowed_then_the_rest_are_rejected() {
        let r = PerIpHandshakeRate::new();
        let now = Instant::now();
        let a = ip("1.2.3.4");
        // capacity 5, no time passes: exactly 5 admitted, the 6th rejected.
        for i in 0..5 {
            assert!(r.admit_at(a, 10, 5, now), "attempt {i} within burst");
        }
        assert!(!r.admit_at(a, 10, 5, now), "6th attempt exceeds the burst");
    }

    #[test]
    fn tokens_refill_at_the_sustained_rate() {
        let r = PerIpHandshakeRate::new();
        let t0 = Instant::now();
        let a = ip("1.2.3.4");
        // Drain the burst of 5 at rate 10/s.
        for _ in 0..5 {
            assert!(r.admit_at(a, 10, 5, t0));
        }
        assert!(!r.admit_at(a, 10, 5, t0));
        // After 1 s, 10/s refills the capacity (5) back; 5 more admit, then empty again.
        let t1 = t0 + Duration::from_secs(1);
        for i in 0..5 {
            assert!(r.admit_at(a, 10, 5, t1), "refilled attempt {i}");
        }
        assert!(
            !r.admit_at(a, 10, 5, t1),
            "capacity is the ceiling, not rate*elapsed"
        );
    }

    #[test]
    fn a_flooding_ip_does_not_starve_a_quiet_one() {
        let r = PerIpHandshakeRate::new();
        let now = Instant::now();
        let flood = ip("1.1.1.1");
        for _ in 0..100 {
            let _ = r.admit_at(flood, 2, 2, now);
        }
        assert!(
            !r.admit_at(flood, 2, 2, now),
            "the flooding IP is now rejected"
        );
        // A different IP's bucket is untouched.
        assert!(
            r.admit_at(ip("9.9.9.9"), 2, 2, now),
            "a quiet IP is unaffected"
        );
    }

    #[test]
    fn ipv6_is_keyed_per_64() {
        let r = PerIpHandshakeRate::new();
        let now = Instant::now();
        // Two addresses in the same /64 share one bucket (capacity 1).
        assert!(r.admit_at(ip("2001:db8:abcd:1::1"), 10, 1, now));
        assert!(
            !r.admit_at(ip("2001:db8:abcd:1::2"), 10, 1, now),
            "same /64 must share the bucket"
        );
        // A different /64 is independent.
        assert!(
            r.admit_at(ip("2001:db8:abcd:2::1"), 10, 1, now),
            "a different /64 is its own bucket"
        );
        assert_eq!(r.tracked(), 2, "one bucket per /64, not per address");
    }

    #[test]
    fn a_refilled_bucket_is_swept_so_the_table_stays_bounded() {
        let r = PerIpHandshakeRate::new();
        let t0 = Instant::now();
        // One attempt from each of a few IPs: each bucket is now one token short of full.
        for n in 0..10u32 {
            let a = IpAddr::from([10, 0, 0, n as u8 + 1]);
            assert!(r.admit_at(a, 10, 10, t0));
        }
        assert_eq!(r.tracked(), 10);
        // retain() drops fully-refilled buckets; force it by calling it directly at a later time
        // when every bucket has refilled to capacity.
        let later = t0 + Duration::from_secs(5);
        r.buckets
            .retain(|_, b| b.tokens_at(later, 10.0, 10.0) < 10.0);
        assert_eq!(r.tracked(), 0, "idle, fully-refilled buckets are reclaimed");
    }
}
