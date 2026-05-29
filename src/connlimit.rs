// SPDX-License-Identifier: Apache-2.0
//! Per-IP concurrent-connection limiter — the connection-exhaustion lever.
//!
//! `rate_limit_rps` (see `security.rs`) caps how *often* a source may make
//! requests; this caps how many connections a single source IP may hold
//! open at the *same time*. That's the resource a slow / backed flood
//! actually exhausts — sockets and handshake state, not request frequency.
//! Enforced at accept, before the TLS handshake, so a rejected connection
//! costs one map probe and an immediate close.
//!
//! Cost model mirrors the rate limiter: a `DashMap<IpAddr, u32>` shard
//! lookup + increment on admit, decrement on drop (RAII). When the cap is
//! 0 (disabled, the default) `try_acquire` short-circuits before touching
//! the map — genuinely zero overhead.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Tracks live concurrent connections per source IP. Lives in `AppState`
/// across hot-reloads (it counts sockets, not config); the *cap* is read
/// from the config snapshot at each accept, so changing the limit takes
/// effect on new connections without disturbing live ones.
#[derive(Default)]
pub struct PerIpConnLimiter {
    counts: DashMap<IpAddr, u32>,
}

impl PerIpConnLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to admit a new connection from `ip` under `cap`
    /// (`0` = unlimited). Returns a [`ConnSlot`] guard that releases the
    /// slot when dropped, or `None` if `ip` already holds `cap` concurrent
    /// connections (caller should close the socket).
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr, cap: u32) -> Option<ConnSlot> {
        if cap == 0 {
            // Disabled — don't even touch the map.
            return Some(ConnSlot { limiter: None, ip });
        }
        // `entry` holds the shard write-lock for this key only while we
        // read-and-bump — no other lock is taken inside, so no deadlock.
        let mut count = self.counts.entry(ip).or_insert(0);
        if *count >= cap {
            return None;
        }
        *count += 1;
        Some(ConnSlot {
            limiter: Some(self.clone()),
            ip,
        })
    }

    /// Current number of distinct source IPs with at least one live
    /// connection. For metrics / introspection.
    #[allow(dead_code)]
    pub fn tracked_ips(&self) -> usize {
        self.counts.len()
    }

    fn release(&self, ip: IpAddr) {
        // Decrement under the entry guard, then drop it before any
        // `remove_if` (which needs the same shard lock — holding both
        // would deadlock).
        let now_zero = match self.counts.get_mut(&ip) {
            Some(mut count) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if now_zero {
            // Re-check under the removal path so we never evict an entry a
            // concurrent `try_acquire` just bumped back above zero.
            self.counts.remove_if(&ip, |_, &v| v == 0);
        }
    }
}

/// RAII slot: while held, one connection from `ip` is counted against the
/// per-IP cap. Dropped when the connection task ends (including on panic /
/// early return), releasing the slot.
pub struct ConnSlot {
    limiter: Option<Arc<PerIpConnLimiter>>,
    ip: IpAddr,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        if let Some(limiter) = &self.limiter {
            limiter.release(self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cap_zero_is_unlimited_and_untracked() {
        let l = Arc::new(PerIpConnLimiter::new());
        let a = ip("1.2.3.4");
        let _g1 = l.try_acquire(a, 0).unwrap();
        let _g2 = l.try_acquire(a, 0).unwrap();
        // Disabled cap must not allocate map entries.
        assert_eq!(l.tracked_ips(), 0);
    }

    #[test]
    fn enforces_cap_per_ip() {
        let l = Arc::new(PerIpConnLimiter::new());
        let a = ip("1.2.3.4");
        let g1 = l.try_acquire(a, 2);
        let g2 = l.try_acquire(a, 2);
        assert!(g1.is_some() && g2.is_some());
        // Third concurrent connection from the same IP is rejected.
        assert!(l.try_acquire(a, 2).is_none());
        // A different IP is unaffected.
        assert!(l.try_acquire(ip("5.6.7.8"), 2).is_some());
    }

    #[test]
    fn slot_release_frees_capacity() {
        let l = Arc::new(PerIpConnLimiter::new());
        let a = ip("1.2.3.4");
        let g1 = l.try_acquire(a, 1).unwrap();
        assert!(l.try_acquire(a, 1).is_none());
        drop(g1);
        // Slot freed → a new connection is admitted again, and the entry
        // is reclaimed when the count hits zero.
        let g2 = l.try_acquire(a, 1);
        assert!(g2.is_some());
        drop(g2);
        assert_eq!(l.tracked_ips(), 0);
    }

    #[test]
    fn ipv6_is_tracked_independently() {
        let l = Arc::new(PerIpConnLimiter::new());
        let v6 = ip("2001:db8::1");
        let _g = l.try_acquire(v6, 1).unwrap();
        assert!(l.try_acquire(v6, 1).is_none());
        assert!(l.try_acquire(ip("2001:db8::2"), 1).is_some());
    }
}
