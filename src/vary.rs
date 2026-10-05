// SPDX-License-Identifier: Apache-2.0
//! Secondary cache keys from the origin's `Vary` (RFC 9111 §4.1).
//!
//! A response that says `Vary: Accept-Language` is only valid for requests that send
//! the same `Accept-Language`. The cache stores it under its primary key plus the
//! values of the request headers the origin named, so each variant has its own entry
//! and one client can never be handed another's.
//!
//! What is deliberately NOT keyed, and stays uncacheable:
//!   * `Vary: *` (the origin says nothing about the request can be reused);
//!   * any varied credential header (`Cookie`, `Authorization`, …): such a response is
//!     per-user, and a shared cache must not hold a copy per session;
//!   * more than [`MAX_VARY_NAMES`] varied headers, or a varied request value longer
//!     than [`MAX_VALUE_LEN`].
//!
//! `Accept-Encoding` is already part of the primary key and is ignored here.
//!
//!
//! Header values are compared exactly (trimmed, repeated lines joined with `, `): two
//! requests share a variant only when the values are byte-identical. An absent header
//! and an empty one are different variants. Variants per primary key are capped at
//! [`MAX_VARIANTS_PER_KEY`], so a client cannot fill the cache by varying a header.

use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_VARY_NAMES: usize = 8;
pub const MAX_VALUE_LEN: usize = 256;
pub const MAX_VARIANTS_PER_KEY: usize = 16;

/// Headers whose presence in `Vary` makes a response per-user.
const CREDENTIAL_HEADERS: [&str; 4] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "set-cookie",
];

/// What a response's `Vary` means for storing it.
#[derive(Debug, PartialEq, Eq)]
pub enum VaryPolicy {
    /// No varied headers beyond `Accept-Encoding`: one entry under the primary key.
    None,
    /// Varies on these (lowercased, sorted, unique) request headers.
    Keyed(Vec<String>),
    /// Must not be stored.
    Uncacheable,
}

pub fn policy(resp_headers: &hyper::HeaderMap) -> VaryPolicy {
    let mut names: Vec<String> = Vec::new();
    for value in resp_headers.get_all(hyper::header::VARY) {
        let Ok(v) = value.to_str() else {
            return VaryPolicy::Uncacheable;
        };
        for tok in v.split(',') {
            let t = tok.trim().to_ascii_lowercase();
            if t.is_empty() || t == "accept-encoding" {
                continue;
            }
            if t == "*"
                || CREDENTIAL_HEADERS.contains(&t.as_str())
                || hyper::header::HeaderName::from_bytes(t.as_bytes()).is_err()
            {
                return VaryPolicy::Uncacheable;
            }
            names.push(t);
        }
    }
    names.sort();
    names.dedup();
    if names.is_empty() {
        VaryPolicy::None
    } else if names.len() > MAX_VARY_NAMES {
        VaryPolicy::Uncacheable
    } else {
        VaryPolicy::Keyed(names)
    }
}

/// The cache key of the variant of `primary` that `req` belongs to. `None` when a
/// varied value is too long to key on (the request then bypasses the cache).
/// `\x1e` and `\x1f` cannot occur in a header value, so two different
/// (names, values) combinations can never produce the same key.
pub fn variant_key(primary: &str, names: &[String], req: &hyper::HeaderMap) -> Option<String> {
    let mut k = String::with_capacity(primary.len() + 32 * names.len());
    k.push_str(primary);
    k.push('\x1e');
    for name in names {
        k.push_str(name);
        let mut values = req.get_all(name.as_str()).iter().peekable();
        if values.peek().is_none() {
            k.push('\0'); // absent: distinct from present-but-empty
        } else {
            k.push('=');
            let mut first = true;
            for v in values {
                let s = v.to_str().ok()?.trim();
                if !first {
                    k.push_str(", ");
                }
                first = false;
                k.push_str(s);
                if k.len() > primary.len() + MAX_VALUE_LEN * names.len() + 64 * names.len() {
                    return None;
                }
            }
        }
        k.push('\x1f');
    }
    Some(k)
}

/// What the cache remembers about a primary key whose responses vary.
pub struct VaryRule {
    pub names: Vec<String>,
    expires_at: Instant,
    variants: Mutex<HashSet<String>>,
}

impl VaryRule {
    /// Admit `variant` for storing: already known, or there is room for one more.
    pub fn admit(&self, variant: &str) -> bool {
        let mut set = self.variants.lock().unwrap_or_else(|e| e.into_inner());
        if set.contains(variant) {
            return true;
        }
        if set.len() >= MAX_VARIANTS_PER_KEY {
            return false;
        }
        set.insert(variant.to_string());
        true
    }
}

/// Primary key → the headers its responses vary on. Expires with the responses it
/// describes, and is bounded, so it cannot outgrow the cache it indexes.
pub struct VaryRules {
    map: DashMap<Arc<str>, Arc<VaryRule>>,
    /// The soonest expiry among the rules, in milliseconds since `epoch`: before it, a
    /// sweep of a full index can free nothing, and a new key is refused without looking at
    /// the index. Set by each sweep and lowered by each rule installed. `0` = unknown.
    soonest_expiry_ms: std::sync::atomic::AtomicU64,
    /// When the last sweep started (same clock); `0` = never.
    last_sweep_ms: std::sync::atomic::AtomicU64,
    epoch: Instant,
    /// Sweeps of the whole index so far.
    sweeps: std::sync::atomic::AtomicU64,
}

/// The least time between two sweeps of a full index. A sweep reads every rule and locks
/// every shard: which URLs miss the cache is the client's choice, so the sweep must not be
/// something each of them can trigger (#526).
const SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(1);

impl Default for VaryRules {
    fn default() -> Self {
        Self {
            map: DashMap::new(),
            soonest_expiry_ms: std::sync::atomic::AtomicU64::new(0),
            last_sweep_ms: std::sync::atomic::AtomicU64::new(0),
            epoch: Instant::now(),
            sweeps: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl VaryRules {
    pub fn get(&self, primary: &str) -> Option<Arc<VaryRule>> {
        let rule = self.map.get(primary)?.clone();
        if Instant::now() >= rule.expires_at {
            self.map.remove(primary);
            return None;
        }
        Some(rule)
    }

    /// Record that `primary`'s responses vary on `names`, for `ttl_secs`. Returns the
    /// live rule (the existing one when the names are unchanged, so its variant set
    /// survives), or `None` when the index is full.
    pub fn install(
        &self,
        primary: &str,
        names: Vec<String>,
        ttl_secs: u64,
        max_rules: usize,
    ) -> Option<Arc<VaryRule>> {
        if let Some(existing) = self.get(primary) {
            if existing.names == names {
                return Some(existing);
            }
        }
        if self.map.len() >= max_rules.max(1) && !self.make_room(max_rules.max(1)) {
            return None;
        }
        let rule = Arc::new(VaryRule {
            names,
            expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            variants: Mutex::new(HashSet::new()),
        });
        // A rule that expires before the soonest known one moves the next useful sweep up.
        let expires_ms = self.ms(rule.expires_at);
        let soonest = &self.soonest_expiry_ms;
        let mut known = soonest.load(std::sync::atomic::Ordering::Relaxed);
        while known != 0 && expires_ms < known {
            match soonest.compare_exchange_weak(
                known,
                expires_ms,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(now) => known = now,
            }
        }
        self.map.insert(Arc::from(primary), rule.clone());
        Some(rule)
    }

    /// Milliseconds since `epoch`, never `0` (which the atomics use for "not set").
    fn ms(&self, t: Instant) -> u64 {
        t.saturating_duration_since(self.epoch).as_millis() as u64 + 1
    }

    /// The index is full: drop the rules that have expired, if a sweep can free one and
    /// none ran in the last [`SWEEP_MIN_INTERVAL`]. `false` when there is still no room.
    /// When no sweep is due the answer costs two comparisons: before, every miss of a new
    /// varying URL swept the whole index, found the rules still alive, and was refused
    /// anyway.
    fn make_room(&self, max_rules: usize) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let now = Instant::now();
        let now_ms = self.ms(now);
        let last = self.last_sweep_ms.load(Relaxed);
        let too_soon = last != 0 && now_ms < last + SWEEP_MIN_INTERVAL.as_millis() as u64;
        if too_soon || now_ms < self.soonest_expiry_ms.load(Relaxed) {
            return false;
        }
        // One thread sweeps; the others see that a sweep has just started.
        if self
            .last_sweep_ms
            .compare_exchange(last, now_ms, Relaxed, Relaxed)
            .is_err()
        {
            return false;
        }
        self.sweeps.fetch_add(1, Relaxed);
        let mut soonest: Option<Instant> = None;
        self.map.retain(|_, r| {
            let live = now < r.expires_at;
            if live {
                soonest = Some(soonest.map_or(r.expires_at, |s| s.min(r.expires_at)));
            }
            live
        });
        self.soonest_expiry_ms
            .store(soonest.map_or(0, |s| self.ms(s)), Relaxed);
        self.map.len() < max_rules
    }

    pub fn remove(&self, primary: &str) {
        self.map.remove(primary);
    }

    pub fn clear(&self) {
        self.map.clear();
    }

    pub fn remove_prefix(&self, prefix: &str) {
        self.map.retain(|k, _| !k.starts_with(prefix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};

    fn resp(vary: &[&str]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for v in vary {
            h.append(hyper::header::VARY, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn req(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn policy_classifies_vary() {
        assert_eq!(policy(&resp(&[])), VaryPolicy::None);
        assert_eq!(policy(&resp(&["Accept-Encoding"])), VaryPolicy::None);
        assert_eq!(
            policy(&resp(&["accept-encoding, ACCEPT-ENCODING"])),
            VaryPolicy::None
        );
        assert_eq!(
            policy(&resp(&["Accept-Language, accept"])),
            VaryPolicy::Keyed(vec!["accept".into(), "accept-language".into()])
        );
        // repeated Vary lines are merged, duplicates dropped, order irrelevant
        assert_eq!(
            policy(&resp(&["Origin", "origin, Accept-Encoding"])),
            VaryPolicy::Keyed(vec!["origin".into()])
        );
        for bad in [
            "*",
            "Cookie",
            "Accept-Language, Authorization",
            "proxy-authorization",
            "x-a, *",
        ] {
            assert_eq!(policy(&resp(&[bad])), VaryPolicy::Uncacheable, "{bad}");
        }
        let many = (0..=MAX_VARY_NAMES)
            .map(|i| format!("x-h{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            policy(&resp(&[&many])),
            VaryPolicy::Uncacheable,
            "too many names"
        );
        assert_eq!(
            policy(&resp(&["bad name"])),
            VaryPolicy::Uncacheable,
            "not a header name"
        );
    }

    #[test]
    fn variant_key_separates_what_must_be_separate() {
        let n = vec!["accept-language".to_string()];
        let k = |pairs: &[(&str, &str)]| variant_key("/p", &n, &req(pairs)).unwrap();
        assert_ne!(
            k(&[("accept-language", "de")]),
            k(&[("accept-language", "fr")])
        );
        assert_ne!(k(&[]), k(&[("accept-language", "")]), "absent is not empty");
        assert_eq!(
            k(&[("accept-language", "de")]),
            k(&[("accept-language", " de ")]),
            "trimmed"
        );
        assert_ne!(
            k(&[("accept-language", "de")]),
            k(&[("accept-language", "DE")]),
            "exact, not folded"
        );
        // a different primary key never shares a variant
        assert_ne!(
            variant_key("/p", &n, &req(&[])).unwrap(),
            variant_key("/q", &n, &req(&[])).unwrap()
        );
        // repeated header lines are one joined value, in order
        let two = variant_key(
            "/p",
            &n,
            &req(&[("accept-language", "de"), ("accept-language", "fr")]),
        )
        .unwrap();
        let one = variant_key("/p", &n, &req(&[("accept-language", "de, fr")])).unwrap();
        assert_eq!(two, one);
    }

    #[test]
    fn variant_key_cannot_be_forged_by_splitting_values() {
        // two headers whose values could be confused if joined naively
        let n = vec!["x-a".to_string(), "x-b".to_string()];
        let a = variant_key("/p", &n, &req(&[("x-a", "1=2"), ("x-b", "3")])).unwrap();
        let b = variant_key("/p", &n, &req(&[("x-a", "1"), ("x-b", "2=3")])).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn overlong_values_are_not_keyed() {
        let n = vec!["x-a".to_string()];
        let long = "a".repeat(MAX_VALUE_LEN + 200);
        assert!(variant_key("/p", &n, &req(&[("x-a", &long)])).is_none());
    }

    fn sweeps(rules: &VaryRules) -> u64 {
        rules.sweeps.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// #526: with the index full of rules that are still alive, each new varying URL used
    /// to sweep the whole index (every shard locked) and be refused anyway. Which URLs
    /// miss is the client's choice. Now the first one sweeps and the rest are refused for
    /// the price of a comparison.
    #[test]
    fn a_full_index_of_live_rules_refuses_without_sweeping_each_time() {
        let rules = VaryRules::default();
        for i in 0..500 {
            assert!(rules
                .install(&format!("/p{i}"), vec!["x-a".into()], 600, 500)
                .is_some());
        }
        assert_eq!(sweeps(&rules), 0, "no sweep while there is room");
        for i in 0..10_000 {
            assert!(
                rules
                    .install(&format!("/new{i}"), vec!["x-a".into()], 600, 500)
                    .is_none(),
                "full of live rules: refused"
            );
        }
        assert_eq!(sweeps(&rules), 1, "one sweep for 10,000 refusals");
        assert_eq!(rules.map.len(), 500);
        // A key that has its rule is not affected by any of this.
        assert!(rules.install("/p7", vec!["x-a".into()], 600, 500).is_some());
        assert!(rules.get("/p7").is_some());
    }

    #[test]
    fn expired_rules_make_room_for_new_ones() {
        let rules = VaryRules::default();
        rules.install("/gone", vec!["x-a".into()], 0, 3).unwrap(); // expires at once
        rules.install("/b", vec!["x-a".into()], 600, 3).unwrap();
        rules.install("/c", vec!["x-a".into()], 600, 3).unwrap();
        // (`map.len()`, not `get`: `get` would drop the expired rule itself)
        assert_eq!(rules.map.len(), 3);
        assert!(
            rules.install("/d", vec!["x-a".into()], 600, 3).is_some(),
            "the expired rule was swept and its place taken"
        );
        assert_eq!(sweeps(&rules), 1);
        assert!(rules.map.get("/gone").is_none());
        assert_eq!(rules.map.len(), 3);
    }

    /// The refusal is cheap only until a sweep could free something. A rule that expires
    /// soon, installed after the last sweep, must bring the next sweep forward: or the
    /// index would stay full of nothing for as long as its longest-lived rules.
    #[test]
    fn a_rule_about_to_expire_is_swept_when_it_does_not_an_hour_later() {
        let rules = VaryRules::default();
        for i in 0..3 {
            rules
                .install(&format!("/long{i}"), vec!["x-a".into()], 3_600, 3)
                .unwrap();
        }
        assert!(rules.install("/x", vec!["x-a".into()], 3_600, 3).is_none());
        assert_eq!(
            sweeps(&rules),
            1,
            "swept once: the soonest expiry is an hour away"
        );
        // One long-lived rule goes (a purge), and a rule that lives one second takes its place.
        rules.remove("/long0");
        rules.install("/short", vec!["x-a".into()], 1, 3).unwrap();
        assert!(
            rules.install("/y", vec!["x-a".into()], 3_600, 3).is_none(),
            "full"
        );
        assert_eq!(sweeps(&rules), 1, "and nothing to sweep yet");
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(
            rules.install("/y", vec!["x-a".into()], 3_600, 3).is_some(),
            "the short-lived rule expired: swept, and its place taken"
        );
        assert_eq!(sweeps(&rules), 2);
        assert!(rules.map.get("/short").is_none());
    }

    /// A second later nothing has changed: the rules all live for an hour, and a sweep that
    /// can free nothing is not run just because one is allowed.
    #[test]
    fn a_full_index_is_not_swept_again_before_a_rule_can_have_expired() {
        let rules = VaryRules::default();
        for i in 0..20 {
            rules
                .install(&format!("/p{i}"), vec!["x-a".into()], 3_600, 20)
                .unwrap();
        }
        assert!(rules.install("/x", vec!["x-a".into()], 3_600, 20).is_none());
        assert_eq!(sweeps(&rules), 1);
        std::thread::sleep(SWEEP_MIN_INTERVAL + Duration::from_millis(100));
        assert!(rules.install("/x", vec!["x-a".into()], 3_600, 20).is_none());
        assert_eq!(sweeps(&rules), 1, "nothing could have expired: no sweep");
    }

    /// And when rules expire one after the other, the sweeps are spaced: not one per rule.
    #[test]
    fn sweeps_are_at_least_a_second_apart() {
        let rules = VaryRules::default();
        for i in 0..50 {
            rules
                .install(&format!("/p{i}"), vec!["x-a".into()], 600, 50)
                .unwrap();
        }
        assert!(rules.install("/x", vec!["x-a".into()], 600, 50).is_none());
        assert_eq!(sweeps(&rules), 1);
        // Rules that expire at once keep arriving in freed places; the index is full of
        // expired rules again and again within the same second.
        for round in 0..20 {
            rules.remove(&format!("/p{round}"));
            rules
                .install(&format!("/e{round}"), vec!["x-a".into()], 0, 50)
                .unwrap();
            let _ = rules.install(&format!("/n{round}"), vec!["x-a".into()], 600, 50);
        }
        assert_eq!(sweeps(&rules), 1, "no second sweep within the interval");
        std::thread::sleep(SWEEP_MIN_INTERVAL + Duration::from_millis(100));
        assert!(rules
            .install("/after", vec!["x-a".into()], 600, 50)
            .is_some());
        assert_eq!(sweeps(&rules), 2);
    }

    #[test]
    fn rules_admit_a_bounded_number_of_variants_and_expire() {
        let rules = VaryRules::default();
        let rule = rules.install("/p", vec!["x-a".into()], 60, 10).unwrap();
        for i in 0..MAX_VARIANTS_PER_KEY {
            assert!(rule.admit(&format!("v{i}")));
        }
        assert!(!rule.admit("one-too-many"), "variant cap");
        assert!(rule.admit("v0"), "a known variant is always admitted");
        // same names → same rule (variant set preserved); new names → a fresh rule
        assert!(Arc::ptr_eq(
            &rule,
            &rules.install("/p", vec!["x-a".into()], 60, 10).unwrap()
        ));
        let fresh = rules.install("/p", vec!["x-b".into()], 60, 10).unwrap();
        assert!(!Arc::ptr_eq(&rule, &fresh));
        assert!(fresh.admit("new"));
        // bounded index
        assert!(rules.install("/q", vec!["x-a".into()], 60, 2).is_some());
        assert!(
            rules.install("/r", vec!["x-a".into()], 60, 2).is_none(),
            "index full"
        );
        // expiry
        let short = VaryRules::default();
        short.install("/p", vec!["x-a".into()], 0, 10).unwrap();
        assert!(short.get("/p").is_none(), "an expired rule is gone");
    }

    #[test]
    fn prefix_and_clear_remove_rules() {
        let rules = VaryRules::default();
        rules.install("/a/1", vec!["x-a".into()], 60, 10).unwrap();
        rules.install("/b/1", vec!["x-a".into()], 60, 10).unwrap();
        rules.remove_prefix("/a");
        assert!(rules.get("/a/1").is_none() && rules.get("/b/1").is_some());
        rules.clear();
        assert!(rules.get("/b/1").is_none());
    }
}
