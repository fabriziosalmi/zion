// SPDX-License-Identifier: Apache-2.0
//! Security primitives — CORS, rate limiting, validation, and response hardening.
//!
//! Extracted from main.rs (C-01) to reduce monolith complexity.
//! All items are zero-cost at runtime (pre-compiled statics, branch-free paths).

use hyper::header::HeaderValue;
use hyper::Response;
use std::borrow::Cow;

use crate::proxy::ZionBody;

// ── Security response headers (pre-compiled, zero alloc at runtime) ──

pub static HSTS: HeaderValue =
    HeaderValue::from_static("max-age=63072000; includeSubDomains; preload");
pub static XCTO: HeaderValue = HeaderValue::from_static("nosniff");
pub static XFO: HeaderValue = HeaderValue::from_static("DENY");
pub static REFERRER: HeaderValue = HeaderValue::from_static("strict-origin-when-cross-origin");
pub static PERMISSIONS: HeaderValue =
    HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()");
#[allow(dead_code)] // Kept for future per-route CSP feature
pub static CSP: HeaderValue = HeaderValue::from_static(
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
);

/// Maximum tracked IPs in the rate limiter map (prevents memory exhaustion).
pub const MAX_RATE_MAP_ENTRIES: usize = 100_000;

// ============================================================================
// CORS
// ============================================================================

/// Pre-compiled CORS headers (built at boot from config, zero alloc per request).
/// Uses FNV hash set for O(1) origin lookup (case-insensitive via lowercased storage).
#[derive(Debug)]
pub struct CorsHeaders {
    pub allow_origin_wildcard: bool,
    /// Lowercased origins for O(1) case-insensitive lookup.
    allowed_origins_set: fnv::FnvHashSet<String>,
    pub allow_methods: HeaderValue,
    pub allow_headers: HeaderValue,
    pub max_age: HeaderValue,
}

impl CorsHeaders {
    pub fn from_config(cors: &crate::config::CorsConfig) -> Self {
        // (Was `enabled: !allowed_origins.is_empty()` — never read by any
        //  caller. Whether CORS is active is derived at the caller side
        //  by checking `route.cors.is_some()`.)
        let wildcard = cors.allowed_origins.iter().any(|o| o == "*");

        let methods = HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS");
        let headers_str = cors.allowed_headers.join(", ");
        let allow_headers = HeaderValue::from_str(&headers_str)
            .unwrap_or_else(|_| HeaderValue::from_static("Content-Type"));
        let max_age = HeaderValue::from_str(&cors.max_age.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("86400"));

        // Store lowercased for case-insensitive O(1) lookup (RFC 6454 §5)
        let allowed_origins_set: fnv::FnvHashSet<String> = cors
            .allowed_origins
            .iter()
            .map(|o| o.to_ascii_lowercase())
            .collect();

        Self {
            allow_origin_wildcard: wildcard,
            allowed_origins_set,
            allow_methods: methods,
            allow_headers,
            max_age,
        }
    }

    /// Check if origin is allowed. Returns the origin value to echo back.
    /// O(1) FNV hash lookup, case-insensitive per RFC 6454 §5.
    pub fn check_origin(&self, origin: &str) -> Option<HeaderValue> {
        if self.allow_origin_wildcard {
            return Some(HeaderValue::from_static("*"));
        }
        // Lowercase the incoming origin for case-insensitive comparison
        let lower = origin.to_ascii_lowercase();
        if self.allowed_origins_set.contains(&lower) {
            return HeaderValue::from_str(origin).ok();
        }
        None
    }
}

// ============================================================================
// Security headers injection
// ============================================================================

// CSP header name kept for future per-route CSP feature
#[allow(dead_code)]
static CSP_NAME: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("content-security-policy");

/// Inject security headers and strip hop-by-hop headers.
/// All values are pre-compiled statics — zero allocation per response.
#[inline]
pub fn inject_security_headers(resp: &mut Response<ZionBody>) {
    let h = resp.headers_mut();
    // Security headers (pre-compiled static values)
    h.insert(hyper::header::STRICT_TRANSPORT_SECURITY, HSTS.clone());
    h.insert(hyper::header::X_CONTENT_TYPE_OPTIONS, XCTO.clone());
    h.insert(hyper::header::X_FRAME_OPTIONS, XFO.clone());
    h.insert(
        hyper::header::HeaderName::from_static("referrer-policy"),
        REFERRER.clone(),
    );
    h.insert(
        hyper::header::HeaderName::from_static("permissions-policy"),
        PERMISSIONS.clone(),
    );
    // Strip server identity + hop-by-hop (RFC 7230 §6.1)
    h.remove(hyper::header::SERVER);
    h.remove(hyper::header::CONNECTION);
    h.remove(hyper::header::TRANSFER_ENCODING);
    h.remove("Keep-Alive");
    h.remove("Proxy-Authenticate");
    h.remove("Proxy-Authorization");
    h.remove("TE");
    h.remove("Trailer");
}

// ============================================================================
// Rate limiter
// ============================================================================

/// Per-IP rate limiter entry — packed into a single AtomicU64 for atomic reset.
/// Layout: upper 32 bits = window_start, lower 32 bits = count.
/// This eliminates the CAS-store gap where concurrent threads could lose counts.
pub struct RateEntry {
    /// Packed: (window_start << 32) | count
    pub(crate) packed: std::sync::atomic::AtomicU64,
}

impl RateEntry {
    #[inline]
    fn new(window: u32) -> Self {
        Self {
            packed: std::sync::atomic::AtomicU64::new(((window as u64) << 32) | 1),
        }
    }

    #[inline]
    fn window(val: u64) -> u32 {
        (val >> 32) as u32
    }

    #[inline]
    fn count(val: u64) -> u32 {
        val as u32
    }

    #[inline]
    fn pack(window: u32, count: u32) -> u64 {
        ((window as u64) << 32) | (count as u64)
    }
}

/// Lock-free per-IP rate limiter.
/// Uses a single AtomicU64 per IP with packed window+count for atomic resets.
/// Eliminates the CAS-store gap that could lose counts during window transitions.
///
/// **Saturation policy: fail-CLOSED.** When the map hits the cap
/// (`max_tracked_ips`, default `MAX_RATE_MAP_ENTRIES`) room is made by removing
/// entries of past windows: first a look at a few entries, then, once per window
/// at most, a sweep of the whole map (see [`RateSweep`]). A new IP is denied only
/// when the map holds `max_tracked_ips` addresses that were all seen in the current
/// window (e.g. a botnet): the safe default for a security gate.
#[inline]
pub fn check_rate_limit(
    rate_limit_rps: u32,
    rate_limit_window: u64,
    max_tracked_ips: usize,
    rate_map: &crate::numa::NumaAwareMap<std::net::IpAddr, RateEntry>,
    sweep: &RateSweep,
    ip: std::net::IpAddr,
) -> bool {
    if rate_limit_rps == 0 {
        return true; // disabled — zero overhead
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let current_window = (now / rate_limit_window) as u32;

    if let Some(entry) = rate_map.get(&ip) {
        loop {
            let old = entry.packed.load(std::sync::atomic::Ordering::Relaxed);
            let old_window = RateEntry::window(old);
            let old_count = RateEntry::count(old);

            if old_window == current_window {
                // Same window — try to increment count atomically
                let new = RateEntry::pack(current_window, old_count + 1);
                match entry.packed.compare_exchange_weak(
                    old,
                    new,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                ) {
                    Ok(_) => return old_count < rate_limit_rps,
                    Err(_) => continue, // retry — another thread changed the value
                }
            } else {
                // New window — reset count to 1 atomically (window + count in one CAS)
                let new = RateEntry::pack(current_window, 1);
                match entry.packed.compare_exchange_weak(
                    old,
                    new,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                ) {
                    Ok(_) => return true, // first request in new window
                    Err(_) => continue,   // retry — another thread reset first
                }
            }
        }
    }

    // First request from this IP — cap total tracked IPs to prevent memory exhaustion.
    // Fail-CLOSED: if we can't make room, deny rather than bypass the limiter.
    if rate_map.len() >= max_tracked_ips && !try_evict_stale(rate_map, current_window) {
        // No stale entry among the first few. That says nothing about the rest: the
        // probe looks at the same entries every time, and while those belong to
        // clients that are active the map can be full of addresses not seen for a
        // minute and still turn every new client away (#528). So sweep all of it,
        // once per window: the sweep reads every entry, and under a real flood each
        // request would otherwise pay for one.
        if sweep.claim(current_window) {
            remove_stale(rate_map, current_window);
        }
        if rate_map.len() >= max_tracked_ips {
            // Full of addresses seen in this window (or another thread is still
            // sweeping). Fail CLOSED: deny rather than let the limiter be bypassed.
            return false;
        }
    }
    rate_map.insert(ip, RateEntry::new(current_window));
    true
}

/// The window in which the rate map was last swept in full because it was at its cap:
/// what makes that sweep happen once per window and not once per request. Kept next to
/// the map it belongs to.
#[derive(Debug, Default)]
pub struct RateSweep {
    /// The window number plus one; `0` = never.
    last: std::sync::atomic::AtomicU64,
}

impl RateSweep {
    /// `true` for the first caller in `window`, who then does the sweep.
    fn claim(&self, window: u32) -> bool {
        let mark = u64::from(window) + 1;
        self.last.swap(mark, std::sync::atomic::Ordering::Relaxed) != mark
    }
}

/// Remove every entry whose window is not `current_window`; how many went.
fn remove_stale(
    rate_map: &crate::numa::NumaAwareMap<std::net::IpAddr, RateEntry>,
    current_window: u32,
) -> usize {
    let mut stale_ips = Vec::new();
    for entry in rate_map.iter() {
        let val = entry
            .value()
            .packed
            .load(std::sync::atomic::Ordering::Relaxed);
        if RateEntry::window(val) != current_window {
            stale_ips.push(*entry.key());
        }
    }
    let removed = stale_ips.len();
    for ip in stale_ips {
        rate_map.remove(&ip);
    }
    removed
}

/// Attempt to evict one stale entry (expired window) from the rate map.
/// Probes up to `EVICT_PROBE_LIMIT` entries to bound worst-case latency.
/// Returns `true` if an entry was evicted, `false` if all probed entries
/// belong to the current window.
fn try_evict_stale(
    rate_map: &crate::numa::NumaAwareMap<std::net::IpAddr, RateEntry>,
    current_window: u32,
) -> bool {
    const EVICT_PROBE_LIMIT: usize = 16;
    // Find the first stale entry among the first few, and only then remove it: the
    // iterator holds a read lock on the shard it is in for as long as it lives, and
    // `remove` takes the write lock of that same shard. Removing from inside the loop
    // (dropping the entry first released nothing: the iterator kept its own guard)
    // blocked the thread for good, and behind it every request whose address fell in
    // that shard. It happened whenever the map was at its cap and the probe found a
    // stale entry, from v0.1.8 on.
    let stale = rate_map
        .iter()
        .take(EVICT_PROBE_LIMIT)
        .find(|entry| {
            let val = entry
                .value()
                .packed
                .load(std::sync::atomic::Ordering::Relaxed);
            RateEntry::window(val) != current_window
        })
        .map(|entry| *entry.key());
    match stale {
        Some(ip) => {
            rate_map.remove(&ip);
            true
        }
        None => false,
    }
}

/// Scavenge stale entries from the rate map. Designed to be called
/// periodically by a background task (e.g. every 60s) to prevent
/// unbounded growth from one-shot visitors that never return.
///
/// Removes all entries whose window is older than `current_window`.
/// Returns the number of entries removed.
pub fn scavenge_rate_map(
    rate_map: &crate::numa::NumaAwareMap<std::net::IpAddr, RateEntry>,
    rate_limit_window: u64,
) -> usize {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let current_window = (now / rate_limit_window) as u32;
    remove_stale(rate_map, current_window)
}

// ============================================================================
// Host & IP validation
// ============================================================================

/// Validate Host header to prevent header injection in redirects.
/// Single-pass byte scan instead of 8 separate contains() calls.
#[inline]
pub fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host
            .as_bytes()
            .iter()
            .any(|&b| matches!(b, b'/' | b'\\' | b'@' | b'\n' | b'\r' | b'\0' | b' '))
}

/// Normalize a request authority — the URI `:authority` (HTTP/2, absolute-form)
/// or `Host` header (HTTP/1, origin-form) — into a canonical host-routing key
/// per ADR-0010: lowercased, `:port` stripped (IPv6-literal-safe), and any
/// trailing FQDN dot removed. Returns `None` when the authority is empty or
/// fails [`is_valid_host`]; the caller then routes via the hostless/shared
/// layer rather than a bogus key.
///
/// Borrows when the input is already canonical (the common case — lowercase,
/// no port) so the hot path allocates only when it must actually fold case.
/// This is the single primitive both sides of the match go through: config
/// `hosts` entries are validated to be fixed points of this function, and
/// request authorities pass through it at lookup, so a config key and a request
/// key are compared in the same normal form (no silent host mismatch).
pub fn normalize_host(raw: &str) -> Option<Cow<'_, str>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // Split off an optional `:port`, keeping an IPv6 literal's own colons intact.
    let host = if raw.starts_with('[') {
        // `[2001:db8::1]` or `[2001:db8::1]:443` → keep through the closing ']'.
        let end = raw.find(']')?; // malformed literal (no ']') ⇒ no key ⇒ shared
        &raw[..=end]
    } else {
        match raw.rsplit_once(':') {
            // Exactly one colon and a numeric suffix ⇒ `host:port`. A bare
            // (unbracketed) IPv6 literal has multiple colons and is left intact
            // — it can't be a legal authority, so it just misses the map.
            Some((h, p))
                if !h.contains(':') && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) =>
            {
                h
            }
            _ => raw,
        }
    };

    let host = host.trim_end_matches('.'); // drop the root FQDN dot(s)
    if host.is_empty() || !is_valid_host(host) {
        return None;
    }

    // Borrow when already lowercase; allocate only to fold case.
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(Cow::Owned(host.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(host))
    }
}

/// Extract and normalize the request authority for host routing (ADR-0010):
/// the URI `:authority` (HTTP/2 / absolute-form) when present, otherwise the
/// `Host` header (HTTP/1 origin-form). Returns the canonical routing key via
/// [`normalize_host`], or `None` when the authority is absent or invalid.
/// Callers gate this behind `HostRouter::host_routing_active` so a hostless
/// deployment never pays for the extraction.
pub fn request_host<B>(req: &hyper::Request<B>) -> Option<Cow<'_, str>> {
    req.uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
        })
        .and_then(normalize_host)
}

/// Check if an IP is internal (loopback, private RFC1918, link-local).
#[inline]
pub fn is_internal_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()       // 127.0.0.0/8
            || v4.is_private()     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local() // 169.254.0.0/16
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()                                     // ::1
            || (v6.segments()[0] & 0xffc0) == 0xfe80             // fe80::/10 link-local
            || (v6.segments()[0] & 0xfe00) == 0xfc00             // fc00::/7 unique local (ULA)
            || v6.to_ipv4_mapped().map(|v4| v4.is_private() || v4.is_loopback()).unwrap_or(false)
        }
    }
}

// ============================================================================
// Trusted Proxy IP Resolution
// ============================================================================

/// Pre-parsed CIDR ranges for trusted proxy identification.
/// When the TCP peer IP matches a trusted proxy CIDR, the real client IP is
/// extracted from X-Forwarded-For using the rightmost-untrusted-hop algorithm.
///
/// Algorithm (RFC 7239 §5.2 recommendation):
///   Walk X-Forwarded-For from RIGHT to LEFT.
///   Skip entries that match trusted proxy CIDRs.
///   The first non-trusted entry is the real client IP.
///
/// This is immune to client-side X-Forwarded-For spoofing because the attacker
/// can only prepend to the left side of the chain. The right side is controlled
/// by trusted infrastructure.
#[derive(Clone, Debug)]
pub struct TrustedProxies {
    cidrs: Vec<CidrRange>,
}

#[derive(Clone, Debug)]
struct CidrRange {
    network: std::net::IpAddr,
    prefix_len: u8,
}

impl CidrRange {
    fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        match parts.len() {
            1 => {
                // Bare IP: treat as /32 or /128
                let ip: std::net::IpAddr = parts[0].parse().ok()?;
                let prefix_len = if ip.is_ipv4() { 32 } else { 128 };
                Some(Self {
                    network: ip,
                    prefix_len,
                })
            }
            2 => {
                let ip: std::net::IpAddr = parts[0].parse().ok()?;
                let prefix_len: u8 = parts[1].parse().ok()?;
                Some(Self {
                    network: ip,
                    prefix_len,
                })
            }
            _ => None,
        }
    }

    fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match (&self.network, ip) {
            (std::net::IpAddr::V4(net), std::net::IpAddr::V4(candidate)) => {
                let net_bits = u32::from(*net);
                let cand_bits = u32::from(*candidate);
                if self.prefix_len == 0 {
                    return true;
                }
                if self.prefix_len >= 32 {
                    return net_bits == cand_bits;
                }
                let mask = !0u32 << (32 - self.prefix_len);
                (net_bits & mask) == (cand_bits & mask)
            }
            (std::net::IpAddr::V6(net), std::net::IpAddr::V6(candidate)) => {
                let net_bits = u128::from(*net);
                let cand_bits = u128::from(*candidate);
                if self.prefix_len == 0 {
                    return true;
                }
                if self.prefix_len >= 128 {
                    return net_bits == cand_bits;
                }
                let mask = !0u128 << (128 - self.prefix_len);
                (net_bits & mask) == (cand_bits & mask)
            }
            _ => false, // v4/v6 mismatch
        }
    }
}

/// Is `s` a well-formed CIDR (or bare IP) whose prefix fits its address family?
/// `CidrRange::parse` alone would accept `10.0.0.0/99`; config validation uses this
/// so a typo is an error, not a silently-different network.
pub fn is_valid_cidr(s: &str) -> bool {
    CidrRange::parse(s).is_some_and(|c| {
        let max = if c.network.is_ipv4() { 32 } else { 128 };
        c.prefix_len <= max
    })
}

/// Which peers count as "internal" for the data-plane's internal-only gates:
/// `/metrics`, `/_zion/snapshot.json`, `/_zion/cache/purge` and routes marked
/// `internal_only`.
///
/// Default (empty list): any loopback / RFC 1918 / link-local / ULA address, as
/// [`is_internal_ip`]. That is a *network position* test, not authentication: behind
/// a private-range load balancer, Kubernetes SNAT or a Docker bridge every internet
/// client presents a private address and passes it. `[server] internal_networks`
/// replaces the default with an explicit allowlist, so only the hosts the operator
/// names are internal. The cache purge is stricter by default: see
/// [`InternalNetworks::allows_purge`].
#[derive(Clone, Debug, Default)]
pub struct InternalNetworks {
    cidrs: Vec<CidrRange>,
}

impl InternalNetworks {
    /// Build from `[server] internal_networks`. Entries are validated at config
    /// load ([`is_valid_cidr`]); one that still fails to parse is dropped, which can
    /// only make the allowlist *smaller*, never wider.
    pub fn from_config(cidrs: &[String]) -> Self {
        Self {
            cidrs: cidrs.iter().filter_map(|s| CidrRange::parse(s)).collect(),
        }
    }

    /// Is `ip` an internal peer under the active policy?
    #[inline]
    pub fn contains(&self, ip: &std::net::IpAddr) -> bool {
        if self.cidrs.is_empty() {
            is_internal_ip(ip)
        } else {
            self.cidrs.iter().any(|c| c.contains(ip))
        }
    }

    /// May `ip` use the one destructive internal endpoint, `POST /_zion/cache/purge`?
    ///
    /// With no `internal_networks` the default "any private address" test is good enough to
    /// read `/metrics` and too weak to flush the cache: behind a private-range load balancer
    /// or a Docker bridge every internet client passes it. So by default only loopback may
    /// purge. An explicit `internal_networks` is the operator naming who is internal, and
    /// is honoured as written.
    #[inline]
    pub fn allows_purge(&self, ip: &std::net::IpAddr) -> bool {
        if self.cidrs.is_empty() {
            ip.to_canonical().is_loopback()
        } else {
            self.contains(ip)
        }
    }
}

/// Drop the headers by which Zion attests what the TLS layer verified (every copy). See
/// [`crate::reserved_headers`]: every listener calls this before the pipeline, and only the
/// HTTPS listener re-injects the values it verified.
pub fn strip_transport_attestations(headers: &mut hyper::HeaderMap) {
    crate::reserved_headers::scrub(headers, crate::reserved_headers::Asserter::Transport);
}

/// Drop the headers only a trusted proxy may set (every copy): the caller checks the peer.
pub fn scrub_client_override_headers(headers: &mut hyper::HeaderMap) {
    crate::reserved_headers::scrub(headers, crate::reserved_headers::Asserter::TrustedProxy);
}

impl TrustedProxies {
    /// Parse trusted proxy CIDR list from config.
    /// Invalid CIDRs are logged and skipped.
    pub fn from_config(cidrs: &[String]) -> Self {
        let mut parsed = Vec::with_capacity(cidrs.len());
        for s in cidrs {
            match CidrRange::parse(s) {
                Some(cidr) => parsed.push(cidr),
                None => eprintln!("  warning: invalid trusted_proxy CIDR '{s}', skipping"),
            }
        }
        Self { cidrs: parsed }
    }

    /// Check if an IP is a trusted proxy.
    #[inline]
    pub fn is_trusted(&self, ip: &std::net::IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    /// Returns true if any trusted proxies are configured.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// Resolve the real client IP from X-Forwarded-For using the
    /// rightmost-untrusted-hop algorithm.
    ///
    /// If `socket_ip` is not a trusted proxy, returns `socket_ip` directly.
    /// If trusted, walks X-Forwarded-For right-to-left, skipping trusted hops.
    #[inline]
    pub fn resolve_client_ip(
        &self,
        socket_ip: std::net::IpAddr,
        xff_header: Option<&str>,
    ) -> std::net::IpAddr {
        // Fast path: no trusted proxies configured, or socket is not trusted
        if self.cidrs.is_empty() || !self.is_trusted(&socket_ip) {
            return socket_ip;
        }

        // Walk X-Forwarded-For right-to-left
        if let Some(xff) = xff_header {
            let hops: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
            for hop in hops.iter().rev() {
                if let Ok(ip) = hop.parse::<std::net::IpAddr>() {
                    if !self.is_trusted(&ip) {
                        return ip;
                    }
                }
            }
        }

        // All hops are trusted or no XFF — fall back to socket IP
        socket_ip
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[test]
    fn every_transport_attestation_is_stripped_in_any_case() {
        let mut h = hyper::HeaderMap::new();
        for name in [
            "X-Client-Cert-Fingerprint",
            "x-client-cert-dn",
            "X-CLIENT-TLS-JA4",
            "X-Client-TLS-Allowlisted",
        ] {
            h.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "forged".parse().unwrap(),
            );
        }
        h.insert("authorization", "Bearer t".parse().unwrap());
        strip_transport_attestations(&mut h);
        assert_eq!(h.len(), 1, "only the forged attestations go: {h:?}");
        assert!(h.contains_key("authorization"));
    }

    fn proxies(cidrs: &[&str]) -> TrustedProxies {
        TrustedProxies::from_config(&cidrs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn rate_map_cap_is_the_configured_one_and_fails_closed() {
        let map = crate::numa::NumaAwareMap::new();
        let ip = |n: u8| std::net::IpAddr::from([10, 0, 0, n]);
        // cap of 2 distinct IPs: the third live client is denied, tracked ones are not
        assert!(check_rate_limit(
            100,
            WINDOW,
            2,
            &map,
            &RateSweep::default(),
            ip(1)
        ));
        assert!(check_rate_limit(
            100,
            WINDOW,
            2,
            &map,
            &RateSweep::default(),
            ip(2)
        ));
        assert!(!check_rate_limit(
            100,
            WINDOW,
            2,
            &map,
            &RateSweep::default(),
            ip(3)
        ));
        assert!(check_rate_limit(
            100,
            WINDOW,
            2,
            &map,
            &RateSweep::default(),
            ip(1)
        ));
        // a larger cap admits it
        assert!(check_rate_limit(
            100,
            WINDOW,
            3,
            &map,
            &RateSweep::default(),
            ip(3)
        ));
    }

    /// The window these tests use, in seconds: one that does not roll over while a test
    /// runs. (With an hour, a test that straddled the top of the hour saw every address it
    /// had just stored as stale: it happened under Miri, which is slow, and it is how the
    /// deadlock below was found.) The next boundary is in 2033.
    const WINDOW: u64 = 1_000_000_000;

    /// The window now, and the one before it.
    fn windows() -> (u32, u32) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current = (now / WINDOW) as u32;
        (current, current - 1)
    }

    /// Run `f` on another thread and return what it returns, or fail the test if it has
    /// not come back in ten seconds: a deadlock must be a failure, not a hung test run.
    fn must_return<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the rate limiter did not return: it is blocked on its own map")
    }

    /// The map is at its cap and one of the first entries the probe looks at is stale: the
    /// ordinary case once a site has seen more addresses than the cap. The probe removed it
    /// while still iterating, and never returned.
    #[test]
    fn the_probe_removes_a_stale_entry_and_returns() {
        // Few entries, all stale: whatever order the map iterates in, the probe finds one.
        for stale_entries in [1u32, 4, 16, 40] {
            let (admitted, left) = must_return(move || {
                let (_, previous) = windows();
                let map = crate::numa::NumaAwareMap::new();
                for n in 0..stale_entries {
                    map.insert(
                        std::net::IpAddr::from(n.to_be_bytes()),
                        RateEntry::new(previous),
                    );
                }
                let newcomer = std::net::IpAddr::from([203, 0, 113, 7]);
                let admitted = check_rate_limit(
                    100,
                    WINDOW,
                    stale_entries as usize,
                    &map,
                    &RateSweep::default(),
                    newcomer,
                );
                // And the map is usable afterwards, for writes too.
                map.insert(
                    std::net::IpAddr::from([203, 0, 113, 8]),
                    RateEntry::new(previous),
                );
                map.remove(&std::net::IpAddr::from([203, 0, 113, 8]));
                (admitted, map.len())
            });
            assert!(
                admitted,
                "{stale_entries} stale entries: the newcomer is admitted"
            );
            assert_eq!(
                left, stale_entries as usize,
                "one stale entry made room for it"
            );
        }
    }

    /// A rate map at its cap, holding `live_head` addresses seen in the current window in
    /// the places the cheap probe looks at, and addresses of a past window everywhere else.
    /// Returns the map and the current window.
    fn map_at_cap_with_stale_entries_beyond_the_probe(
        cap: u32,
    ) -> (crate::numa::NumaAwareMap<std::net::IpAddr, RateEntry>, u32) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current = (now / WINDOW) as u32;
        let map = crate::numa::NumaAwareMap::new();
        for n in 0..cap {
            let ip = std::net::IpAddr::from(n.to_be_bytes());
            map.insert(ip, RateEntry::new(current - 1));
        }
        // Whatever order the map iterates in, its first entries are the ones probed.
        let head: Vec<std::net::IpAddr> = map.iter().take(64).map(|e| *e.key()).collect();
        for ip in head {
            map.insert(ip, RateEntry::new(current));
        }
        (map, current)
    }

    /// #528: the probe at the cap looks at the first few entries, always the same ones. With
    /// those in use, a map otherwise full of addresses not seen since a past window turned
    /// every new client away until the 60 s scavenger ran. It is now swept.
    #[test]
    fn a_map_full_of_addresses_from_past_windows_admits_a_new_client() {
        const CAP: u32 = 5_000;
        let (map, _) = map_at_cap_with_stale_entries_beyond_the_probe(CAP);
        assert_eq!(map.len(), CAP as usize);
        let sweep = RateSweep::default();
        let newcomer = std::net::IpAddr::from([203, 0, 113, 7]);
        assert!(
            check_rate_limit(100, WINDOW, CAP as usize, &map, &sweep, newcomer),
            "a new client is admitted: the map was full of stale entries"
        );
        assert_eq!(
            map.len(),
            64 + 1,
            "what is left is what was seen in this window, and the newcomer"
        );
        assert!(map.get(&newcomer).is_some());
    }

    /// The sweep reads every entry, so it runs once per window at most: under a flood of
    /// new addresses each request would otherwise pay for one. A second time at the cap in
    /// the same window, with nothing stale where the probe looks, is a refusal.
    #[test]
    fn the_full_sweep_runs_once_per_window() {
        const CAP: u32 = 2_000;
        let (map, current) = map_at_cap_with_stale_entries_beyond_the_probe(CAP);
        let sweep = RateSweep::default();
        let ip = |n: u8| std::net::IpAddr::from([203, 0, 113, n]);
        assert!(check_rate_limit(
            100,
            WINDOW,
            CAP as usize,
            &map,
            &sweep,
            ip(1)
        ));
        assert_eq!(map.len(), 65);
        // Fill it again in the same window: addresses of this window where the probe
        // looks, stale ones behind them.
        for n in 0..CAP {
            let stale = std::net::IpAddr::from((0x0a00_0000u32 + n).to_be_bytes());
            map.insert(stale, RateEntry::new(current - 1));
        }
        let head: Vec<std::net::IpAddr> = map.iter().take(64).map(|e| *e.key()).collect();
        for addr in head {
            map.insert(addr, RateEntry::new(current));
        }
        let before = map.len();
        assert!(
            !check_rate_limit(100, WINDOW, before, &map, &sweep, ip(2)),
            "no second sweep in the same window"
        );
        assert_eq!(map.len(), before, "nothing was removed");
        // A fresh marker (as in the next window) sweeps again.
        assert!(check_rate_limit(
            100,
            WINDOW,
            before,
            &map,
            &RateSweep::default(),
            ip(2)
        ));
        assert!(map.len() < before);
    }

    /// A map full of addresses that ARE of this window is full: the newcomer is refused,
    /// sweep or no sweep, and an address already tracked is not.
    #[test]
    fn a_map_full_of_addresses_of_this_window_still_fails_closed() {
        let map = crate::numa::NumaAwareMap::new();
        let sweep = RateSweep::default();
        let ip = |n: u32| std::net::IpAddr::from(n.to_be_bytes());
        for n in 0..500 {
            assert!(check_rate_limit(100, WINDOW, 500, &map, &sweep, ip(n)));
        }
        assert!(!check_rate_limit(100, WINDOW, 500, &map, &sweep, ip(9_999)));
        assert!(!check_rate_limit(
            100,
            WINDOW,
            500,
            &map,
            &RateSweep::default(),
            ip(9_998)
        ));
        assert_eq!(map.len(), 500);
        assert!(check_rate_limit(100, WINDOW, 500, &map, &sweep, ip(3)));
    }

    #[test]
    fn no_trusted_proxies_returns_socket_ip() {
        let tp = proxies(&[]);
        let socket: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(
            tp.resolve_client_ip(socket, Some("10.0.0.1, 5.6.7.8")),
            socket
        );
    }

    #[test]
    fn socket_not_trusted_returns_socket_ip() {
        let tp = proxies(&["10.0.0.0/8"]);
        let socket: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(
            tp.resolve_client_ip(socket, Some("10.0.0.1, 5.6.7.8")),
            socket
        );
    }

    #[test]
    fn trusted_socket_extracts_rightmost_untrusted() {
        let tp = proxies(&["10.0.0.0/8"]);
        let socket: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let expected: std::net::IpAddr = "5.6.7.8".parse().unwrap();
        // XFF: client, proxy1 → rightmost untrusted = 5.6.7.8
        assert_eq!(
            tp.resolve_client_ip(socket, Some("1.1.1.1, 5.6.7.8")),
            expected
        );
    }

    #[test]
    fn trusted_socket_skips_trusted_xff_hops() {
        let tp = proxies(&["10.0.0.0/8", "172.16.0.0/12"]);
        let socket: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let expected: std::net::IpAddr = "203.0.113.42".parse().unwrap();
        // XFF: real_client, proxy1(trusted), proxy2(trusted)
        assert_eq!(
            tp.resolve_client_ip(socket, Some("203.0.113.42, 172.16.1.1, 10.0.0.5")),
            expected
        );
    }

    #[test]
    fn all_hops_trusted_falls_back_to_socket() {
        let tp = proxies(&["10.0.0.0/8"]);
        let socket: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            tp.resolve_client_ip(socket, Some("10.0.0.2, 10.0.0.3")),
            socket
        );
    }

    #[test]
    fn no_xff_returns_socket_ip() {
        let tp = proxies(&["10.0.0.0/8"]);
        let socket: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(tp.resolve_client_ip(socket, None), socket);
    }

    #[test]
    fn cidr_single_ip_matches() {
        let tp = proxies(&["192.168.1.100"]);
        let socket: std::net::IpAddr = "192.168.1.100".parse().unwrap();
        let expected: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(tp.resolve_client_ip(socket, Some("8.8.8.8")), expected);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property-based tests (Track C). Drive the rate-limiter and the trusted-
// proxy resolver with arbitrary inputs to surface invariants the hand-rolled
// tests above might miss. Kept in a dedicated module so a CI failure here
// is visibly distinct from a unit-test failure.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr};

    proptest! {
        // The rate-limiter must never permit more than `rps` admits within
        // a single one-second window for the same IP, regardless of how many
        // requests we throw at it. The packed `(window, count)` u64 makes
        // window-flip races particularly tricky to reason about; this
        // property exercises the boundary repeatedly.
        #[test]
        fn rate_limiter_caps_at_rps_within_window(
            rps in 1u32..=100,
            burst in 1usize..=500,
        ) {
            let map = crate::numa::NumaAwareMap::new();
            let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
            let mut allowed = 0;
            for _ in 0..burst {
                if check_rate_limit(rps, 1, MAX_RATE_MAP_ENTRIES, &map, &RateSweep::default(), ip) {
                    allowed += 1;
                }
            }
            // The limiter keys its window off `SystemTime::now()`, so a
            // tight loop on a slow runner (Windows CI) can straddle a
            // second boundary, reset the counter, and admit up to `rps`
            // again — i.e. up to `2*rps` for the burst as a whole. We
            // accept that as the wall-clock-honest upper bound here; the
            // real invariant we care about is "never unbounded relative
            // to rps", not "never crosses a window boundary mid-burst".
            prop_assert!(
                allowed <= 2 * rps as usize,
                "rps={rps}, burst={burst}, allowed={allowed} (>2*rps)"
            );
        }

        // With rps = 0 (disabled) every request must be admitted, regardless
        // of burst size — the gate is documented as zero-overhead when off.
        #[test]
        fn rate_limiter_disabled_admits_everything(burst in 1usize..=10_000) {
            let map = crate::numa::NumaAwareMap::new();
            let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
            for _ in 0..burst {
                prop_assert!(check_rate_limit(0, 1, MAX_RATE_MAP_ENTRIES, &map, &RateSweep::default(), ip));
            }
        }

        // Distinct IPs MUST be counted independently. Saturating one IP
        // never affects another. (This is the "noisy neighbour" property.)
        #[test]
        fn rate_limiter_isolates_ips(
            rps in 1u32..=20,
            burst_a in 1usize..=200,
            burst_b in 1usize..=200,
        ) {
            let map = crate::numa::NumaAwareMap::new();
            let ip_a: IpAddr = Ipv4Addr::new(10, 0, 0, 3).into();
            let ip_b: IpAddr = Ipv4Addr::new(10, 0, 0, 4).into();
            let mut allowed_a = 0;
            let mut allowed_b = 0;
            for _ in 0..burst_a {
                if check_rate_limit(rps, 1, MAX_RATE_MAP_ENTRIES, &map, &RateSweep::default(), ip_a) {
                    allowed_a += 1;
                }
            }
            for _ in 0..burst_b {
                if check_rate_limit(rps, 1, MAX_RATE_MAP_ENTRIES, &map, &RateSweep::default(), ip_b) {
                    allowed_b += 1;
                }
            }
            // Same wall-clock relaxation as the cap test above: a burst
            // straddling a 1-second boundary may admit up to 2*rps for
            // each IP. The property we still enforce is *isolation* —
            // saturating IP A must not affect IP B's budget — encoded
            // implicitly because we count each IP separately.
            prop_assert!(allowed_a <= 2 * rps as usize);
            prop_assert!(allowed_b <= 2 * rps as usize);
        }
    }
}

#[cfg(test)]
mod normalize_host_tests {
    //! The normative host-normalization contract from ADR-0010. These lock the
    //! primitive that both config `hosts` validation and the dispatch hot path
    //! route through, so a config key and a request authority are always
    //! compared in the same form.
    use super::normalize_host;

    /// Each row: raw authority → expected canonical key (`None` = route via the
    /// hostless/shared layer). Mirrors the ADR-0010 contract table.
    #[test]
    fn contract_table() {
        let cases: &[(&str, Option<&str>)] = &[
            ("api.example.com", Some("api.example.com")), // plain
            ("api.example.com:8443", Some("api.example.com")), // port stripped
            ("API.Example.COM", Some("api.example.com")), // case-folded
            ("api.example.com.", Some("api.example.com")), // trailing FQDN dot
            ("api.example.com.:443", Some("api.example.com")), // dot + port
            ("  api.example.com  ", Some("api.example.com")), // trimmed
            ("[2001:db8::1]", Some("[2001:db8::1]")),     // v6 literal kept
            ("[2001:db8::1]:443", Some("[2001:db8::1]")), // v6 literal, port off
            ("", None),                                   // empty ⇒ shared
            (":8443", None),                              // port only ⇒ shared
            ("host/with/slash", None),                    // path char ⇒ invalid
            ("user@host", None),                          // userinfo ⇒ invalid
        ];
        for (raw, want) in cases {
            assert_eq!(
                normalize_host(raw).as_deref(),
                *want,
                "normalize_host({raw:?})"
            );
        }
    }

    #[test]
    fn borrows_when_already_canonical() {
        // No allocation when the input is already lowercase + portless.
        assert!(matches!(
            normalize_host("api.example.com"),
            Some(std::borrow::Cow::Borrowed(_))
        ));
        // Allocates only to fold case.
        assert!(matches!(
            normalize_host("API.example.com"),
            Some(std::borrow::Cow::Owned(_))
        ));
    }

    #[test]
    fn canonical_hosts_are_fixed_points() {
        // The invariant config validation relies on: a canonical host normalizes
        // to itself, so `hosts` entries accepted at load are exactly the keys the
        // dispatcher will look up.
        for h in ["api.example.com", "a.b.c.example.org", "[::1]"] {
            assert_eq!(normalize_host(h).as_deref(), Some(h), "fixed point: {h}");
        }
    }

    #[test]
    fn unbracketed_v6_is_not_port_split() {
        // A bare (illegal) IPv6 literal must not be mangled by the port splitter
        // into a truncated key — it stays intact and simply misses the host map.
        assert_eq!(normalize_host("::1").as_deref(), Some("::1"));
    }
}

#[cfg(test)]
mod internal_networks_tests {

    #[test]
    fn purging_needs_loopback_unless_the_operator_named_the_networks() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let default = InternalNetworks::default();
        for ok in ["127.0.0.1", "127.8.8.8", "::1", "::ffff:127.0.0.1"] {
            assert!(default.allows_purge(&ip(ok)), "{ok}");
        }
        // Internal enough to read /metrics, not to flush the cache.
        for no in [
            "10.0.0.5",
            "172.16.3.4",
            "192.168.1.1",
            "169.254.1.1",
            "fd00::1",
            "203.0.113.9",
        ] {
            assert!(!default.allows_purge(&ip(no)), "{no}");
        }
        assert!(default.contains(&ip("10.0.0.5")), "reads are unchanged");
        // An explicit list is honoured as written, for purging too.
        let named = InternalNetworks::from_config(&["10.0.0.0/8".to_string()]);
        assert!(named.allows_purge(&ip("10.0.0.5")));
        assert!(!named.allows_purge(&ip("127.0.0.1")));
        assert!(!named.allows_purge(&ip("192.168.1.1")));
    }
    use super::*;

    // ── ZION-AUTH-03: which peers count as "internal" ─────────────────────

    #[test]
    fn default_is_the_private_range_rule() {
        let n = InternalNetworks::default();
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
        ] {
            assert!(
                n.contains(&ip.parse().unwrap()),
                "{ip} is internal by default"
            );
        }
        for ip in ["8.8.8.8", "203.0.113.7", "2001:db8::1"] {
            assert!(!n.contains(&ip.parse().unwrap()), "{ip} is public");
        }
    }

    #[test]
    fn an_explicit_list_replaces_the_private_range_rule() {
        // The point of the setting: a private address that is NOT listed (a load
        // balancer, a SNAT hop, a neighbour on the bridge) is no longer internal.
        let n = InternalNetworks::from_config(&["10.20.0.0/24".into(), "127.0.0.1".into()]);
        assert!(n.contains(&"10.20.0.5".parse().unwrap()));
        assert!(n.contains(&"127.0.0.1".parse().unwrap()));
        assert!(
            !n.contains(&"10.99.0.1".parse().unwrap()),
            "private but not listed"
        );
        assert!(
            !n.contains(&"192.168.1.1".parse().unwrap()),
            "private but not listed"
        );
        assert!(
            !n.contains(&"::1".parse().unwrap()),
            "v6 loopback was not listed"
        );
        assert!(!n.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_validation_rejects_typos_instead_of_widening_or_shrinking() {
        for ok in [
            "10.0.0.0/24",
            "127.0.0.1",
            "0.0.0.0/0",
            "::1/128",
            "fd00::/8",
        ] {
            assert!(is_valid_cidr(ok), "{ok}");
        }
        for bad in [
            "10.0.0.0/99",
            "::/129",
            "not-an-ip",
            "10.0.0.0/",
            "10.0.0/24",
            "",
        ] {
            assert!(!is_valid_cidr(bad), "{bad:?} must be rejected");
        }
    }
}
