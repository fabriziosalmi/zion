//! Security primitives — CORS, rate limiting, validation, and response hardening.
//!
//! Extracted from main.rs (C-01) to reduce monolith complexity.
//! All items are zero-cost at runtime (pre-compiled statics, branch-free paths).

use hyper::header::HeaderValue;
use hyper::Response;

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
            packed: std::sync::atomic::AtomicU64::new((window as u64) << 32 | 1),
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
        (window as u64) << 32 | count as u64
    }
}

/// Lock-free per-IP rate limiter.
/// Uses a single AtomicU64 per IP with packed window+count for atomic resets.
/// Eliminates the CAS-store gap that could lose counts during window transitions.
#[inline]
pub fn check_rate_limit(
    rate_limit_rps: u32,
    rate_limit_window: u64,
    rate_map: &dashmap::DashMap<std::net::IpAddr, RateEntry>,
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

    // First request from this IP — cap total tracked IPs to prevent memory exhaustion
    if rate_map.len() >= MAX_RATE_MAP_ENTRIES {
        // At capacity: allow the request but don't track (fail-open under extreme load)
        return true;
    }
    rate_map.insert(ip, RateEntry::new(current_window));
    true
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

impl TrustedProxies {
    /// Parse trusted proxy CIDR list from config.
    /// Invalid CIDRs are logged and skipped.
    pub fn from_config(cidrs: &[String]) -> Self {
        let mut parsed = Vec::with_capacity(cidrs.len());
        for s in cidrs {
            match CidrRange::parse(s) {
                Some(cidr) => parsed.push(cidr),
                None => eprintln!("  warning: invalid trusted_proxy CIDR '{}', skipping", s),
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

    fn proxies(cidrs: &[&str]) -> TrustedProxies {
        TrustedProxies::from_config(&cidrs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
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
