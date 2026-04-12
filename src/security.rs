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
pub static XCTO: HeaderValue =
    HeaderValue::from_static("nosniff");
pub static XFO: HeaderValue =
    HeaderValue::from_static("DENY");
pub static REFERRER: HeaderValue =
    HeaderValue::from_static("strict-origin-when-cross-origin");
pub static PERMISSIONS: HeaderValue =
    HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()");
#[allow(dead_code)] // Kept for future per-route CSP feature
pub static CSP: HeaderValue =
    HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");

/// Maximum tracked IPs in the rate limiter map (prevents memory exhaustion).
pub const MAX_RATE_MAP_ENTRIES: usize = 100_000;

// ============================================================================
// CORS
// ============================================================================

/// Pre-compiled CORS headers (built at boot from config, zero alloc per request).
pub struct CorsHeaders {
    pub enabled: bool,
    pub allow_origin_wildcard: bool,
    pub allowed_origins: Vec<String>,
    pub allow_methods: HeaderValue,
    pub allow_headers: HeaderValue,
    pub max_age: HeaderValue,
}

impl CorsHeaders {
    pub fn from_config(cors: &crate::config::CorsConfig) -> Self {
        let enabled = !cors.allowed_origins.is_empty();
        let wildcard = cors.allowed_origins.iter().any(|o| o == "*");

        let methods = HeaderValue::from_static(
            "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"
        );
        let headers_str = cors.allowed_headers.join(", ");
        let allow_headers = HeaderValue::from_str(&headers_str)
            .unwrap_or_else(|_| HeaderValue::from_static("Content-Type"));
        let max_age = HeaderValue::from_str(&cors.max_age.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("86400"));

        Self {
            enabled,
            allow_origin_wildcard: wildcard,
            allowed_origins: cors.allowed_origins.clone(),
            allow_methods: methods,
            allow_headers,
            max_age,
        }
    }

    /// Check if origin is allowed. Returns the origin value to echo back.
    pub fn check_origin(&self, origin: &str) -> Option<HeaderValue> {
        if self.allow_origin_wildcard {
            return Some(HeaderValue::from_static("*"));
        }
        if self.allowed_origins.iter().any(|o| o == origin) {
            return HeaderValue::from_str(origin).ok();
        }
        None
    }
}

// ============================================================================
// Security headers injection
// ============================================================================

// Pre-parsed header names for non-standard headers (S-03 fix).
// Using HeaderName::from_static() avoids parsing the string on every response.
static REFERRER_POLICY: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("referrer-policy");
static PERMISSIONS_POLICY: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("permissions-policy");
#[allow(dead_code)] // Kept for future per-route CSP feature
static CSP_NAME: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("content-security-policy");

/// Inject security headers into any response. All pre-compiled static values.
/// Cost: 6 hashmap inserts with pre-parsed keys = ~30ns total.
#[inline]
pub fn inject_security_headers(resp: &mut Response<ZionBody>) {
    let h = resp.headers_mut();
    h.insert(hyper::header::STRICT_TRANSPORT_SECURITY, HSTS.clone());
    h.insert(hyper::header::X_CONTENT_TYPE_OPTIONS, XCTO.clone());
    h.insert(hyper::header::X_FRAME_OPTIONS, XFO.clone());
    h.insert(REFERRER_POLICY.clone(), REFERRER.clone());
    h.insert(PERMISSIONS_POLICY.clone(), PERMISSIONS.clone());
    // S-05 FIX: CSP removed — as a reverse proxy, Zion should not override
    // upstream Content-Security-Policy. The upstream application knows its own
    // resource origins (CDNs, inline scripts, etc.) and must set its own CSP.
    // Injecting a restrictive default-src 'self' would break most frontends.
    // If CSP enforcement is needed, configure it per-route (future feature).
    // h.insert(CSP_NAME.clone(), CSP.clone());

    // Strip server identity — zero information leakage
    h.remove(hyper::header::SERVER);
    // S-04 FIX: Strip hop-by-hop headers from upstream responses.
    // Per RFC 7230 §6.1, proxies MUST NOT forward hop-by-hop headers.
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
                    old, new,
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
                    old, new,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                ) {
                    Ok(_) => return true, // first request in new window
                    Err(_) => continue, // retry — another thread reset first
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
#[inline]
pub fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.contains('/')
        && !host.contains('\\')
        && !host.contains('@')
        && !host.contains('\n')
        && !host.contains('\r')
        && !host.contains('\0')
        && !host.contains(' ')
}

/// Check if an IP is internal (loopback, private RFC1918, link-local).
#[inline]
pub fn is_internal_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()       // 127.0.0.0/8
            || v4.is_private()     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local()  // 169.254.0.0/16
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()                                     // ::1
            || (v6.segments()[0] & 0xffc0) == 0xfe80             // fe80::/10 link-local
            || (v6.segments()[0] & 0xfe00) == 0xfc00             // fc00::/7 unique local (ULA)
            || v6.to_ipv4_mapped().map(|v4| v4.is_private() || v4.is_loopback()).unwrap_or(false)
        }
    }
}
