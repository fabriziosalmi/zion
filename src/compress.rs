//! Opt-in downstream response compression (ADR-0025).
//!
//! This module decides *whether* a response should be compressed and *with what*
//! coding; it does not touch bytes. The byte-level encoders (flate2 for gzip, the
//! brotli crate) and the streaming body adapter arrive behind the `compress` Cargo
//! feature in a follow-up. Keeping the decision here, pure and always compiled,
//! lets it be unit-tested in isolation and keeps the hot path's branching in one
//! reviewed place.
//!
//! The decision is conservative by construction (ADR-0025): it refuses 206/Range
//! and HEAD, an already-encoded or `no-transform` body, a non-text content type, a
//! body below `min_bytes`, and any request whose `Accept-Encoding` does not overlap.
//! A default-on BREACH guard refuses to compress a response that carries
//! `Set-Cookie` or `Cache-Control: private` unless the route opts in with
//! `allow_cookied` (compressing a secret mixed with attacker-reflected input over
//! TLS is the BREACH oracle).
//!
//! SCAFFOLD (ADR-0025, first step): `negotiate` and its helpers are proven here in
//! isolation before the response path calls them. The module-level `allow(dead_code)`
//! covers the decision surface until the encoder and the `finish_response` wiring
//! land in the follow-up, which removes this attribute.
#![allow(dead_code)]

use hyper::header::{HeaderMap, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, SET_COOKIE};
use hyper::{Method, StatusCode};
use serde::Deserialize;

/// Per-route compression configuration (`[[route]] compress`). Off unless `enabled`.
#[derive(Debug, Clone, Deserialize)]
pub struct CompressConfig {
    /// Turn compression on for this route. Default `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Do not compress a body smaller than this many bytes: a tiny body costs more
    /// CPU to compress than it saves on the wire, and the encoder's framing can make
    /// it larger. Default 1024.
    #[serde(default = "default_min_bytes")]
    pub min_bytes: usize,
    /// Compress even when the response carries `Set-Cookie` or `Cache-Control:
    /// private`. Off by default: this is the BREACH posture (ADR-0025). Default
    /// `false`.
    #[serde(default)]
    pub allow_cookied: bool,
}

fn default_min_bytes() -> usize {
    1024
}

/// The resolved, startup-validated form of [`CompressConfig`]. `None` when the
/// route does not enable compression, so a route that never compresses carries no
/// state and the hot path sees an `Option::None` to short-circuit on.
#[derive(Debug, Clone)]
pub struct ResolvedCompress {
    pub min_bytes: usize,
    pub allow_cookied: bool,
}

impl ResolvedCompress {
    /// Resolve a route's config into the runtime form, or `None` when disabled.
    pub fn from_config(c: &CompressConfig) -> Option<Self> {
        c.enabled.then_some(Self {
            min_bytes: c.min_bytes,
            allow_cookied: c.allow_cookied,
        })
    }
}

/// A content coding this proxy can produce. `br` is preferred over `gzip` when the
/// client accepts both (better ratio at the levels we use), matching the static
/// sidecar negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Brotli,
}

impl Encoding {
    /// The `Content-Encoding` token.
    pub fn token(self) -> &'static str {
        match self {
            Encoding::Gzip => "gzip",
            Encoding::Brotli => "br",
        }
    }
}

/// Whether a `Content-Type` names a text-like body worth compressing. Binary media
/// (images, video, audio, fonts, archives, `octet-stream`) are already compressed
/// or incompressible, so compressing them only burns CPU.
pub fn is_compressible_type(content_type: &str) -> bool {
    // Compare the media type only, without parameters (`; charset=utf-8`) and case.
    let media = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media.starts_with("text/") {
        return true;
    }
    // Structured-syntax suffixes: application/*+json, */*+xml, +text.
    if media.ends_with("+json") || media.ends_with("+xml") || media.ends_with("+text") {
        return true;
    }
    matches!(
        media.as_str(),
        "application/json"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "application/manifest+json"
            | "application/ld+json"
            | "application/wasm"  // wasm is not pre-compressed on the wire
            | "image/svg+xml"
            | "image/x-icon"
    )
}

/// Does `Accept-Encoding` accept `coding`? RFC 9110 section 12.5.3: an explicit
/// entry overrides the `*` wildcard, and a `q=0` entry refuses. Mirrors the static
/// sidecar helper; consolidation of the two is a follow-up.
fn accepts(accept_encoding: &str, coding: &str) -> bool {
    let mut wildcard: Option<f32> = None;
    let mut explicit: Option<f32> = None;
    for part in accept_encoding.split(',') {
        let part = part.trim();
        let (name, params) = match part.split_once(';') {
            Some((n, p)) => (n.trim(), p),
            None => (part, ""),
        };
        let q = parse_q(params);
        if name.eq_ignore_ascii_case(coding) {
            explicit = Some(q);
        } else if name == "*" {
            wildcard = Some(q);
        }
    }
    match explicit.or(wildcard) {
        Some(q) => q > 0.0,
        None => false,
    }
}

/// The `q` value of an `Accept-Encoding` entry's parameters (`;q=0.5`), default 1.0.
fn parse_q(params: &str) -> f32 {
    for p in params.split(';') {
        let p = p.trim();
        if let Some(v) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
            return v.trim().parse().unwrap_or(0.0);
        }
    }
    1.0
}

/// Decide whether and how to compress a response. Returns the coding to apply, or
/// `None` to leave the body as identity. Pure: it reads only what is passed in, so
/// it is exhaustively unit-tested. The caller applies the result (and the header
/// edits: `Content-Encoding`, `Vary`, drop `Content-Length`, weaken a strong
/// `ETag`) in a follow-up; PR1 does not wire this into the response path.
pub fn negotiate(
    accept_encoding: Option<&str>,
    method: &Method,
    status: StatusCode,
    headers: &HeaderMap,
    body_len_hint: Option<u64>,
    cfg: &ResolvedCompress,
) -> Option<Encoding> {
    // A HEAD response carries no body to compress (and its headers must still
    // describe the identity representation).
    if method == Method::HEAD {
        return None;
    }
    // Only successful full representations. 206 is a byte range of a stored
    // representation; compressing it would corrupt the offsets.
    if !status.is_success() || status == StatusCode::PARTIAL_CONTENT {
        return None;
    }
    // Already encoded by the upstream (gzip/br/identity-with-a-value): never
    // double-encode.
    if headers.contains_key(CONTENT_ENCODING) {
        return None;
    }
    let cache_control = headers
        .get(CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase());
    // `no-transform` forbids a proxy from changing the representation.
    if let Some(cc) = &cache_control {
        if cc.contains("no-transform") {
            return None;
        }
    }
    // Non-text content types are not worth compressing.
    let compressible = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(is_compressible_type)
        .unwrap_or(false);
    if !compressible {
        return None;
    }
    // A body known to be below the floor is not worth it. An unknown length
    // (streamed) is allowed through.
    if let Some(len) = body_len_hint {
        if (len as usize) < cfg.min_bytes {
            return None;
        }
    }
    // BREACH guard: a response that mixes a secret (a cookie, or a response marked
    // private) with reflected input is the BREACH oracle when compressed over TLS.
    if !cfg.allow_cookied {
        let private = cache_control
            .as_deref()
            .is_some_and(|cc| cc.contains("private"));
        if headers.contains_key(SET_COOKIE) || private {
            return None;
        }
    }
    // Choose a coding the client accepts, brotli first.
    let ae = accept_encoding?;
    if accepts(ae, "br") {
        Some(Encoding::Brotli)
    } else if accepts(ae, "gzip") {
        Some(Encoding::Gzip)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hv(s: &str) -> hyper::header::HeaderValue {
        hyper::header::HeaderValue::from_str(s).unwrap()
    }

    fn text_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, hv("text/html; charset=utf-8"));
        h
    }

    fn enabled() -> ResolvedCompress {
        ResolvedCompress {
            min_bytes: 1024,
            allow_cookied: false,
        }
    }

    fn neg(
        ae: &str,
        headers: &HeaderMap,
        len: Option<u64>,
        cfg: &ResolvedCompress,
    ) -> Option<Encoding> {
        negotiate(Some(ae), &Method::GET, StatusCode::OK, headers, len, cfg)
    }

    #[test]
    fn prefers_brotli_when_both_accepted() {
        assert_eq!(
            neg("gzip, br", &text_headers(), Some(4096), &enabled()),
            Some(Encoding::Brotli)
        );
    }

    #[test]
    fn falls_back_to_gzip() {
        assert_eq!(
            neg("gzip", &text_headers(), Some(4096), &enabled()),
            Some(Encoding::Gzip)
        );
    }

    #[test]
    fn no_overlap_declines() {
        assert_eq!(neg("zstd", &text_headers(), Some(4096), &enabled()), None);
        assert_eq!(neg("", &text_headers(), Some(4096), &enabled()), None);
    }

    #[test]
    fn q_zero_refuses_the_coding() {
        assert_eq!(
            neg("br;q=0, gzip", &text_headers(), Some(4096), &enabled()),
            Some(Encoding::Gzip)
        );
        assert_eq!(
            neg("br;q=0, gzip;q=0", &text_headers(), Some(4096), &enabled()),
            None
        );
    }

    #[test]
    fn wildcard_is_a_fallback_not_an_override() {
        // explicit br;q=0 refuses even though * would accept.
        assert_eq!(
            neg("*, br;q=0", &text_headers(), Some(4096), &enabled()),
            Some(Encoding::Gzip)
        );
        // bare wildcard accepts brotli.
        assert_eq!(
            neg("*", &text_headers(), Some(4096), &enabled()),
            Some(Encoding::Brotli)
        );
    }

    #[test]
    fn below_min_bytes_declines_known_length() {
        assert_eq!(neg("br", &text_headers(), Some(512), &enabled()), None);
        // unknown length (streamed) is allowed.
        assert_eq!(
            neg("br", &text_headers(), None, &enabled()),
            Some(Encoding::Brotli)
        );
    }

    #[test]
    fn non_text_declines() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, hv("image/png"));
        assert_eq!(neg("br", &h, Some(4096), &enabled()), None);
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, hv("application/octet-stream"));
        assert_eq!(neg("br", &h, Some(4096), &enabled()), None);
    }

    #[test]
    fn missing_content_type_declines() {
        assert_eq!(neg("br", &HeaderMap::new(), Some(4096), &enabled()), None);
    }

    #[test]
    fn already_encoded_declines() {
        let mut h = text_headers();
        h.insert(CONTENT_ENCODING, hv("gzip"));
        assert_eq!(neg("br", &h, Some(4096), &enabled()), None);
    }

    #[test]
    fn no_transform_declines() {
        let mut h = text_headers();
        h.insert(CACHE_CONTROL, hv("public, no-transform"));
        assert_eq!(neg("br", &h, Some(4096), &enabled()), None);
    }

    #[test]
    fn head_and_206_decline() {
        assert_eq!(
            negotiate(
                Some("br"),
                &Method::HEAD,
                StatusCode::OK,
                &text_headers(),
                Some(4096),
                &enabled()
            ),
            None
        );
        assert_eq!(
            negotiate(
                Some("br"),
                &Method::GET,
                StatusCode::PARTIAL_CONTENT,
                &text_headers(),
                Some(4096),
                &enabled()
            ),
            None
        );
    }

    #[test]
    fn non_2xx_declines() {
        assert_eq!(
            negotiate(
                Some("br"),
                &Method::GET,
                StatusCode::NOT_FOUND,
                &text_headers(),
                Some(4096),
                &enabled()
            ),
            None
        );
    }

    #[test]
    fn breach_guard_blocks_set_cookie_by_default() {
        let mut h = text_headers();
        h.insert(SET_COOKIE, hv("session=abc"));
        assert_eq!(neg("br", &h, Some(4096), &enabled()), None);
        // opt-in overrides the guard.
        let cfg = ResolvedCompress {
            min_bytes: 1024,
            allow_cookied: true,
        };
        assert_eq!(neg("br", &h, Some(4096), &cfg), Some(Encoding::Brotli));
    }

    #[test]
    fn breach_guard_blocks_private_by_default() {
        let mut h = text_headers();
        h.insert(CACHE_CONTROL, hv("private, max-age=0"));
        assert_eq!(neg("br", &h, Some(4096), &enabled()), None);
    }

    #[test]
    fn compressible_types() {
        for ct in [
            "text/html",
            "text/plain; charset=utf-8",
            "application/json",
            "application/ld+json",
            "application/xml",
            "image/svg+xml",
            "application/javascript",
            "application/vnd.api+json",
        ] {
            assert!(is_compressible_type(ct), "{ct} should compress");
        }
        for ct in [
            "image/png",
            "image/jpeg",
            "video/mp4",
            "application/octet-stream",
            "font/woff2",
            "application/zip",
        ] {
            assert!(!is_compressible_type(ct), "{ct} should not compress");
        }
    }

    #[test]
    fn resolve_is_none_when_disabled() {
        let c = CompressConfig {
            enabled: false,
            min_bytes: 1024,
            allow_cookied: false,
        };
        assert!(ResolvedCompress::from_config(&c).is_none());
        let c = CompressConfig {
            enabled: true,
            min_bytes: 2048,
            allow_cookied: true,
        };
        let r = ResolvedCompress::from_config(&c).unwrap();
        assert_eq!(r.min_bytes, 2048);
        assert!(r.allow_cookied);
    }
}
