// SPDX-License-Identifier: Apache-2.0
//! Request-ID generation and the small response builders shared by the
//! request pipeline (`dispatch`, `admin`, `quic`, the listeners).
//!
//! These lived in the crate root (`main.rs`), which made every consumer depend
//! on the module that wires them together (ZION-ARCH-01). They are pure helpers
//! with no dependency on `AppState`, so they sit here and the root only
//! composes.

use crate::proxy::ZionBody;
use crate::security;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};

/// Atomic request counter for generating unique request IDs.
/// Format: {timestamp_hex}-{counter_hex} — unique, sortable.
pub(crate) static REQUEST_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Hex digit lookup table for zero-alloc hex encoding.
pub(crate) const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Generate a unique request ID using a stack buffer.
/// Format: 16-char hex timestamp + '-' + 4-char hex counter = 21 bytes.
/// Zero heap allocation — writes directly to a stack [u8; 21] and converts
/// to String via from_utf8_unchecked (all bytes are ASCII hex or '-').
pub(crate) fn generate_request_id() -> [u8; 21] {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let seq = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u16;

    let mut buf = [0u8; 21]; // 16 hex + '-' + 4 hex
                             // Encode timestamp as 16 hex chars (big-endian)
    for i in 0..8 {
        let byte = (ts >> (56 - i * 8)) as u8;
        buf[i * 2] = HEX_DIGITS[(byte >> 4) as usize];
        buf[i * 2 + 1] = HEX_DIGITS[(byte & 0xF) as usize];
    }
    buf[16] = b'-';
    // Encode counter as 4 hex chars
    for i in 0..2 {
        let byte = (seq >> (8 - i * 8)) as u8;
        buf[17 + i * 2] = HEX_DIGITS[(byte >> 4) as usize];
        buf[17 + i * 2 + 1] = HEX_DIGITS[(byte & 0xF) as usize];
    }
    buf
}

// Pre-compiled constants — zero runtime cost.
static EMPTY_BYTES: Bytes = Bytes::new();

pub(crate) fn empty_response(status: StatusCode) -> Response<ZionBody> {
    // INVARIANT: hyper's `Response::builder().status(StatusCode).body(...)`
    // returns `Err` only when the builder accumulated a header parse error.
    // We pass a typed StatusCode (no parse step) and a typed body, so the
    // construction is infallible by typing.
    Response::builder()
        .status(status)
        .body(
            Full::new(EMPTY_BYTES.clone())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

pub(crate) fn text_response(status: StatusCode, text: &'static str) -> Response<ZionBody> {
    // INVARIANT: same as `empty_response` — typed StatusCode + typed body,
    // no headers added that could fail to parse.
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from_static(text.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// 405 Method Not Allowed with the mandatory `Allow` header (RFC 9110 §15.5.6:
/// "The origin server MUST generate an Allow header field in a 405"). `allow`
/// is the comma-separated method list valid at that resource, e.g.
/// `"GET, HEAD, POST"`. Static value → header parse is infallible.
pub(crate) fn method_not_allowed(allow: &'static str) -> Response<ZionBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(hyper::header::ALLOW, allow)
        .body(
            Full::new(EMPTY_BYTES.clone())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// 401 Unauthorized with the mandatory `WWW-Authenticate` challenge (RFC 9110
/// §15.5.2: "The server generating a 401 response MUST send a WWW-Authenticate
/// header field"). `challenge` is the scheme + optional params, e.g. `"Bearer"`
/// or `Bearer error="invalid_token"` (RFC 6750 §3). Static values → infallible.
// Only the `--features auth` gate emits 401s today; keep it building (and
// unit-tested) without the feature.
#[cfg_attr(not(feature = "auth"), allow(dead_code))]
pub(crate) fn unauthorized(text: &'static str, challenge: &'static str) -> Response<ZionBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(hyper::header::WWW_AUTHENTICATE, challenge)
        .body(
            Full::new(Bytes::from_static(text.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Inject security headers — delegates to security module.
pub(crate) fn inject_security_headers(resp: &mut Response<ZionBody>) {
    security::inject_security_headers(resp);
}

#[cfg(test)]
mod response_header_tests {
    use super::*;

    #[test]
    fn method_not_allowed_carries_allow_header() {
        // RFC 9110 §15.5.6 MUST: a 405 carries the Allow header.
        let resp = method_not_allowed("GET, HEAD, POST");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            resp.headers().get(hyper::header::ALLOW).unwrap(),
            "GET, HEAD, POST"
        );
    }

    #[test]
    fn unauthorized_carries_www_authenticate() {
        // RFC 9110 §15.5.2 MUST: a 401 carries the WWW-Authenticate challenge.
        let resp = unauthorized("authorization required", "Bearer");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(hyper::header::WWW_AUTHENTICATE).unwrap(),
            "Bearer"
        );
    }
}
