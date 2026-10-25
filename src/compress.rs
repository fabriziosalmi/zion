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
//! [`apply`] is the single entry the response path calls; it runs the decision and,
//! when the `compress` feature is built, hands the body to the streaming encoder.
//! Without the feature the decision still runs but the body is left as identity, so
//! a route that asks for compression on a build without the backend degrades to
//! no-op rather than failing.

use crate::http_util::ZionBody;
use hyper::body::Body as _;
use hyper::header::{HeaderMap, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, SET_COOKIE};
use hyper::{Method, Response, StatusCode};
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
    /// The `Content-Encoding` token. Used by the encoder, so it is dead on a build
    /// without the `compress` feature.
    #[cfg_attr(not(feature = "compress"), allow(dead_code))]
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

/// The single entry the response path calls. Runs [`negotiate`] against the route's
/// resolved settings and, when a coding is chosen and the `compress` feature is
/// built, replaces the body with its compressed form and edits the headers
/// accordingly. A `None` config, a decision of "do not compress", or a build without
/// the feature all return the response untouched.
pub fn apply(
    resp: Response<ZionBody>,
    cfg: Option<&ResolvedCompress>,
    method: &Method,
    accept_encoding: Option<&str>,
    max_concurrent: u32,
) -> Response<ZionBody> {
    let Some(cfg) = cfg else { return resp };
    let hint = resp.body().size_hint().exact();
    let Some(enc) = negotiate(
        accept_encoding,
        method,
        resp.status(),
        resp.headers(),
        hint,
        cfg,
    ) else {
        return resp;
    };
    #[cfg(feature = "compress")]
    {
        // CPU admission: a slot is held by the compressed body until it finishes, so
        // the number of responses compressing at once is bounded. Over budget, the
        // body is served as identity rather than shed.
        match budget::global().try_acquire(max_concurrent) {
            Some(permit) => encode::compress_response(resp, enc, permit),
            None => resp,
        }
    }
    #[cfg(not(feature = "compress"))]
    {
        // The decision stands but the backend was not built: serve identity.
        let _ = (enc, max_concurrent);
        resp
    }
}

/// Global CPU admission budget for response compression (ADR-0025). A slot is taken
/// for the lifetime of each compressed body; over the configured cap a response is
/// served as identity. Built only with the `compress` feature.
#[cfg(feature = "compress")]
pub mod budget {
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
    use std::sync::{Arc, LazyLock};

    #[derive(Default)]
    pub struct Limiter {
        in_flight: AtomicU32,
        shed: AtomicU64,
    }

    static GLOBAL: LazyLock<Arc<Limiter>> = LazyLock::new(|| Arc::new(Limiter::default()));

    /// The process-wide compression budget.
    pub fn global() -> &'static Arc<Limiter> {
        &GLOBAL
    }

    /// A held compression slot; releases it on drop.
    pub struct Permit(Arc<Limiter>);

    impl Drop for Permit {
        fn drop(&mut self) {
            self.0.in_flight.fetch_sub(1, Relaxed);
        }
    }

    impl Limiter {
        /// Take a slot if fewer than `limit` are in use; `limit == 0` means no cap.
        /// Never blocks. Returns `None` (and counts a shed) when at the cap.
        pub fn try_acquire(self: &Arc<Self>, limit: u32) -> Option<Permit> {
            if limit == 0 {
                self.in_flight.fetch_add(1, Relaxed);
                return Some(Permit(self.clone()));
            }
            let mut cur = self.in_flight.load(Relaxed);
            loop {
                if cur >= limit {
                    self.shed.fetch_add(1, Relaxed);
                    return None;
                }
                match self
                    .in_flight
                    .compare_exchange_weak(cur, cur + 1, Relaxed, Relaxed)
                {
                    Ok(_) => return Some(Permit(self.clone())),
                    Err(actual) => cur = actual,
                }
            }
        }

        /// Responses compressing right now.
        pub fn in_flight(&self) -> u32 {
            self.in_flight.load(Relaxed)
        }

        /// Responses served as identity because the budget was full.
        pub fn shed(&self) -> u64 {
            self.shed.load(Relaxed)
        }
    }
}

/// The byte-level encoder and the streaming body adapter. Built only with the
/// `compress` Cargo feature, which pulls flate2 (gzip) and brotli.
#[cfg(feature = "compress")]
mod encode {
    use super::{Encoding, ZionBody};
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use hyper::body::{Body, Frame};
    use hyper::header::{CONTENT_ENCODING, CONTENT_LENGTH, ETAG, VARY};
    use hyper::Response;
    use std::io::Write;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Wrap the response body in [`CompressBody`] and set the headers a compressed
    /// representation requires.
    pub fn compress_response(
        resp: Response<ZionBody>,
        enc: Encoding,
        permit: super::budget::Permit,
    ) -> Response<ZionBody> {
        let (mut parts, body) = resp.into_parts();
        parts.headers.insert(
            CONTENT_ENCODING,
            hyper::header::HeaderValue::from_static(enc.token()),
        );
        // The body length changes; let the framing layer recompute it.
        parts.headers.remove(CONTENT_LENGTH);
        // The representation now varies by Accept-Encoding. Append, do not clobber.
        append_vary_accept_encoding(&mut parts.headers);
        // A strong ETag no longer identifies these bytes; weaken it to a weak validator.
        weaken_etag(&mut parts.headers);
        let body = CompressBody::new(body, enc, permit).boxed();
        Response::from_parts(parts, body)
    }

    fn append_vary_accept_encoding(headers: &mut hyper::HeaderMap) {
        // If Vary already lists accept-encoding (any case) or is `*`, leave it.
        let already = headers.get_all(VARY).iter().any(|v| {
            v.to_str().is_ok_and(|s| {
                s == "*"
                    || s.split(',')
                        .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
            })
        });
        if !already {
            headers.append(
                VARY,
                hyper::header::HeaderValue::from_static("accept-encoding"),
            );
        }
    }

    fn weaken_etag(headers: &mut hyper::HeaderMap) {
        if let Some(etag) = headers.get(ETAG) {
            if let Ok(s) = etag.to_str() {
                if !s.starts_with("W/") {
                    if let Ok(weak) = hyper::header::HeaderValue::from_str(&format!("W/{s}")) {
                        headers.insert(ETAG, weak);
                    }
                }
            }
        }
    }

    /// A streaming body that compresses the frames of an inner body. It writes each
    /// data frame into a write-based encoder and emits whatever compressed bytes the
    /// encoder has produced; on the inner body's end it finalizes the stream. Non-data
    /// frames (trailers) are finalized-then-forwarded so the encoded stream is
    /// well-formed before the trailers.
    pub struct CompressBody {
        inner: ZionBody,
        enc: Option<EncState>,
        pending: Vec<u8>,
        inner_done: bool,
        trailers: Option<Frame<Bytes>>,
        /// The CPU admission slot, released when this body is dropped.
        _permit: super::budget::Permit,
    }

    enum EncState {
        Gzip(flate2::write::GzEncoder<Vec<u8>>),
        Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    }

    impl CompressBody {
        pub fn new(inner: ZionBody, enc: Encoding, permit: super::budget::Permit) -> Self {
            let state = match enc {
                Encoding::Gzip => EncState::Gzip(flate2::write::GzEncoder::new(
                    Vec::new(),
                    flate2::Compression::new(6),
                )),
                // 4 KiB buffer, quality 4 (fast, good ratio for text), window 22.
                Encoding::Brotli => EncState::Brotli(Box::new(brotli::CompressorWriter::new(
                    Vec::new(),
                    4096,
                    4,
                    22,
                ))),
            };
            Self {
                inner,
                enc: Some(state),
                pending: Vec::new(),
                inner_done: false,
                trailers: None,
                _permit: permit,
            }
        }

        /// Write a chunk into the encoder and move whatever it produced into `pending`.
        fn write_chunk(&mut self, data: &[u8]) {
            match self.enc.as_mut() {
                Some(EncState::Gzip(e)) => {
                    let _ = e.write_all(data);
                    self.pending.append(e.get_mut());
                }
                Some(EncState::Brotli(e)) => {
                    let _ = e.write_all(data);
                    self.pending.append(e.get_mut());
                }
                None => {}
            }
        }

        /// Finalize the stream, appending the encoder's trailer bytes to `pending`.
        fn finish(&mut self) {
            match self.enc.take() {
                Some(EncState::Gzip(mut e)) => {
                    if e.try_finish().is_ok() {
                        self.pending.append(e.get_mut());
                    }
                }
                Some(EncState::Brotli(e)) => {
                    let mut buf = e.into_inner();
                    self.pending.append(&mut buf);
                }
                None => {}
            }
        }
    }

    impl Body for CompressBody {
        type Data = Bytes;
        type Error = hyper::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
            let this = &mut *self;
            loop {
                if !this.pending.is_empty() {
                    let out = std::mem::take(&mut this.pending);
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                }
                if this.inner_done {
                    if this.enc.is_some() {
                        this.finish();
                        continue; // emit the final bytes, if any
                    }
                    if let Some(trailers) = this.trailers.take() {
                        return Poll::Ready(Some(Ok(trailers)));
                    }
                    return Poll::Ready(None);
                }
                match Pin::new(&mut this.inner).poll_frame(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        this.inner_done = true;
                    }
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                    Poll::Ready(Some(Ok(frame))) => {
                        if frame.is_data() {
                            let data = frame.into_data().unwrap_or_default();
                            this.write_chunk(&data);
                        } else {
                            // Trailers: close the encoded stream, then forward them.
                            this.trailers = Some(frame);
                            this.inner_done = true;
                        }
                    }
                }
            }
        }
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

#[cfg(all(test, feature = "compress"))]
mod encode_tests {
    use super::encode::CompressBody;
    use super::Encoding;
    use crate::http_util::ZionBody;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use hyper::body::{Body, Frame};
    use std::io::Read;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A body that yields a fixed list of data frames, to exercise the multi-frame
    /// path of the encoder (write called repeatedly, then finish).
    struct Chunks(Vec<Bytes>);

    impl Body for Chunks {
        type Data = Bytes;
        type Error = hyper::Error;
        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
            let this = self.get_mut();
            if this.0.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Ready(Some(Ok(Frame::data(this.0.remove(0)))))
            }
        }
    }

    fn chunked_body(chunks: Vec<Vec<u8>>) -> ZionBody {
        Chunks(chunks.into_iter().map(Bytes::from).collect()).boxed()
    }

    fn compress_all(inner: ZionBody, enc: Encoding) -> Vec<u8> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let permit = super::budget::global().try_acquire(0).unwrap();
            CompressBody::new(inner, enc, permit)
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec()
        })
    }

    fn sample(n: usize) -> Vec<u8> {
        // Compressible but not trivial: a repeating-ish byte pattern.
        (0..n).map(|i| b"the quick brown fox "[i % 20]).collect()
    }

    #[test]
    fn gzip_roundtrip_multichunk() {
        let original = sample(50_000);
        let chunks = vec![
            original[..10_000].to_vec(),
            original[10_000..30_000].to_vec(),
            original[30_000..].to_vec(),
        ];
        let compressed = compress_all(chunked_body(chunks), Encoding::Gzip);
        assert!(
            compressed.len() < original.len(),
            "gzip should shrink the sample"
        );
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, original, "gzip round-trip must reproduce the bytes");
    }

    #[test]
    fn brotli_roundtrip_multichunk() {
        let original = sample(50_000);
        let chunks = vec![
            original[..1].to_vec(),
            original[1..25_000].to_vec(),
            original[25_000..].to_vec(),
        ];
        let compressed = compress_all(chunked_body(chunks), Encoding::Brotli);
        assert!(
            compressed.len() < original.len(),
            "brotli should shrink the sample"
        );
        let mut out = Vec::new();
        brotli::Decompressor::new(&compressed[..], 4096)
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, original, "brotli round-trip must reproduce the bytes");
    }

    #[test]
    fn empty_body_roundtrips() {
        let compressed = compress_all(chunked_body(vec![]), Encoding::Gzip);
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_end(&mut out)
            .unwrap();
        assert!(out.is_empty());
    }
}

#[cfg(all(test, feature = "compress"))]
mod budget_tests {
    use super::budget::Limiter;
    use std::sync::Arc;

    #[test]
    fn caps_concurrent_and_frees_on_drop() {
        let lim = Arc::new(Limiter::default());
        let p1 = lim.try_acquire(2);
        let p2 = lim.try_acquire(2);
        assert!(p1.is_some() && p2.is_some());
        assert_eq!(lim.in_flight(), 2);
        assert!(
            lim.try_acquire(2).is_none(),
            "over budget is shed to identity"
        );
        assert_eq!(lim.shed(), 1);
        drop(p1);
        assert_eq!(lim.in_flight(), 1);
        assert!(lim.try_acquire(2).is_some(), "a freed slot is reusable");
    }

    #[test]
    fn zero_means_no_cap() {
        let lim = Arc::new(Limiter::default());
        let _a = lim.try_acquire(0).unwrap();
        let _b = lim.try_acquire(0).unwrap();
        assert_eq!(lim.in_flight(), 2);
        assert_eq!(lim.shed(), 0);
    }
}
