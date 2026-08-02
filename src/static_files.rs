//! Static file serving for `mode = "static"` (ADR-0015).
//!
//! The one security property that matters: a request must NEVER read a file
//! outside the configured `serve_dir`. Defense in depth, in order:
//!  1. per-segment percent-decode, refusing a decoded `/`, `\`, NUL or invalid
//!     UTF-8 — so `%2f`, `%00` and encoded traversal cannot smuggle structure;
//!  2. refuse any `..` or dotfile segment outright (no normalization of `..`);
//!  3. `canonicalize` the resolved path AND the root and require the resolved
//!     path to stay under the root — this is what defeats a symlink pointing out
//!     of the tree.
//!
//! [`sanitize`] is pure (no I/O) and adversarially unit-tested; [`serve`] does
//! the filesystem work on the tokio blocking pool via `tokio::fs`.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Method, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::proxy::ZionBody;

/// Whole-file / whole-slice in-memory read cap. Streaming is a deferred follow-up
/// (ADR-0015); until then a response body — a full file OR a single range slice —
/// is refused past this size rather than buffered whole, which under concurrency
/// would be a memory-amplification DoS.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Turn a request-path tail (already stripped of the route prefix) into a safe
/// RELATIVE path under the serve root, or `None` if it must be refused. Pure —
/// no filesystem access, so it is exhaustively unit-testable.
pub fn sanitize(tail: &str) -> Option<PathBuf> {
    let mut rel = PathBuf::new();
    for raw in tail.split('/') {
        if raw.is_empty() {
            continue;
        }
        let seg = percent_decode(raw)?; // invalid UTF-8 → refuse
        if seg == "." || seg.is_empty() {
            continue;
        }
        // A decoded separator / NUL / traversal / dotfile is an attack, never a
        // real filename we are willing to serve.
        if seg == ".."
            || seg.starts_with('.')
            || seg.contains('/')
            || seg.contains('\\')
            || seg.contains(':') // Windows drive letter / alternate data stream
            || seg.chars().any(|c| c.is_control()) // NUL, CR/LF, tab, other control
            || is_reserved_windows_name(&seg)
        {
            return None;
        }
        rel.push(seg);
    }
    Some(rel)
}

/// Percent-decode a single path segment to a UTF-8 `String`; `None` if the
/// decoded bytes are not valid UTF-8. A malformed `%` escape is left literal.
fn percent_decode(seg: &str) -> Option<String> {
    let b = seg.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Reserved Windows device names (`CON`, `NUL`, `COM1`…). Harmless to reject on
/// Unix; on Windows opening one of these by name is a footgun, so refuse them
/// regardless of the build target (defense in depth).
fn is_reserved_windows_name(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0')
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn resp(status: StatusCode) -> Response<ZionBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap()
}

/// Serve `tail` from `root`. `method` gates to GET/HEAD; `spa_fallback` serves
/// the root `index.html` for a miss (single-page apps).
pub async fn serve(
    root: &Path,
    tail: &str,
    spa_fallback: bool,
    method: &Method,
    req_headers: &HeaderMap,
) -> Response<ZionBody> {
    if method != Method::GET && method != Method::HEAD {
        return resp(StatusCode::METHOD_NOT_ALLOWED);
    }
    // The root itself must resolve; a missing serve_dir is a 404, not a leak.
    let canon_root = match tokio::fs::canonicalize(root).await {
        Ok(r) => r,
        Err(_) => return resp(StatusCode::NOT_FOUND),
    };
    let Some(rel) = sanitize(tail) else {
        return resp(StatusCode::FORBIDDEN);
    };

    if let Some(path) = resolve_file(&canon_root, &rel).await {
        return read_file(&path, method, req_headers).await;
    }
    if spa_fallback {
        if let Some(index) = resolve_file(&canon_root, Path::new("index.html")).await {
            return read_file(&index, method, req_headers).await;
        }
    }
    resp(StatusCode::NOT_FOUND)
}

/// Resolve `rel` under `canon_root` to an existing regular file, staying inside
/// the tree (`canonicalize` defeats a symlink escape). A directory maps to its
/// `index.html`.
async fn resolve_file(canon_root: &Path, rel: &Path) -> Option<PathBuf> {
    let candidate = canon_root.join(rel);
    let canon = tokio::fs::canonicalize(&candidate).await.ok()?;
    if !canon.starts_with(canon_root) {
        return None; // a symlink (or a race) escaped the tree
    }
    let meta = tokio::fs::metadata(&canon).await.ok()?;
    if meta.is_dir() {
        let index = canon.join("index.html");
        let ci = tokio::fs::canonicalize(&index).await.ok()?;
        if ci.starts_with(canon_root) && tokio::fs::metadata(&ci).await.ok()?.is_file() {
            Some(ci)
        } else {
            None
        }
    } else if meta.is_file() {
        Some(canon)
    } else {
        None // device / socket / fifo — never served
    }
}

async fn read_file(path: &Path, method: &Method, req_headers: &HeaderMap) -> Response<ZionBody> {
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return resp(StatusCode::NOT_FOUND),
    };
    let (etag, last_modified) = validators(&meta);
    let mime = mime_for(path);
    let total = meta.len();

    // Conditional request first (RFC 9110 §13.2.1 evaluation order): a fresh
    // validator answers 304 (no body) for GET *and* HEAD (RFC 9110 §15.4.5), so a
    // revalidating client gets bytes back only when the file actually changed.
    if crate::http_conditional::is_not_modified(req_headers, etag.as_ref(), last_modified.as_ref())
    {
        return not_modified(etag, last_modified);
    }

    // Range request (RFC 9110 §14): honor it only when `If-Range` (if present)
    // still matches this representation, then serve a 206 slice.
    if if_range_allows(req_headers, last_modified.as_ref()) {
        match parse_range(req_headers.get(hyper::header::RANGE), total) {
            RangeOutcome::Unsatisfiable => {
                return range_not_satisfiable(total, etag, last_modified);
            }
            RangeOutcome::Satisfiable(start, end) => {
                // A HEAD reports the slice metadata without reading any bytes.
                if method == Method::HEAD {
                    return partial_response(
                        mime,
                        start,
                        end,
                        total,
                        etag,
                        last_modified,
                        Bytes::new(),
                    );
                }
                return read_range(path, mime, start, end, total, etag, last_modified).await;
            }
            RangeOutcome::Full => {} // no usable Range — fall through to the full 200.
        }
    }

    // Full representation. HEAD needs only the length — never read the bytes into
    // memory (a HEAD to a huge file would otherwise be a cheap
    // memory-amplification DoS).
    if method == Method::HEAD {
        return file_response(mime, total, etag, last_modified, Bytes::new());
    }
    if total > MAX_FILE_BYTES {
        return resp(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let data = match tokio::fs::read(path).await {
        Ok(d) => d,
        Err(_) => return resp(StatusCode::NOT_FOUND),
    };
    let len = data.len() as u64;
    file_response(mime, len, etag, last_modified, Bytes::from(data))
}

/// Derive the `(ETag, Last-Modified)` validators from file metadata. The ETag is
/// *weak* (`W/"len-secs.nanos"`): `len`+`mtime` is a cheap change fingerprint,
/// not a byte-for-byte content hash, so it must never be used for a strong
/// comparison (RFC 9110 §8.8.1) — which is why an `If-Range` carrying an
/// entity-tag can never match it (see [`if_range_allows`]). Either validator is
/// `None` when the platform can't supply an mtime; the file still serves, just
/// without revalidation or ranged reads keyed on the tag.
fn validators(meta: &std::fs::Metadata) -> (Option<HeaderValue>, Option<HeaderValue>) {
    let dur = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    let etag = dur.and_then(|d| {
        HeaderValue::from_str(&format!(
            "W/\"{:x}-{:x}.{:x}\"",
            meta.len(),
            d.as_secs(),
            d.subsec_nanos()
        ))
        .ok()
    });
    let last_modified = dur.and_then(|d| {
        HeaderValue::from_str(&crate::http_conditional::fmt_imf_fixdate(d.as_secs())).ok()
    });
    (etag, last_modified)
}

/// A `304 Not Modified` — validators preserved, no body (RFC 9110 §15.4.5).
fn not_modified(
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
) -> Response<ZionBody> {
    let mut b = Response::builder().status(StatusCode::NOT_MODIFIED);
    if let Some(e) = etag {
        b = b.header(hyper::header::ETAG, e);
    }
    if let Some(lm) = last_modified {
        b = b.header(hyper::header::LAST_MODIFIED, lm);
    }
    b.body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap()
}

/// A `200 OK` file response (or its HEAD twin, with an empty `body`): content
/// headers, the revalidation validators the client echoes back next time, and
/// `Accept-Ranges: bytes` advertising that ranged requests are supported.
fn file_response(
    mime: &'static str,
    content_length: u64,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
    body: Bytes,
) -> Response<ZionBody> {
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, mime)
        .header(hyper::header::CONTENT_LENGTH, content_length)
        .header(hyper::header::ACCEPT_RANGES, "bytes");
    if let Some(e) = etag {
        b = b.header(hyper::header::ETAG, e);
    }
    if let Some(lm) = last_modified {
        b = b.header(hyper::header::LAST_MODIFIED, lm);
    }
    b.body(Full::new(body).map_err(|n| match n {}).boxed())
        .unwrap()
}

/// The outcome of evaluating a `Range` header against a file of `total` bytes.
enum RangeOutcome {
    /// No range, an unrecognized unit, a multi-range set, or a malformed spec:
    /// serve the full 200 (RFC 9110 §14.2 lets a server ignore a Range it cannot
    /// or chooses not to satisfy).
    Full,
    /// A single satisfiable byte range, inclusive `[start, end]`.
    Satisfiable(u64, u64),
    /// A syntactically valid but unsatisfiable range → 416.
    Unsatisfiable,
}

/// Parse a single-range `Range: bytes=…` against `total`. Only one range is
/// supported (multipart/byteranges is a follow-up); a multi-range set is treated
/// as [`RangeOutcome::Full`]. Suffix (`-N`) and open-ended (`N-`) forms handled.
fn parse_range(header: Option<&HeaderValue>, total: u64) -> RangeOutcome {
    let Some(spec) = header
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().strip_prefix("bytes="))
    else {
        return RangeOutcome::Full;
    };
    let spec = spec.trim();
    if spec.is_empty() || spec.contains(',') {
        return RangeOutcome::Full; // multi-range or empty → serve full
    }
    let Some((a, b)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };
    let (a, b) = (a.trim(), b.trim());
    if total == 0 {
        return RangeOutcome::Unsatisfiable;
    }
    let (start, end) = if a.is_empty() {
        // Suffix range: the last `n` bytes.
        match b.parse::<u64>() {
            Ok(0) => return RangeOutcome::Unsatisfiable, // "-0" = last zero bytes
            Ok(n) => (total.saturating_sub(n), total - 1),
            Err(_) => return RangeOutcome::Full,
        }
    } else {
        let Ok(start) = a.parse::<u64>() else {
            return RangeOutcome::Full;
        };
        let end = if b.is_empty() {
            total - 1
        } else {
            match b.parse::<u64>() {
                Ok(e) => e.min(total - 1), // clamp to the last byte
                Err(_) => return RangeOutcome::Full,
            }
        };
        (start, end)
    };
    if start > end || start >= total {
        return RangeOutcome::Unsatisfiable;
    }
    RangeOutcome::Satisfiable(start, end)
}

/// Does `If-Range` (if present) still permit a ranged response? Our validator is
/// a *weak* ETag, which can never satisfy `If-Range`'s strong entity-tag
/// comparison (RFC 9110 §13.1.5) — so an `If-Range` carrying any entity-tag
/// declines to a full 200. An `If-Range` carrying an HTTP-date honors the range
/// only when it exactly matches our `Last-Modified`.
fn if_range_allows(req_headers: &HeaderMap, last_modified: Option<&HeaderValue>) -> bool {
    let Some(v) = req_headers
        .get(hyper::header::IF_RANGE)
        .and_then(|v| v.to_str().ok())
    else {
        return true; // no If-Range → range permitted
    };
    let v = v.trim();
    // An entity-tag (weak or strong) requires strong comparison, which our weak
    // tag fails by definition.
    if v.starts_with("W/") || v.starts_with('"') {
        return false;
    }
    // Otherwise it is an HTTP-date: honor the range only on an exact match.
    match last_modified.and_then(|lm| lm.to_str().ok()) {
        Some(lm) => v == lm.trim(),
        None => false,
    }
}

/// Read `[start, end]` from `path` and answer `206 Partial Content`. The slice is
/// bounded by [`MAX_FILE_BYTES`] (the same memory guard as the full read) — a
/// larger single range is refused with 413 until streaming lands.
async fn read_range(
    path: &Path,
    mime: &'static str,
    start: u64,
    end: u64,
    total: u64,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
) -> Response<ZionBody> {
    let len = end - start + 1;
    if len > MAX_FILE_BYTES {
        return resp(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let mut f = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => return resp(StatusCode::NOT_FOUND),
    };
    if f.seek(SeekFrom::Start(start)).await.is_err() {
        return resp(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let mut buf = vec![0u8; len as usize];
    if f.read_exact(&mut buf).await.is_err() {
        // The file shrank between metadata and read (a race): the range that was
        // satisfiable a moment ago no longer holds.
        return range_not_satisfiable(total, etag, last_modified);
    }
    partial_response(
        mime,
        start,
        end,
        total,
        etag,
        last_modified,
        Bytes::from(buf),
    )
}

/// A `206 Partial Content` (or its HEAD twin, empty `body`) with `Content-Range`.
#[allow(clippy::too_many_arguments)]
fn partial_response(
    mime: &'static str,
    start: u64,
    end: u64,
    total: u64,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
    body: Bytes,
) -> Response<ZionBody> {
    let mut b = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(hyper::header::CONTENT_TYPE, mime)
        .header(hyper::header::CONTENT_LENGTH, end - start + 1)
        .header(hyper::header::ACCEPT_RANGES, "bytes")
        .header(
            hyper::header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}"),
        );
    if let Some(e) = etag {
        b = b.header(hyper::header::ETAG, e);
    }
    if let Some(lm) = last_modified {
        b = b.header(hyper::header::LAST_MODIFIED, lm);
    }
    b.body(Full::new(body).map_err(|n| match n {}).boxed())
        .unwrap()
}

/// A `416 Range Not Satisfiable` carrying the authoritative total via
/// `Content-Range: bytes */total` (RFC 9110 §14.4).
fn range_not_satisfiable(
    total: u64,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
) -> Response<ZionBody> {
    let mut b = Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(hyper::header::CONTENT_RANGE, format!("bytes */{total}"));
    if let Some(e) = etag {
        b = b.header(hyper::header::ETAG, e);
    }
    if let Some(lm) = last_modified {
        b = b.header(hyper::header::LAST_MODIFIED, lm);
    }
    b.body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap()
}

/// MIME type by extension — a small, closed table (no `mime_guess` dependency).
fn mime_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "xml" => "application/xml",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t: &str) -> Option<String> {
        sanitize(t).map(|p| p.to_string_lossy().replace('\\', "/"))
    }

    #[test]
    fn normal_paths_pass() {
        assert_eq!(s("css/main.css").as_deref(), Some("css/main.css"));
        assert_eq!(s("/index.html").as_deref(), Some("index.html"));
        assert_eq!(s("").as_deref(), Some(""));
        assert_eq!(s("a/b/c.js").as_deref(), Some("a/b/c.js"));
        // collapse empty + `.` segments, never escaping.
        assert_eq!(s("////a").as_deref(), Some("a"));
        assert_eq!(s("a/./b").as_deref(), Some("a/b"));
        // a legit space (percent-encoded) decodes and is served.
        assert_eq!(s("my%20file.txt").as_deref(), Some("my file.txt"));
    }

    #[test]
    fn dotdot_traversal_is_refused() {
        assert_eq!(sanitize("../etc/passwd"), None);
        assert_eq!(sanitize("a/../../etc/passwd"), None);
        assert_eq!(sanitize("..").into_iter().count(), 0);
    }

    #[test]
    fn encoded_traversal_is_refused() {
        assert_eq!(sanitize("%2e%2e/secret"), None); // %2e%2e → ".."
        assert_eq!(sanitize("%2e%2e%2fsecret"), None); // decodes to "../secret" → contains '/'
        assert_eq!(sanitize("a%2f%2e%2e"), None); // "a/.." smuggled via %2f
    }

    #[test]
    fn dotfiles_are_refused() {
        assert_eq!(sanitize(".env"), None);
        assert_eq!(sanitize(".git/config"), None);
        assert_eq!(sanitize("ok/.ssh/id_rsa"), None);
    }

    #[test]
    fn nul_backslash_and_bad_utf8_are_refused() {
        assert_eq!(sanitize("a%00b"), None); // NUL
        assert_eq!(sanitize("a\\b"), None); // backslash (Windows sep)
        assert_eq!(sanitize("%ff%fe"), None); // invalid UTF-8
    }

    #[test]
    fn windows_hazards_and_control_chars_refused() {
        // F5: drive letter / alternate-data-stream colon + reserved device names.
        assert_eq!(sanitize("C:/x"), None);
        assert_eq!(sanitize("file.txt:$DATA"), None);
        assert_eq!(sanitize("CON"), None);
        assert_eq!(sanitize("nul.txt"), None);
        assert_eq!(sanitize("COM1"), None);
        assert_eq!(sanitize("lpt9.log"), None);
        // F6: decoded control chars (newline, tab) as filename bytes.
        assert_eq!(sanitize("a%0ab"), None);
        assert_eq!(sanitize("a%09b"), None);
        // ...but ordinary names that merely contain those substrings are fine.
        assert!(sanitize("common.css").is_some()); // "com" prefix, not COM1
        assert!(sanitize("com10.txt").is_some()); // COM10 is not reserved
        assert!(sanitize("nulls.json").is_some());
    }

    #[test]
    fn mime_by_extension() {
        assert_eq!(mime_for(Path::new("a/b.css")), "text/css; charset=utf-8");
        assert_eq!(
            mime_for(Path::new("app.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(mime_for(Path::new("x.unknown")), "application/octet-stream");
    }

    // ── Range parsing (pure) ──────────────────────────────────────────────────

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    /// Assert `parse_range(bytes=spec, total)` yields a satisfiable `[a, b]`.
    #[track_caller]
    fn sat(spec: &str, total: u64, a: u64, b: u64) {
        match parse_range(Some(&hv(spec)), total) {
            RangeOutcome::Satisfiable(s, e) => assert_eq!((s, e), (a, b), "for {spec}"),
            _ => panic!("{spec} on {total}: expected Satisfiable({a},{b})"),
        }
    }
    #[track_caller]
    fn unsat(spec: &str, total: u64) {
        assert!(
            matches!(
                parse_range(Some(&hv(spec)), total),
                RangeOutcome::Unsatisfiable
            ),
            "{spec} on {total}: expected Unsatisfiable"
        );
    }
    #[track_caller]
    fn full(spec: &str, total: u64) {
        assert!(
            matches!(parse_range(Some(&hv(spec)), total), RangeOutcome::Full),
            "{spec} on {total}: expected Full"
        );
    }

    #[test]
    fn range_satisfiable_forms() {
        sat("bytes=0-9", 100, 0, 9);
        sat("bytes=10-", 100, 10, 99); // open-ended → to the last byte
        sat("bytes=-20", 100, 80, 99); // suffix → last 20 bytes
        sat("bytes=90-1000", 100, 90, 99); // end clamped to last byte
        sat("bytes=0-0", 100, 0, 0); // first byte only
        sat("bytes=99-99", 100, 99, 99); // last byte only
        sat("bytes=-1000", 100, 0, 99); // suffix larger than file → whole file
        sat("bytes= 0-9 ", 100, 0, 9); // tolerate surrounding whitespace
    }

    #[test]
    fn range_unsatisfiable_forms() {
        unsat("bytes=100-200", 100); // start at/after EOF
        unsat("bytes=500-100", 100); // start > end (after clamp)
        unsat("bytes=-0", 100); // suffix of zero bytes
        unsat("bytes=0-0", 0); // any range on an empty file
    }

    #[test]
    fn range_falls_through_to_full() {
        assert!(matches!(parse_range(None, 100), RangeOutcome::Full)); // no header
        full("bytes=0-9,20-29", 100); // multi-range not supported yet
        full("items=0-9", 100); // unrecognized unit
        full("bytes=", 100); // empty spec
        full("bytes=abc", 100); // garbage (no dash)
        full("bytes=-", 100); // no numbers
        full("bytes=x-9", 100); // non-numeric start
        full("bytes=0-y", 100); // non-numeric end
    }

    // ── If-Range gate (pure) ──────────────────────────────────────────────────

    #[test]
    fn if_range_gate() {
        let lm = hv("Sun, 06 Nov 1994 08:49:37 GMT");
        let none = HeaderMap::new();
        assert!(if_range_allows(&none, Some(&lm)), "no If-Range → allowed");

        let mut etag_ir = HeaderMap::new();
        etag_ir.insert(hyper::header::IF_RANGE, hv("W/\"abc\""));
        assert!(
            !if_range_allows(&etag_ir, Some(&lm)),
            "a weak entity-tag can never satisfy If-Range"
        );
        let mut strong_ir = HeaderMap::new();
        strong_ir.insert(hyper::header::IF_RANGE, hv("\"abc\""));
        assert!(
            !if_range_allows(&strong_ir, Some(&lm)),
            "our validator is weak, so even a strong If-Range tag declines"
        );

        let mut date_hit = HeaderMap::new();
        date_hit.insert(hyper::header::IF_RANGE, hv("Sun, 06 Nov 1994 08:49:37 GMT"));
        assert!(
            if_range_allows(&date_hit, Some(&lm)),
            "matching date → allowed"
        );
        let mut date_miss = HeaderMap::new();
        date_miss.insert(hyper::header::IF_RANGE, hv("Mon, 07 Nov 1994 00:00:00 GMT"));
        assert!(
            !if_range_allows(&date_miss, Some(&lm)),
            "stale date → declines"
        );
    }
}

#[cfg(all(test, unix))]
mod serve_tests {
    use super::*;

    /// A throwaway serve root under the temp dir, cleaned up on drop.
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn root(tag: &str) -> Root {
        let dir = std::env::temp_dir().join(format!("zion-static-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("css")).unwrap();
        std::fs::write(dir.join("index.html"), b"<h1>home</h1>").unwrap();
        std::fs::write(dir.join("css/main.css"), b"body{}").unwrap();
        std::fs::write(dir.join(".env"), b"SECRET=1").unwrap();
        Root(dir)
    }

    async fn get(root: &Path, tail: &str, spa: bool) -> (StatusCode, String) {
        let r = serve(root, tail, spa, &Method::GET, &HeaderMap::new()).await;
        let status = r.status();
        let body = r.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// GET with a set of request headers; returns the full response so tests can
    /// inspect status + response headers (validators, 304, …).
    async fn get_h(root: &Path, tail: &str, req: HeaderMap) -> Response<ZionBody> {
        serve(root, tail, false, &Method::GET, &req).await
    }

    fn one(k: hyper::header::HeaderName, v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(k, HeaderValue::from_str(v).unwrap());
        h
    }

    #[tokio::test]
    async fn serves_files_and_index() {
        let root = root("ok");
        assert_eq!(
            get(&root.0, "css/main.css", false).await,
            (StatusCode::OK, "body{}".into())
        );
        // a directory (root) → index.html
        assert_eq!(get(&root.0, "", false).await.0, StatusCode::OK);
        assert!(get(&root.0, "", false).await.1.contains("home"));
    }

    #[tokio::test]
    async fn missing_is_404_unless_spa() {
        let root = root("spa");
        assert_eq!(
            get(&root.0, "does/not/exist", false).await.0,
            StatusCode::NOT_FOUND
        );
        // SPA fallback serves index.html for the unmatched path.
        let (st, body) = get(&root.0, "some/app/route", true).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.contains("home"));
    }

    #[tokio::test]
    async fn traversal_and_dotfiles_never_leak() {
        let root = root("safe");
        assert_eq!(
            get(&root.0, "../../../etc/passwd", false).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(get(&root.0, ".env", false).await.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn symlink_escaping_the_root_is_refused() {
        let root = root("symlink");
        // A secret outside the root, and a symlink inside pointing at it.
        let outside = std::env::temp_dir().join(format!("zion-secret-{}", std::process::id()));
        std::fs::write(&outside, b"TOP SECRET").unwrap();
        std::os::unix::fs::symlink(&outside, root.0.join("leak")).unwrap();
        // Following the symlink must not escape the canonical root.
        assert_eq!(get(&root.0, "leak", false).await.0, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(&outside);
    }

    #[tokio::test]
    async fn head_returns_length_without_reading_the_body() {
        // F2: HEAD must report Content-Length without buffering the file.
        let root = root("head");
        let r = serve(
            &root.0,
            "css/main.css",
            false,
            &Method::HEAD,
            &HeaderMap::new(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(hyper::header::CONTENT_LENGTH).unwrap(),
            "6" // "body{}" is 6 bytes
        );
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    // ── Conditional GET (ETag / Last-Modified → 304) ──────────────────────────

    #[tokio::test]
    async fn a_200_carries_both_validators() {
        let root = root("cond-200");
        let r = get_h(&root.0, "css/main.css", HeaderMap::new()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let et = r.headers().get(hyper::header::ETAG).expect("ETag present");
        assert!(
            et.to_str().unwrap().starts_with("W/\""),
            "ETag should be weak, got {et:?}"
        );
        assert!(
            r.headers().get(hyper::header::LAST_MODIFIED).is_some(),
            "Last-Modified present"
        );
    }

    #[tokio::test]
    async fn matching_if_none_match_is_304_with_no_body() {
        let root = root("cond-inm");
        // First fetch to learn the ETag the server minted for this file.
        let first = get_h(&root.0, "css/main.css", HeaderMap::new()).await;
        let etag = first
            .headers()
            .get(hyper::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        // Re-request with it: must be a bodiless 304 that still echoes the ETag.
        let second = get_h(
            &root.0,
            "css/main.css",
            one(hyper::header::IF_NONE_MATCH, &etag),
        )
        .await;
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            second.headers().get(hyper::header::ETAG).unwrap(),
            etag.as_str()
        );
        let body = second.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty(), "304 must carry no body");
    }

    #[tokio::test]
    async fn matching_if_modified_since_is_304() {
        let root = root("cond-ims");
        let first = get_h(&root.0, "css/main.css", HeaderMap::new()).await;
        let lm = first
            .headers()
            .get(hyper::header::LAST_MODIFIED)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let second = get_h(
            &root.0,
            "css/main.css",
            one(hyper::header::IF_MODIFIED_SINCE, &lm),
        )
        .await;
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn stale_if_none_match_still_serves_200() {
        let root = root("cond-stale");
        let r = get_h(
            &root.0,
            "css/main.css",
            one(hyper::header::IF_NONE_MATCH, "W/\"deadbeef-0.0\""),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"body{}");
    }

    #[tokio::test]
    async fn if_none_match_star_is_304() {
        let root = root("cond-star");
        let r = get_h(
            &root.0,
            "css/main.css",
            one(hyper::header::IF_NONE_MATCH, "*"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn conditional_head_also_304s() {
        // A HEAD that carries a matching validator must 304 too, not 200.
        let root = root("cond-head");
        let first = serve(
            &root.0,
            "css/main.css",
            false,
            &Method::HEAD,
            &HeaderMap::new(),
        )
        .await;
        let etag = first.headers().get(hyper::header::ETAG).unwrap().clone();
        let mut h = HeaderMap::new();
        h.insert(hyper::header::IF_NONE_MATCH, etag);
        let second = serve(&root.0, "css/main.css", false, &Method::HEAD, &h).await;
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
    }

    // ── Range requests (206 / 416 / Accept-Ranges) ────────────────────────────
    // css/main.css is the 6-byte "body{}".

    async fn body_bytes(r: Response<ZionBody>) -> Vec<u8> {
        r.into_body().collect().await.unwrap().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn range_206_returns_the_slice() {
        let root = root("range-mid");
        let r = get_h(
            &root.0,
            "css/main.css",
            one(hyper::header::RANGE, "bytes=0-2"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            r.headers().get(hyper::header::CONTENT_RANGE).unwrap(),
            "bytes 0-2/6"
        );
        assert_eq!(r.headers().get(hyper::header::CONTENT_LENGTH).unwrap(), "3");
        assert_eq!(
            r.headers().get(hyper::header::ACCEPT_RANGES).unwrap(),
            "bytes"
        );
        assert_eq!(&body_bytes(r).await, b"bod");
    }

    #[tokio::test]
    async fn range_open_ended_and_suffix() {
        let root = root("range-ends");
        // open-ended: from byte 2 to the end
        let r = get_h(
            &root.0,
            "css/main.css",
            one(hyper::header::RANGE, "bytes=2-"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            r.headers().get(hyper::header::CONTENT_RANGE).unwrap(),
            "bytes 2-5/6"
        );
        assert_eq!(&body_bytes(r).await, b"dy{}");
        // suffix: the last 2 bytes
        let r = get_h(
            &root.0,
            "css/main.css",
            one(hyper::header::RANGE, "bytes=-2"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            r.headers().get(hyper::header::CONTENT_RANGE).unwrap(),
            "bytes 4-5/6"
        );
        assert_eq!(&body_bytes(r).await, b"{}");
    }

    #[tokio::test]
    async fn range_unsatisfiable_is_416_with_total() {
        let root = root("range-416");
        let r = get_h(
            &root.0,
            "css/main.css",
            one(hyper::header::RANGE, "bytes=100-200"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            r.headers().get(hyper::header::CONTENT_RANGE).unwrap(),
            "bytes */6"
        );
    }

    #[tokio::test]
    async fn head_with_range_is_206_headers_no_body() {
        let root = root("range-head");
        let r = serve(
            &root.0,
            "css/main.css",
            false,
            &Method::HEAD,
            &one(hyper::header::RANGE, "bytes=1-3"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            r.headers().get(hyper::header::CONTENT_RANGE).unwrap(),
            "bytes 1-3/6"
        );
        assert_eq!(r.headers().get(hyper::header::CONTENT_LENGTH).unwrap(), "3");
        assert!(body_bytes(r).await.is_empty(), "HEAD must carry no body");
    }

    #[tokio::test]
    async fn full_200_advertises_accept_ranges() {
        let root = root("range-adv");
        let r = get_h(&root.0, "css/main.css", HeaderMap::new()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(hyper::header::ACCEPT_RANGES).unwrap(),
            "bytes"
        );
    }

    #[tokio::test]
    async fn if_range_with_weak_etag_declines_to_full_200() {
        // A resumable client sends back the weak ETag in If-Range; because it is
        // weak it can't satisfy If-Range, so we return the full 200, not a 206.
        let root = root("range-ifrange");
        let etag = get_h(&root.0, "css/main.css", HeaderMap::new())
            .await
            .headers()
            .get(hyper::header::ETAG)
            .unwrap()
            .clone();
        let mut h = HeaderMap::new();
        h.insert(hyper::header::IF_RANGE, etag);
        h.insert(hyper::header::RANGE, HeaderValue::from_static("bytes=0-2"));
        let r = get_h(&root.0, "css/main.css", h).await;
        assert_eq!(r.status(), StatusCode::OK, "weak If-Range → full 200");
        assert_eq!(&body_bytes(r).await, b"body{}");
    }
}
