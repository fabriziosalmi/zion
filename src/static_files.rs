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

use std::path::{Path, PathBuf};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Method, Response, StatusCode};

use crate::proxy::ZionBody;

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

    // Conditional request: a fresh validator answers 304 (no body) for GET *and*
    // HEAD (RFC 9110 §15.4.5). This is the whole point of the feature — a
    // revalidating client gets bytes back only when the file actually changed.
    if crate::http_conditional::is_not_modified(req_headers, etag.as_ref(), last_modified.as_ref())
    {
        return not_modified(etag, last_modified);
    }

    // HEAD needs only the length — never read the bytes into memory (a HEAD to a
    // huge file would otherwise be a cheap memory-amplification DoS).
    if method == Method::HEAD {
        return file_response(
            mime_for(path),
            meta.len(),
            etag,
            last_modified,
            Bytes::new(),
        );
    }

    // Cap the whole-file in-memory read (streaming is a deferred follow-up,
    // ADR-0015): refuse an oversized file rather than buffering it whole, which
    // would be a memory-amplification DoS under concurrency.
    const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
    if meta.len() > MAX_FILE_BYTES {
        return resp(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let data = match tokio::fs::read(path).await {
        Ok(d) => d,
        Err(_) => return resp(StatusCode::NOT_FOUND),
    };
    let len = data.len() as u64;
    file_response(mime_for(path), len, etag, last_modified, Bytes::from(data))
}

/// Derive the `(ETag, Last-Modified)` validators from file metadata. The ETag is
/// *weak* (`W/"len-secs.nanos"`): `len`+`mtime` is a cheap change fingerprint,
/// not a byte-for-byte content hash, so it must never be used for a strong
/// comparison (RFC 9110 §8.8.1) — which is exactly why `If-Range` byte-range
/// reuse is deferred to the range follow-up. Either validator is `None` when the
/// platform can't supply an mtime; the file still serves, just without
/// revalidation.
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
/// headers plus the revalidation validators the client echoes back next time.
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
        .header(hyper::header::CONTENT_LENGTH, content_length);
    if let Some(e) = etag {
        b = b.header(hyper::header::ETAG, e);
    }
    if let Some(lm) = last_modified {
        b = b.header(hyper::header::LAST_MODIFIED, lm);
    }
    b.body(Full::new(body).map_err(|n| match n {}).boxed())
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
}
