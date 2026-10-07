// SPDX-License-Identifier: Apache-2.0
//! Request-path normalization (RFC 3986 §6.2.2).
//!
//! Zion decides what a request is allowed to do from its path: which route it matches,
//! whether that route is `internal_only`, which WAF profile and auth profile apply, and
//! the cache key. The upstream then interprets the path it is sent. If the two read the
//! same bytes differently, a request can be matched to a permissive route and still reach
//! a protected resource: `/open/../internal/x` matches `/open/{*rest}` but an upstream
//! that resolves `..` serves `/internal/x`; `//internal/x` and `/%69nternal/x` slip past
//! a `/internal/{*rest}` route the same way.
//!
//! So the path is normalized BEFORE routing, and the normalized form is what is matched,
//! cached and forwarded:
//!   * percent-encodings of unreserved characters (`A-Z a-z 0-9 - . _ ~`) are decoded,
//!     so `%2e%2e` is `..` and `%69` is `i`; every other escape keeps its bytes with
//!     upper-case hex digits (`%2f` → `%2F`);
//!   * dot segments are removed (`/a/b/../c` → `/a/c`), never climbing above the root;
//!   * runs of `/` collapse to one (`//a///b` → `/a/b`).
//!
//! A trailing slash is preserved. An encoded slash (`%2F`) is left alone: it is data, not a
//! separator, and decoding it would change what the request means.

use std::borrow::Cow;

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Step 1: decode unreserved escapes, upper-case the hex of the others.
fn normalize_escapes(path: &str) -> Cow<'_, str> {
    if !path.contains('%') {
        return Cow::Borrowed(path);
    }
    let b = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() {
            let v = hex(b[i + 1]).unwrap() * 16 + hex(b[i + 2]).unwrap();
            if is_unreserved(v) {
                out.push(v as char);
            } else {
                out.push('%');
                out.push(b[i + 1].to_ascii_uppercase() as char);
                out.push(b[i + 2].to_ascii_uppercase() as char);
            }
            i += 3;
        } else {
            // not an escape (or a malformed one): keep the byte as written
            let ch_len = path[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&path[i..i + ch_len]);
            i += ch_len;
        }
    }
    Cow::Owned(out)
}

/// True when normalization would leave `path` exactly as it is: no dot segments, no
/// repeated slashes, and every escape already canonical (valid, upper-case hex, not an
/// unreserved character). One byte scan, no allocation, so the common case — including
/// paths that carry `%2F` or `%20` — costs nothing on the hot path.
fn is_normal(path: &str) -> bool {
    let b = path.as_bytes();
    let mut seg_start = 0; // index of the first byte of the current segment
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' => {
                let seg = &b[seg_start..i];
                // an empty segment is a repeated slash, except right at the root's start
                if i > 0 && seg.is_empty() && seg_start > 0 {
                    return false;
                }
                if seg == b"." || seg == b".." {
                    return false;
                }
                seg_start = i + 1;
                i += 1;
            }
            b'%' => {
                if i + 2 >= b.len() {
                    // too short to be an escape: left as written by normalization
                    i += 1;
                    continue;
                }
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        let v = h * 16 + l;
                        if is_unreserved(v)
                            || b[i + 1].is_ascii_lowercase()
                            || b[i + 2].is_ascii_lowercase()
                        {
                            return false;
                        }
                        i += 3;
                    }
                    _ => i += 1, // malformed: left as written
                }
            }
            _ => i += 1,
        }
    }
    let last = &b[seg_start..];
    !(last == b"." || last == b"..")
}

/// The normalized form of `path` (the path component only, no query). Paths that do not
/// start with `/` (`*` for `OPTIONS *`) are returned unchanged.
pub fn normalize_path(path: &str) -> Cow<'_, str> {
    if !path.starts_with('/') {
        return Cow::Borrowed(path);
    }
    // Fast path: already canonical — no allocation, one pass.
    if is_normal(path) {
        return Cow::Borrowed(path);
    }
    let out = normalize_slow(path);
    if out == path {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(out)
    }
}

/// The full normalization, always computed (the reference the fast check is tested against).
fn normalize_slow(path: &str) -> String {
    let escaped = normalize_escapes(path);
    let trailing_slash = escaped.ends_with('/')
        || escaped.ends_with("/.")
        || escaped.ends_with("/..")
        || escaped.len() == 1;
    let mut stack: Vec<&str> = Vec::new();
    for seg in escaped.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    let mut out = String::with_capacity(escaped.len());
    out.push('/');
    out.push_str(&stack.join("/"));
    if trailing_slash && !stack.is_empty() {
        out.push('/');
    }
    out
}

/// The query string with its parameters in a canonical order, for use in a CACHE KEY only
/// (the upstream is always sent the query as the client wrote it). Parameters are split on
/// `&` and stably sorted by name (the text before the first `=`), so `?b=2&a=1` and
/// `?a=1&b=2` agree; parameters that share a name keep their relative order, because
/// `?x=1&x=2` and `?x=2&x=1` can mean different things. Names are compared exactly:
/// case, escapes and empty segments are left alone, so nothing that differs is merged.
pub fn sorted_query(query: &str) -> Cow<'_, str> {
    if !query.contains('&') {
        return Cow::Borrowed(query);
    }
    let mut params: Vec<&str> = query.split('&').collect();
    fn name(p: &str) -> &str {
        p.split_once('=').map_or(p, |(n, _)| n)
    }
    if params.windows(2).all(|w| name(w[0]) <= name(w[1])) {
        return Cow::Borrowed(query); // already in order
    }
    params.sort_by(|a, b| name(a).cmp(name(b))); // stable
    Cow::Owned(params.join("&"))
}

/// The normalized form of `path`, or `None` when one pass of normalization does not reach a
/// canonical form. The result is what is routed, checked against policy and sent upstream,
/// and the upstream decodes it once more: a path that still has something to normalize after
/// the pass (decoding can complete an escape that a stray `%` had started) would be read
/// differently by zion and by the upstream. Such a path is refused, not iterated on: the
/// number of passes an adversarial path can demand grows with its length, and a path a
/// client writes honestly always reaches its canonical form in one.
pub fn try_normalize_path(path: &str) -> Option<Cow<'_, str>> {
    let out = normalize_path(path);
    if matches!(out, Cow::Borrowed(_)) || is_normal(&out) {
        Some(out)
    } else {
        None
    }
}

/// Rewrite `req`'s URI to its normalized path (query untouched). `Ok(())` when the request
/// was already normal or has been rewritten; `Err(())` when the path cannot be brought to a
/// canonical form in one pass (see [`try_normalize_path`]) or the normalized URI cannot be
/// rebuilt (the caller answers 400). Shared by the HTTPS pipeline and the plaintext :80
/// handler, which routes and forwards ACME challenges on its own.
pub fn rewrite_request<B>(req: &mut hyper::Request<B>) -> Result<(), ()> {
    let normalized = try_normalize_path(req.uri().path()).ok_or(())?;
    if matches!(normalized, Cow::Borrowed(_)) {
        return Ok(()); // already normal: no allocation, no rewrite
    }
    let pq = match req.uri().query() {
        Some(q) => format!("{normalized}?{q}"),
        None => normalized.into_owned(),
    };
    let mut parts = req.uri().clone().into_parts();
    parts.path_and_query = Some(pq.parse().map_err(|_| ())?);
    *req.uri_mut() = hyper::Uri::from_parts(parts).map_err(|_| ())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(p: &str) -> String {
        normalize_path(p).into_owned()
    }

    #[test]
    fn ordinary_paths_are_untouched() {
        for p in [
            "/",
            "/a",
            "/a/b",
            "/a/b/",
            "/a-b_c.d~e",
            "/a%2Fb",
            "/a%20b",
            "*",
            "/a.b/c..d/e",
        ] {
            assert_eq!(n(p), p, "{p}");
        }
        // no allocation when nothing changes — including paths that carry canonical escapes
        for p in [
            "/a/b",
            "/a%2Fb",
            "/a%20b",
            "/caf%C3%A9/x",
            "/a%2F..%2Fb",
            "/a/",
            "/",
            "/a%",
            "/a%2",
        ] {
            assert!(
                matches!(normalize_path(p), Cow::Borrowed(_)),
                "{p} must not allocate"
            );
        }
        for p in [
            "/a%2fb", "/a%41", "/a//b", "/a/./b", "/a/..", "//", "/a/b/.",
        ] {
            assert!(
                matches!(normalize_path(p), Cow::Owned(_)),
                "{p} must be rewritten"
            );
        }
    }

    #[test]
    fn dot_segments_are_removed_and_never_climb_above_the_root() {
        for (i, o) in [
            ("/a/./b", "/a/b"),
            ("/a/b/../c", "/a/c"),
            ("/a/b/..", "/a/"),
            ("/a/b/.", "/a/b/"),
            ("/a/../../b", "/b"),
            ("/../a", "/a"),
            ("/./", "/"),
            ("/a/b/../../..", "/"),
            ("/open/../internal/x", "/internal/x"),
            ("/a/b/../c/", "/a/c/"),
        ] {
            assert_eq!(n(i), o, "{i}");
        }
    }

    #[test]
    fn encoded_dots_are_dots_and_encoded_letters_are_letters() {
        for (i, o) in [
            ("/a/%2e%2e/b", "/b"),
            ("/a/%2E%2E/b", "/b"),
            ("/a/.%2e/b", "/b"),
            ("/a/%2e/b", "/a/b"),
            ("/%69nternal", "/internal"),
            ("/%41%62%43", "/AbC"),
            ("/a%2d%5f%7e", "/a-_~"),
        ] {
            assert_eq!(n(i), o, "{i}");
        }
    }

    #[test]
    fn other_escapes_keep_their_meaning_with_upper_case_hex() {
        assert_eq!(
            n("/a%2fb"),
            "/a%2Fb",
            "an encoded slash is data, not a separator"
        );
        assert_eq!(n("/a%5cb"), "/a%5Cb");
        assert_eq!(n("/a%20b%3f"), "/a%20b%3F");
        assert_eq!(
            n("/a%2f..%2fb"),
            "/a%2F..%2Fb",
            "dots hidden behind %2F are not dot segments"
        );
        for bad in ["/a%", "/a%2", "/a%zz", "/a%2g"] {
            assert_eq!(n(bad), bad, "a malformed escape is left as written: {bad}");
        }
    }

    #[test]
    fn repeated_slashes_collapse() {
        for (i, o) in [
            ("//a", "/a"),
            ("/a//b", "/a/b"),
            ("///", "/"),
            ("/a///b//", "/a/b/"),
            ("//internal/x", "/internal/x"),
        ] {
            assert_eq!(n(i), o, "{i}");
        }
    }

    #[test]
    fn normalization_is_idempotent() {
        for p in [
            "/a/../b//c/%2e%2E/d%2f/./e/",
            "/%2e%2e/%2e%2e",
            "//%2e//x//..",
            "/a%2Fb/%7Euser",
            "/",
        ] {
            let once = n(p);
            assert_eq!(n(&once), once, "{p} -> {once}");
        }
    }

    /// The one-pass fast check must agree with the full normalization on every input: if it
    /// says "normal" the slow path must leave the path alone, and if the slow path changes
    /// anything the fast check must not have claimed it normal. Exhaustive over a small
    /// alphabet that covers slashes, dots, escapes (both hex cases) and truncated escapes.
    #[test]
    fn the_fast_check_agrees_with_the_full_normalization() {
        let alphabet = ["/", ".", "%", "2", "e", "E", "F", "a", "4", "1", "z"];
        let mut checked = 0u32;
        // every string of length 1..=6 over the alphabet, prefixed with '/'
        let mut idx = [0usize; 6];
        for len in 1..=6usize {
            idx.iter_mut().for_each(|x| *x = 0);
            loop {
                let mut p = String::from("/");
                for k in 0..len {
                    p.push_str(alphabet[idx[k]]);
                }
                let changed = normalize_slow(&p) != p;
                assert_eq!(is_normal(&p), !changed, "{p:?}");
                checked += 1;
                // odometer over the first `len` digits
                let mut k = 0;
                loop {
                    if k == len {
                        break;
                    }
                    idx[k] += 1;
                    if idx[k] < alphabet.len() {
                        break;
                    }
                    idx[k] = 0;
                    k += 1;
                }
                if k == len {
                    break;
                }
            }
        }
        assert!(checked > 1_000_000, "covered {checked} inputs");
    }

    #[test]
    fn sorted_query_orders_by_name_and_keeps_repeated_names_in_order() {
        let q = |s: &str| sorted_query(s).into_owned();
        assert_eq!(q("b=2&a=1"), "a=1&b=2");
        assert_eq!(q("c=3&a=1&b=2"), "a=1&b=2&c=3");
        assert_eq!(q("x=2&x=1"), "x=2&x=1", "repeated names keep their order");
        assert_eq!(q("y=0&x=2&x=1&a"), "a&x=2&x=1&y=0");
        assert_eq!(q("b&a="), "a=&b", "a bare name sorts by its name");
        // different parameters are never merged, case and escapes are compared exactly
        assert_ne!(q("X=1"), q("x=1"));
        assert_ne!(q("a=1&b=2"), q("a=1&b=3"));
        assert_eq!(q("a=%2e&b=1"), "a=%2e&b=1");
        assert_eq!(q(""), "");
        assert_eq!(q("a=1"), "a=1");
        assert!(
            matches!(sorted_query("a=1&b=2"), Cow::Borrowed(_)),
            "already ordered: no allocation"
        );
        assert!(matches!(sorted_query("a=1"), Cow::Borrowed(_)));
    }

    #[test]
    fn sorted_query_is_idempotent_and_a_permutation() {
        for s in [
            "z=1&y=2&x=3&x=1&&a",
            "b&a&c&b=2&b=1",
            "=1&a=&=",
            "q=1&Q=2&q=0",
        ] {
            let once = sorted_query(s).into_owned();
            assert_eq!(sorted_query(&once), once, "{s}");
            let mut a: Vec<&str> = s.split('&').collect();
            let mut b: Vec<&str> = once.split('&').collect();
            a.sort();
            b.sort();
            assert_eq!(a, b, "{s}: same parameters, only reordered");
        }
    }

    #[test]
    fn non_ascii_survives() {
        assert_eq!(n("/caf\u{e9}//x"), "/caf\u{e9}/x");
        assert_eq!(n("/caf%C3%A9/./x"), "/caf%C3%A9/x");
    }
}
