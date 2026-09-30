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

/// The normalized form of `path` (the path component only, no query). Paths that do not
/// start with `/` (`*` for `OPTIONS *`) are returned unchanged.
pub fn normalize_path(path: &str) -> Cow<'_, str> {
    if !path.starts_with('/') {
        return Cow::Borrowed(path);
    }
    // Fast path: nothing that normalization touches.
    let plain = !path.contains('%')
        && !path.contains("//")
        && !path.contains("/./")
        && !path.contains("/../")
        && !path.ends_with("/.")
        && !path.ends_with("/..");
    if plain {
        return Cow::Borrowed(path);
    }
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
    if out == path {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(out)
    }
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
        assert!(
            matches!(normalize_path("/a/b"), Cow::Borrowed(_)),
            "no allocation when nothing changes"
        );
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

    #[test]
    fn non_ascii_survives() {
        assert_eq!(n("/caf\u{e9}//x"), "/caf\u{e9}/x");
        assert_eq!(n("/caf%C3%A9/./x"), "/caf%C3%A9/x");
    }
}
