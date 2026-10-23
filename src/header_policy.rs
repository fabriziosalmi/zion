// SPDX-License-Identifier: Apache-2.0
//! Request headers and cookies a route strips or refuses (#695): `strip_headers`,
//! `deny_headers` and `deny_cookies`, in `[server]` for every route and in `[[route]]` for
//! one (a route's lists add to the global ones).
//!
//! Built in, on every route:
//!   * `X-Middleware-Subrequest` and `HTTP2-Settings` are stripped. The first is how Next.js
//!     marks its own middleware subrequests, and a client that sends it skips the middleware
//!     (CVE-2025-29927); the second only means something with an `h2c` upgrade, which zion
//!     never forwards (`Upgrade` is removed on every request that is not a WebSocket
//!     handshake, in `proxy::prepare_request`).
//!   * A header named `__proto__` or `constructor` is refused: an upstream that copies the
//!     headers into a JavaScript object pollutes its prototype.
//!
//! Names are compared without case, and with `_` and `-` as the same character: a CGI or PHP
//! upstream reads `X_Debug` as `X-Debug` (both become `HTTP_X_DEBUG`). Cookie names are
//! compared exactly (RFC 6265 names are case-sensitive) and also percent-decoded, because PHP
//! decodes them (`%43acheWarmer` is `CacheWarmer` to it).

use crate::http_util::{empty_response, ZionBody};
use hyper::header::{HeaderMap, HeaderName, COOKIE};
use hyper::{Response, StatusCode};

/// Stripped on every route.
const BUILT_IN_STRIP: [&str; 2] = ["x-middleware-subrequest", "http2-settings"];
/// Refused on every route.
const BUILT_IN_DENY: [&str; 2] = ["__proto__", "constructor"];

/// The `[server]` lists, validated once and shared by every route's policy.
#[derive(Clone, Debug, Default)]
pub struct HeaderLists {
    strip: Vec<String>,
    deny: Vec<String>,
    deny_cookies: Vec<String>,
}

impl HeaderLists {
    /// Validate the three lists of `owner` (`[server]` or a route) as written.
    pub fn build(
        owner: &str,
        strip: Vec<String>,
        deny: Vec<String>,
        deny_cookies: Vec<String>,
    ) -> Result<Self, String> {
        Ok(Self {
            strip: header_names(owner, "strip_headers", strip)?,
            deny: header_names(owner, "deny_headers", deny)?,
            deny_cookies: cookie_names(owner, deny_cookies)?,
        })
    }
}

/// What one route strips and refuses: the built-in names, the global lists, the route's own.
#[derive(Clone, Debug)]
pub struct HeaderPolicy {
    /// Lower-case, `_` folded to `-`.
    strip: Vec<String>,
    /// Lower-case, `_` folded to `-`.
    deny: Vec<String>,
    /// As written.
    deny_cookies: Vec<String>,
}

impl HeaderPolicy {
    /// The built-in names plus `global` plus `route`, each name once.
    pub fn merge(global: &HeaderLists, route: &HeaderLists) -> Self {
        fn union(names: impl Iterator<Item = String>) -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for name in names {
                if !out.contains(&name) {
                    out.push(name);
                }
            }
            out
        }
        let lists = |built_in: &[&str], g: &[String], r: &[String]| {
            union(
                built_in
                    .iter()
                    .map(|n| fold(n))
                    .chain(g.iter().cloned())
                    .chain(r.iter().cloned()),
            )
        };
        Self {
            strip: lists(&BUILT_IN_STRIP, &global.strip, &route.strip),
            deny: lists(&BUILT_IN_DENY, &global.deny, &route.deny),
            deny_cookies: lists(&[], &global.deny_cookies, &route.deny_cookies),
        }
    }

    /// Apply the policy to a request's headers: `Some(400)` when it carries a refused header
    /// or cookie, otherwise strip what the policy strips and `None`.
    pub fn apply(&self, headers: &mut HeaderMap) -> Option<Response<ZionBody>> {
        // One pass over the names the request carries (a handful); the removals run only
        // for a hit.
        let mut to_strip: Vec<HeaderName> = Vec::new();
        for name in headers.keys() {
            let n = name.as_str();
            if self.deny.iter().any(|d| same_name(d, n)) {
                return Some(empty_response(StatusCode::BAD_REQUEST));
            }
            if self.strip.iter().any(|s| same_name(s, n)) {
                to_strip.push(name.clone());
            }
        }
        if !self.deny_cookies.is_empty() {
            for value in headers.get_all(COOKIE) {
                let Ok(value) = value.to_str() else { continue };
                if value.split(';').any(|pair| {
                    let name = pair.split_once('=').map_or(pair, |(n, _)| n).trim();
                    self.deny_cookies
                        .iter()
                        .any(|d| d == name || percent_decoded(name).is_some_and(|n| *d == n))
                }) {
                    return Some(empty_response(StatusCode::BAD_REQUEST));
                }
            }
        }
        for name in to_strip {
            headers.remove(name);
        }
        None
    }
}

/// `name` lower-cased (hyper stores it so) with `_` as `-`.
fn fold(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// `folded` (from [`fold`]) and a request header name (lower-case) are the same name, with
/// `_` and `-` as one character.
fn same_name(folded: &str, name: &str) -> bool {
    folded.len() == name.len()
        && folded
            .bytes()
            .zip(name.bytes())
            .all(|(a, b)| a == b || (a == b'-' && b == b'_'))
}

/// `name` with its percent-escapes decoded, or `None` when it has none (or a malformed one,
/// or decodes to bytes that are not UTF-8).
fn percent_decoded(name: &str) -> Option<String> {
    if !name.contains('%') {
        return None;
    }
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            let (h, l) = (hex(*b.get(i + 1)?)?, hex(*b.get(i + 2)?)?);
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn header_names(owner: &str, key: &str, written: Vec<String>) -> Result<Vec<String>, String> {
    written
        .into_iter()
        .map(|n| {
            HeaderName::from_bytes(n.as_bytes())
                .map(|h| fold(h.as_str()))
                .map_err(|_| format!("{owner} lists '{n}' in `{key}`, which is not a header name"))
        })
        .collect()
}

fn cookie_names(owner: &str, written: Vec<String>) -> Result<Vec<String>, String> {
    // RFC 6265 §4.1.1: a cookie name is an RFC 9110 token.
    let token = |n: &str| {
        !n.is_empty()
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    written
        .into_iter()
        .map(|n| {
            if token(&n) {
                Ok(n)
            } else {
                Err(format!(
                    "{owner} lists '{n}' in `deny_cookies`, which is not a cookie name"
                ))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists(strip: &[&str], deny: &[&str], cookies: &[&str]) -> HeaderLists {
        let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        HeaderLists::build("test", own(strip), own(deny), own(cookies)).expect("valid lists")
    }

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    fn refused(p: &HeaderPolicy, pairs: &[(&str, &str)]) -> bool {
        p.apply(&mut map(pairs)).is_some()
    }

    #[test]
    fn the_built_in_names_apply_with_no_configuration() {
        let p = HeaderPolicy::merge(&HeaderLists::default(), &HeaderLists::default());
        let mut h = map(&[
            ("x-middleware-subrequest", "middleware"),
            ("http2-settings", "AAMA"),
            ("accept", "*/*"),
        ]);
        assert!(p.apply(&mut h).is_none());
        assert_eq!(h.len(), 1, "only Accept is left: {h:?}");
        for name in ["__proto__", "constructor", "Constructor", "--proto--"] {
            assert!(refused(&p, &[(name, "x")]), "{name}");
        }
    }

    #[test]
    fn a_request_with_none_of_them_is_left_exactly_as_it_was() {
        let p = HeaderPolicy::merge(
            &lists(&["x-debug"], &["x-evil"], &["CacheWarmer"]),
            &HeaderLists::default(),
        );
        let mut h = map(&[
            ("accept", "*/*"),
            ("cookie", "session=abc; theme=dark"),
            ("x-request-id", "1"),
        ]);
        let before = h.clone();
        assert!(p.apply(&mut h).is_none());
        assert_eq!(h, before);
    }

    #[test]
    fn underscores_and_dashes_name_the_same_header() {
        let p = HeaderPolicy::merge(
            &lists(&["X-Debug"], &["X_Evil"], &[]),
            &HeaderLists::default(),
        );
        for name in ["x-evil", "x_evil", "X-EVIL"] {
            assert!(refused(&p, &[(name, "1")]), "{name}");
        }
        let mut h = map(&[("x-debug", "1"), ("x_debug", "2"), ("x-debugger", "3")]);
        assert!(p.apply(&mut h).is_none());
        assert_eq!(
            h.keys().map(|k| k.as_str()).collect::<Vec<_>>(),
            ["x-debugger"],
            "both spellings stripped, a longer name kept"
        );
    }

    #[test]
    fn a_cookie_is_refused_by_its_exact_or_percent_decoded_name() {
        let p = HeaderPolicy::merge(&lists(&[], &[], &["CacheWarmer"]), &HeaderLists::default());
        for cookie in [
            "CacheWarmer=O:8:\"stdClass\":0:{}",
            "a=1; CacheWarmer=x",
            "a=1;CacheWarmer=x",
            " CacheWarmer =x",
            "%43acheWarmer=x",
            "CacheWarmer",
        ] {
            assert!(refused(&p, &[("cookie", cookie)]), "{cookie}");
        }
        // HTTP/2 may send each cookie in its own field
        assert!(refused(
            &p,
            &[("cookie", "a=1"), ("cookie", "CacheWarmer=x")]
        ));
        for cookie in ["cachewarmer=x", "CacheWarmerX=x", "a=CacheWarmer", "%zz=1"] {
            assert!(!refused(&p, &[("cookie", cookie)]), "{cookie}");
        }
    }

    #[test]
    fn a_routes_lists_add_to_the_global_ones() {
        let p = HeaderPolicy::merge(
            &lists(&["x-a"], &["x-deny-a"], &["ca"]),
            &lists(&["x-b", "x-a"], &["x-deny-b"], &["cb"]),
        );
        assert_eq!(
            p.strip,
            ["x-middleware-subrequest", "http2-settings", "x-a", "x-b"]
        );
        assert!(refused(&p, &[("x-deny-a", "1")]));
        assert!(refused(&p, &[("x-deny-b", "1")]));
        assert!(refused(&p, &[("cookie", "ca=1")]));
        assert!(refused(&p, &[("cookie", "cb=1")]));
    }

    #[test]
    fn names_that_are_not_names_are_refused_when_the_config_is_read() {
        let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let e = HeaderLists::build("route '/x'", own(&["bad name"]), vec![], vec![]).unwrap_err();
        assert!(
            e.contains("route '/x'") && e.contains("strip_headers"),
            "{e}"
        );
        let e = HeaderLists::build("[server]", vec![], own(&["a:b"]), vec![]).unwrap_err();
        assert!(e.contains("deny_headers"), "{e}");
        for bad in ["", "a=b", "a;b", "a b"] {
            let e = HeaderLists::build("[server]", vec![], vec![], own(&[bad])).unwrap_err();
            assert!(e.contains("deny_cookies"), "{bad:?}: {e}");
        }
    }
}
