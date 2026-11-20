// SPDX-License-Identifier: Apache-2.0
//! Request-ID generation and the small response builders shared by the
//! request pipeline (`dispatch`, `admin`, `quic`, the listeners).
//!
//! These lived in the crate root (`main.rs`), which made every consumer depend
//! on the module that wires them together (ZION-ARCH-01). They are pure helpers
//! with no dependency on `AppState`, so they sit here and the root only
//! composes.

use crate::security;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{Response, StatusCode};

/// BoxBody used throughout Zion — erases concrete body types. It lives here, with the
/// helpers that build it, so that the modules that only shape responses (`security`,
/// `static_files`, `bulkhead`) do not depend on the upstream client in `proxy` for a type
/// (ZION-ARCH-07, #532).
pub type ZionBody = BoxBody<Bytes, hyper::Error>;

/// The error of a request body: hyper's, or one zion raises itself.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body of a request on its way through the pipeline. Its error is not a `hyper::Error`,
/// which only hyper can build: a body zion reads from somewhere else (an HTTP/3 stream) or
/// counts against a cap must be able to end with an error of its own, so that a reader can tell
/// a broken body from a complete one.
pub type ReqBody = BoxBody<Bytes, BoxError>;

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

/// RFC 9110 §7.6.1: an intermediary MUST remove, before forwarding, every header field named in
/// the `Connection` header (they are hop-by-hop for the sender and the intermediary, not for the
/// next recipient). `Connection: keep-alive, X-Remove-Me` makes `X-Remove-Me` ours to drop.
///
/// The connection options `close`, `keep-alive` and `upgrade` name no field and are skipped
/// (`Upgrade` stays what the WebSocket handshake needs). Run it where the request comes in, before
/// anything of ours is added: a client that lists `X-Client-Cert-Fingerprint` or `X-Auth-Subject`
/// must not be able to make us drop the value we set after this point.
///
/// `X-Forwarded-For` is not dropped either: it is addressed to zion, which reads it to resolve the
/// client behind a trusted proxy and then applies `xff_mode` to what it forwards. Dropping it here
/// let a client behind such a proxy (one that passed the `Connection` token on) become the proxy
/// itself, internal under the default rule.
pub(crate) fn strip_connection_listed(headers: &mut hyper::HeaderMap) {
    if !headers.contains_key(hyper::header::CONNECTION) {
        return;
    }
    let mut named: Vec<hyper::header::HeaderName> = Vec::new();
    for value in headers.get_all(hyper::header::CONNECTION) {
        let Ok(value) = value.to_str() else { continue };
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty()
                || token.eq_ignore_ascii_case("close")
                || token.eq_ignore_ascii_case("keep-alive")
                || token.eq_ignore_ascii_case("upgrade")
                || token.eq_ignore_ascii_case("x-forwarded-for")
            {
                continue;
            }
            if let Ok(name) = hyper::header::HeaderName::from_bytes(token.as_bytes()) {
                named.push(name);
            }
        }
    }
    for name in named {
        headers.remove(name);
    }
}

#[cfg(test)]
mod connection_listed_tests {
    use super::strip_connection_listed;
    use hyper::HeaderMap;

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn the_headers_connection_names_are_removed_and_the_rest_is_kept() {
        let mut h = map(&[
            ("connection", "keep-alive, X-Remove-Me"),
            ("x-remove-me", "1"),
            ("x-remove-me", "2"),
            ("x-keep", "yes"),
            ("host", "a.example"),
        ]);
        strip_connection_listed(&mut h);
        assert!(!h.contains_key("x-remove-me"), "every copy goes");
        assert!(h.contains_key("x-keep") && h.contains_key("host"));
    }

    #[test]
    fn several_connection_lines_empty_elements_and_any_case_are_read() {
        let mut h = map(&[
            ("connection", "close"),
            ("connection", " , X-A ,,x-B"),
            ("x-a", "1"),
            ("x-b", "2"),
            ("x-c", "3"),
        ]);
        strip_connection_listed(&mut h);
        assert!(!h.contains_key("x-a") && !h.contains_key("x-b"));
        assert!(h.contains_key("x-c"));
    }

    #[test]
    fn connection_options_name_no_field_and_upgrade_survives_for_websockets() {
        let mut h = map(&[
            ("connection", "Upgrade, keep-alive, close"),
            ("upgrade", "websocket"),
        ]);
        strip_connection_listed(&mut h);
        assert!(h.contains_key("upgrade"), "the handshake needs it");
        assert!(
            h.contains_key("connection"),
            "the caller decides about Connection itself"
        );
    }

    #[test]
    fn x_forwarded_for_is_kept_for_the_client_ip_resolution() {
        let mut h = map(&[
            ("connection", "keep-alive, X-Forwarded-For, x-a"),
            ("x-forwarded-for", "10.0.0.1"),
            ("x-forwarded-for", "203.0.113.9"),
            ("x-a", "1"),
        ]);
        strip_connection_listed(&mut h);
        assert_eq!(h.get_all("x-forwarded-for").iter().count(), 2);
        assert!(!h.contains_key("x-a"));
    }

    #[test]
    fn a_token_that_is_not_a_header_name_is_ignored_and_no_connection_header_is_a_no_op() {
        let mut h = map(&[
            ("connection", "not a header, X-A"),
            ("x-a", "1"),
            ("x-b", "2"),
        ]);
        strip_connection_listed(&mut h);
        assert!(!h.contains_key("x-a") && h.contains_key("x-b"));
        let mut none = map(&[("x-a", "1")]);
        strip_connection_listed(&mut none);
        assert!(none.contains_key("x-a"));
    }
}

/// The `Cache-Control` of a request or a response: every field line, read as one list.
///
/// RFC 9110 §5.3: a field sent on several lines means what one line with their values joined by
/// commas means, so `Cache-Control: max-age=300` followed by `Cache-Control: private` is
/// `max-age=300, private` (nginx sends exactly that with `expires 5m;` and
/// `add_header Cache-Control private;`). hyper keeps each line as its own value, and a reader that
/// took the first one (`HeaderMap::get`) stored that `private` response in the shared cache and
/// served it to other users. Every reader of `Cache-Control` goes through this type, so none can
/// look at one line only.
///
/// Values are read as bytes: a line that is not visible ASCII still counts.
#[derive(Clone, Copy)]
pub(crate) struct CacheControl<'a> {
    headers: &'a hyper::HeaderMap,
}

/// One directive of a [`CacheControl`] list (RFC 9111 §5.2): `name` or `name=argument`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CacheDirective<'a> {
    name: &'a [u8],
    arg: Option<&'a [u8]>,
}

impl CacheDirective<'_> {
    /// The directive is `name` (directive names are case-insensitive, RFC 9111 §5.2).
    pub(crate) fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }

    /// The argument as seconds (`max-age=60`, `max-age="60"`); `None` when there is none or it
    /// is not a number.
    pub(crate) fn seconds(&self) -> Option<u64> {
        let arg = self.arg?;
        let arg = arg
            .strip_prefix(b"\"")
            .and_then(|a| a.strip_suffix(b"\""))
            .unwrap_or(arg);
        std::str::from_utf8(arg).ok()?.trim().parse().ok()
    }
}

impl<'a> CacheControl<'a> {
    pub(crate) fn of(headers: &'a hyper::HeaderMap) -> Self {
        Self { headers }
    }

    /// Every directive of every line, in order. Elements are separated by commas; empty ones
    /// (`a,,b`, a trailing comma) are skipped. The name is what comes before the first `=`,
    /// the argument what comes after it, both trimmed.
    pub(crate) fn directives(self) -> impl Iterator<Item = CacheDirective<'a>> {
        self.headers
            .get_all(hyper::header::CACHE_CONTROL)
            .iter()
            .flat_map(|line| line.as_bytes().split(|&b| b == b','))
            .filter_map(|element| {
                let element = element.trim_ascii();
                let (name, arg) = match element.iter().position(|&b| b == b'=') {
                    Some(i) => (
                        element[..i].trim_ascii(),
                        Some(element[i + 1..].trim_ascii()),
                    ),
                    None => (element, None),
                };
                (!name.is_empty()).then_some(CacheDirective { name, arg })
            })
    }

    /// A directive called `name` is present, on any line.
    pub(crate) fn has(self, name: &str) -> bool {
        self.directives().any(|d| d.is(name))
    }

    /// The seconds of directive `name` (`max-age`, `s-maxage`, `stale-while-revalidate`), on
    /// any line. `None` when it is absent or none of its values is a number. Given twice with
    /// different values it is `0`: RFC 9111 §4.2.1 lets a cache use the first occurrence or
    /// consider the response stale, and stale is the reading that never keeps or serves a
    /// response for longer than either value allows.
    pub(crate) fn seconds(self, name: &str) -> Option<u64> {
        let mut found: Option<u64> = None;
        for secs in self
            .directives()
            .filter(|d| d.is(name))
            .filter_map(|d| d.seconds())
        {
            match found {
                Some(seen) if seen != secs => return Some(0),
                _ => found = Some(secs),
            }
        }
        found
    }

    /// `word` appears anywhere in the list, case-insensitively, whatever the directive
    /// boundaries. For the checks that must err on the side of refusing (`private`,
    /// `no-store`, `no-transform`): a directive hidden in an unusual spelling or a quoted
    /// argument still counts, as it does for nginx and Varnish.
    pub(crate) fn mentions(self, word: &str) -> bool {
        let word = word.as_bytes();
        self.headers
            .get_all(hyper::header::CACHE_CONTROL)
            .iter()
            .any(|line| {
                line.as_bytes()
                    .windows(word.len())
                    .any(|w| w.eq_ignore_ascii_case(word))
            })
    }
}

#[cfg(test)]
mod cache_control_tests {
    use super::CacheControl;
    use hyper::header::CACHE_CONTROL;
    use hyper::HeaderMap;

    fn lines(values: &[&[u8]]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(
                CACHE_CONTROL,
                hyper::header::HeaderValue::from_bytes(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn every_line_is_one_list() {
        let h = lines(&[b"max-age=300", b"private"]);
        let cc = CacheControl::of(&h);
        assert!(cc.has("private"), "a directive on the second line");
        assert!(cc.mentions("private"));
        assert_eq!(cc.seconds("max-age"), Some(300));
        assert_eq!(cc.directives().count(), 2);
        // three lines, empty elements and whitespace
        let h = lines(&[b" , public", b"", b"s-maxage = \"60\" ,, No-Transform "]);
        let cc = CacheControl::of(&h);
        assert!(cc.has("public") && cc.has("no-transform"));
        assert_eq!(cc.seconds("s-maxage"), Some(60));
        assert_eq!(cc.directives().count(), 3);
    }

    #[test]
    fn names_are_whole_and_case_insensitive() {
        let h = lines(&[b"x-public-ish, s-maxage-like=5, MAX-AGE=7"]);
        let cc = CacheControl::of(&h);
        assert!(!cc.has("public"), "a longer name is another directive");
        assert_eq!(cc.seconds("s-maxage"), None);
        assert_eq!(cc.seconds("max-age"), Some(7));
        assert!(cc.mentions("public"), "mentions is a substring search");
        assert!(!CacheControl::of(&HeaderMap::new()).mentions("private"));
    }

    #[test]
    fn seconds_ignore_a_non_number_and_read_a_conflict_as_stale() {
        let s = |v: &[&[u8]]| CacheControl::of(&lines(v)).seconds("max-age");
        assert_eq!(s(&[b"max-age=abc"]), None);
        assert_eq!(s(&[b"max-age=abc, max-age=60"]), Some(60));
        assert_eq!(s(&[b"max-age=60", b"max-age=60"]), Some(60), "a repeat");
        assert_eq!(s(&[b"max-age=300", b"max-age=60"]), Some(0), "a conflict");
        assert_eq!(s(&[b"max-age"]), None, "no argument");
        assert_eq!(s(&[b"max-age=99999999999999999999999"]), None, "overflow");
    }

    #[test]
    fn a_line_that_is_not_ascii_is_still_read() {
        let h = lines(&[b"max-age=60, x-\xe9t\xe9, private"]);
        let cc = CacheControl::of(&h);
        assert!(h.get(CACHE_CONTROL).unwrap().to_str().is_err());
        assert!(cc.has("private") && cc.mentions("private"));
        assert_eq!(cc.seconds("max-age"), Some(60));
    }
}

/// A URL without the `user:pass@` of its authority. Upstream URLs may carry basic-auth
/// credentials, and they are written to metric labels, the JSON snapshot, the logs and
/// config error messages: none of those may show them.
pub(crate) fn redact_userinfo(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        if let Some(at) = rest[..authority_end].rfind('@') {
            return format!("{}{}", &url[..scheme_end + 3], &rest[at + 1..]);
        }
    }
    url.to_string()
}

#[cfg(test)]
mod redact_tests {
    use super::redact_userinfo;

    #[test]
    fn userinfo_is_dropped_and_nothing_else() {
        for (url, shown) in [
            ("http://user:pw@host:80/p@th", "http://host:80/p@th"),
            ("https://token@api.internal", "https://api.internal"),
            ("http://u:p%40ss@h:1", "http://h:1"),
            // an `@` after the authority is not userinfo
            ("http://host/path?to=a@b", "http://host/path?to=a@b"),
            ("http://host?next=x@y", "http://host?next=x@y"),
            ("http://host#frag@x", "http://host#frag@x"),
            ("http://host:80", "http://host:80"),
            // not a URL: left alone
            ("host:8080", "host:8080"),
            ("", ""),
        ] {
            assert_eq!(redact_userinfo(url), shown, "{url}");
        }
    }
}
