// SPDX-License-Identifier: Apache-2.0
//! Per-route request restrictions (#693): `methods`, `content_types` and `deny_paths`.
//!
//! None of them needs a WAF profile. They are checked once the route is known, after CORS
//! (so a preflight is still answered) and `internal_only`, and before an upstream is chosen,
//! so a refused request costs no upstream work.

use crate::http_util::{empty_response, ZionBody};
use hyper::header::HeaderValue;
use hyper::{Method, Request, Response, StatusCode};

/// The methods a route may list: the ones zion accepts at all (the others are refused before
/// routing, so listing them would be dead config).
const ROUTE_METHODS: [Method; 7] = [
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
];

/// A route's `methods`, `content_types` and `deny_paths`, validated when the config is read.
#[derive(Clone, Debug, Default)]
pub struct RouteRestrictions {
    methods: Option<Methods>,
    /// Lowercase `type/subtype` media types.
    content_types: Option<Vec<String>>,
    /// Compiled like `[[route]] path` (see `config::compile_path_set`).
    deny_paths: Option<matchit::Router<()>>,
}

#[derive(Clone, Debug)]
struct Methods {
    list: Vec<Method>,
    /// The `Allow` value of a 405, in a fixed order.
    allow: HeaderValue,
}

impl RouteRestrictions {
    /// Validate the three keys of route `route` as written. `None` = the key is absent.
    pub fn build(
        route: &str,
        methods: Option<Vec<String>>,
        content_types: Option<Vec<String>>,
        deny_paths: Option<Vec<String>>,
    ) -> Result<Self, String> {
        Ok(Self {
            methods: methods.map(|m| parse_methods(route, &m)).transpose()?,
            content_types: content_types
                .map(|c| parse_content_types(route, &c))
                .transpose()?,
            deny_paths: deny_paths
                .map(|p| parse_deny_paths(route, &p))
                .transpose()?,
        })
    }

    /// Does the route set any restriction?
    pub fn is_empty(&self) -> bool {
        self.methods.is_none() && self.content_types.is_none() && self.deny_paths.is_none()
    }

    /// Is `path` one of the route's `deny_paths`?
    pub fn denies_path(&self, path: &str) -> bool {
        self.deny_paths.as_ref().is_some_and(|d| d.at(path).is_ok())
    }

    /// The answer to a request the route refuses, or `None` to let it through.
    /// `deny_paths` (403), then `methods` (405), then `content_types` (415).
    pub fn check<B: hyper::body::Body>(&self, req: &Request<B>) -> Option<Response<ZionBody>> {
        if self.denies_path(req.uri().path()) {
            return Some(empty_response(StatusCode::FORBIDDEN));
        }
        if let Some(methods) = &self.methods {
            if !methods.list.contains(req.method()) {
                let mut resp = empty_response(StatusCode::METHOD_NOT_ALLOWED);
                resp.headers_mut()
                    .insert(hyper::header::ALLOW, methods.allow.clone());
                return Some(resp);
            }
        }
        if let Some(allowed) = &self.content_types {
            // Only a request that carries a body declares what it is (a GET, or a POST with
            // `Content-Length: 0`, has nothing to label).
            if !hyper::body::Body::is_end_stream(req.body()) {
                let ok = req
                    .headers()
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|ct| crate::waf::content_type_allowed(ct, allowed));
                if !ok {
                    return Some(empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE));
                }
            }
        }
        None
    }
}

fn parse_methods(route: &str, written: &[String]) -> Result<Methods, String> {
    if written.is_empty() {
        return Err(format!(
            "route '{route}' sets `methods = []`, which refuses every request; list the methods \
             it serves or remove the key"
        ));
    }
    let mut list: Vec<Method> = Vec::new();
    for m in written {
        let Some(method) = ROUTE_METHODS.iter().find(|k| k.as_str() == m) else {
            return Err(format!(
                "route '{route}' lists '{m}' in `methods`; a route can list GET, HEAD, POST, PUT, \
                 PATCH, DELETE and OPTIONS (in capitals), the methods zion accepts at all"
            ));
        };
        if !list.contains(method) {
            list.push(method.clone());
        }
    }
    // A route that serves GET serves HEAD (RFC 9110 §9.3.2), as nginx's `limit_except GET` does.
    if list.contains(&Method::GET) && !list.contains(&Method::HEAD) {
        list.push(Method::HEAD);
    }
    let in_order: Vec<&str> = ROUTE_METHODS
        .iter()
        .filter(|k| list.contains(k))
        .map(Method::as_str)
        .collect();
    let allow = HeaderValue::from_str(&in_order.join(", "))
        .map_err(|e| format!("route '{route}': `methods`: {e}"))?;
    Ok(Methods { list, allow })
}

fn parse_content_types(route: &str, written: &[String]) -> Result<Vec<String>, String> {
    if written.is_empty() {
        return Err(format!(
            "route '{route}' sets `content_types = []`, which refuses every request body; list \
             the media types it accepts or remove the key"
        ));
    }
    written
        .iter()
        .map(|ct| {
            let well_formed = ct.split_once('/').is_some_and(|(t, s)| {
                let token = |x: &str| {
                    !x.is_empty()
                        && x.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
                };
                token(t) && token(s)
            });
            if well_formed {
                Ok(ct.to_ascii_lowercase())
            } else {
                Err(format!(
                    "route '{route}' lists '{ct}' in `content_types`; write a media type as \
                     `type/subtype`, without parameters or wildcards (for example \
                     \"application/json\")"
                ))
            }
        })
        .collect()
}

fn parse_deny_paths(route: &str, written: &[String]) -> Result<matchit::Router<()>, String> {
    if written.is_empty() {
        return Err(format!(
            "route '{route}' sets `deny_paths = []`, which denies nothing; remove the key"
        ));
    }
    if let Some(p) = written.iter().find(|p| !p.starts_with('/')) {
        return Err(format!(
            "route '{route}' lists '{p}' in `deny_paths`; a path starts with '/'"
        ));
    }
    crate::config::compile_path_set(written)
        .map_err(|e| format!("route '{route}': `deny_paths`: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{Empty, Full};

    fn build(m: Option<&[&str]>, c: Option<&[&str]>, d: Option<&[&str]>) -> RouteRestrictions {
        try_build(m, c, d).expect("valid restrictions")
    }

    fn try_build(
        m: Option<&[&str]>,
        c: Option<&[&str]>,
        d: Option<&[&str]>,
    ) -> Result<RouteRestrictions, String> {
        let own = |v: Option<&[&str]>| v.map(|v| v.iter().map(|s| s.to_string()).collect());
        RouteRestrictions::build("/r", own(m), own(c), own(d))
    }

    fn req(method: &str, path: &str, ct: Option<&str>, body: &'static str) -> Request<Full<Bytes>> {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(ct) = ct {
            b = b.header(hyper::header::CONTENT_TYPE, ct);
        }
        b.body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap()
    }

    fn status(r: &RouteRestrictions, req: &Request<Full<Bytes>>) -> u16 {
        r.check(req).map_or(200, |resp| resp.status().as_u16())
    }

    #[test]
    fn no_keys_restrict_nothing() {
        let r = build(None, None, None);
        assert!(r.is_empty());
        assert_eq!(
            status(&r, &req("DELETE", "/anything", Some("x/y"), "b")),
            200
        );
    }

    #[test]
    fn a_method_not_listed_is_405_with_allow() {
        let r = build(Some(&["POST", "GET"]), None, None);
        assert_eq!(status(&r, &req("GET", "/", None, "")), 200);
        assert_eq!(status(&r, &req("POST", "/", None, "")), 200);
        let resp = r.check(&req("DELETE", "/", None, "")).expect("refused");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.headers()[hyper::header::ALLOW], "GET, HEAD, POST");
    }

    #[test]
    fn get_brings_head_and_nothing_else_does() {
        let r = build(Some(&["GET"]), None, None);
        assert_eq!(status(&r, &req("HEAD", "/", None, "")), 200);
        let r = build(Some(&["POST"]), None, None);
        assert_eq!(status(&r, &req("HEAD", "/", None, "")), 405);
        assert_eq!(status(&r, &req("OPTIONS", "/", None, "")), 405);
    }

    #[test]
    fn methods_are_written_in_capitals_and_known() {
        for bad in [&["get"][..], &["TRACE"], &["CONNECT"], &[]] {
            let e = try_build(Some(bad), None, None).unwrap_err();
            assert!(e.contains("methods"), "{e}");
        }
    }

    #[test]
    fn a_body_of_an_unlisted_type_is_415() {
        let r = build(None, Some(&["application/json"]), None);
        assert_eq!(
            status(&r, &req("POST", "/", Some("application/json"), "{}")),
            200
        );
        assert_eq!(
            status(
                &r,
                &req("POST", "/", Some("Application/JSON; charset=utf-8"), "{}")
            ),
            200
        );
        let multipart = "multipart/form-data; boundary=x";
        assert_eq!(status(&r, &req("POST", "/", Some(multipart), "--x")), 415);
        assert_eq!(
            status(&r, &req("POST", "/", Some("text/x-component"), "0:")),
            415
        );
        // `application/jsonp` is another type, not a `application/json` with a suffix.
        assert_eq!(
            status(&r, &req("POST", "/", Some("application/jsonp"), "x")),
            415
        );
        // A body with no Content-Type says nothing about itself: refused.
        assert_eq!(status(&r, &req("POST", "/", None, "{}")), 415);
    }

    #[test]
    fn a_request_without_a_body_needs_no_content_type() {
        let r = build(None, Some(&["application/json"]), None);
        assert_eq!(status(&r, &req("GET", "/", None, "")), 200);
        assert_eq!(status(&r, &req("POST", "/", Some("text/plain"), "")), 200);
        let empty = Request::post("/").body(Empty::<Bytes>::new()).unwrap();
        assert!(r.check(&empty).is_none());
    }

    #[test]
    fn content_types_are_bare_media_types() {
        let r = build(None, Some(&["Application/JSON"]), None);
        assert_eq!(
            status(&r, &req("POST", "/", Some("application/json"), "{}")),
            200
        );
        for bad in [
            &["application/json; charset=utf-8"][..],
            &["text/*"],
            &["json"],
            &["/json"],
            &[],
        ] {
            let e = try_build(None, Some(bad), None).unwrap_err();
            assert!(e.contains("content_types"), "{e}");
        }
    }

    #[test]
    fn a_denied_path_is_403_with_the_route_syntax() {
        let r = build(None, None, Some(&["/wp-json/batch/{*rest}", "/admin"]));
        for denied in [
            "/wp-json/batch/v1",
            "/wp-json/batch/v1/x",
            "/wp-json/batch",
            "/wp-json/batch/",
            "/admin",
            "/admin/",
        ] {
            assert_eq!(status(&r, &req("POST", denied, None, "")), 403, "{denied}");
        }
        for allowed in [
            "/wp-json/wp/v2/posts",
            "/wp-json/batchx",
            "/administrator",
            "/",
        ] {
            assert_eq!(
                status(&r, &req("POST", allowed, None, "")),
                200,
                "{allowed}"
            );
        }
    }

    #[test]
    fn deny_paths_are_absolute_route_patterns() {
        for bad in [&["admin"][..], &["/a/{*x}/b"], &[]] {
            let e = try_build(None, None, Some(bad)).unwrap_err();
            assert!(e.contains("deny_paths"), "{e}");
        }
    }

    #[test]
    fn deny_paths_answer_before_methods_and_methods_before_content_types() {
        let r = build(
            Some(&["POST"]),
            Some(&["application/json"]),
            Some(&["/blocked"]),
        );
        assert_eq!(status(&r, &req("GET", "/blocked", None, "")), 403);
        assert_eq!(status(&r, &req("GET", "/ok", Some("text/plain"), "x")), 405);
        assert_eq!(
            status(&r, &req("POST", "/ok", Some("text/plain"), "x")),
            415
        );
    }
}
