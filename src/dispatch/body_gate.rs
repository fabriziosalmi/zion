// SPDX-License-Identifier: Apache-2.0
//! The body stage of the pipeline (#693): `max_body_mb` on a route without a WAF, and
//! `require_content_length`.
//!
//! It runs after the WAF stage, which reads the whole body of a route that has a WAF. A body
//! that reaches it is therefore either already whole or still on the wire.

// The `Err` of this stage is the response that ends the request, as in `waf_gate`.
#![allow(clippy::result_large_err)]

use super::*;
use crate::upstream_body::BodyCap;
use hyper::body::Body;
use hyper::header::{HeaderValue, CONTENT_LENGTH, TRANSFER_ENCODING};

/// How much `require_content_length` reads on a route that sets no `max_body_mb`: the body cap
/// of the WAF when it has none either.
const DEFAULT_BUFFER_CAP: u64 = 10 * 1_048_576;

/// Apply the route's body cap and `require_content_length`.
///
/// - A body that declares a length past the cap is answered `413` before a byte of it is read.
/// - A body without a declared length is read whole under `require_content_length` (`413` past
///   the cap, `408` after 60 s) and goes on with `Content-Length`. Otherwise it is streamed,
///   counted against the cap by the proxy (see `upstream_body`).
///
/// `Ok` is the request to carry on with; `Err` is the response that ends it.
pub(super) async fn run(
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    mut req: Request<ZionBody>,
) -> Result<Request<ZionBody>, Response<ZionBody>> {
    if rule.body_cap.is_none() && !rule.require_content_length {
        return Ok(req);
    }
    if req.body().is_end_stream() {
        return Ok(req);
    }
    // hyper knows the length of an HTTP/1.1 body from `Content-Length` and of an HTTP/2 one
    // from the header too, and holds the body to it. The header alone is a claim (HTTP/3).
    let known = req.body().size_hint().exact();
    if let Some(cap) = rule.body_cap {
        let declared = known.or_else(|| content_length(req.headers()));
        if declared.is_some_and(|len| len > cap) {
            return Err(text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
    }
    match known {
        // The upstream client sends a body of known length with `Content-Length` (hyper sets it
        // from the length on HTTP/1.1 and HTTP/2), a body the WAF has read included.
        Some(_) => Ok(req),
        None if rule.require_content_length => read_whole(rule, remote_addr, req).await,
        None => {
            if let Some(cap) = rule.body_cap {
                req.extensions_mut().insert(BodyCap(cap));
            }
            Ok(req)
        }
    }
}

/// The value of a single valid `Content-Length`, if the request has one.
fn content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let len = values.next()?.to_str().ok()?.parse().ok()?;
    values.next().is_none().then_some(len)
}

/// Read a body of unknown length whole, within the route's cap and 60 s, and put it back with
/// the `Content-Length` it turned out to have.
async fn read_whole(
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    req: Request<ZionBody>,
) -> Result<Request<ZionBody>, Response<ZionBody>> {
    let cap = rule.body_cap.unwrap_or(DEFAULT_BUFFER_CAP);
    let (mut parts, body) = req.into_parts();
    let limited = Limited::new(body, usize::try_from(cap).unwrap_or(usize::MAX));
    let bytes = match tokio::time::timeout(BODY_COLLECT_TIMEOUT, limited.collect()).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) => {
            let (status, msg) = body_read_failure(e.as_ref());
            if status != StatusCode::PAYLOAD_TOO_LARGE {
                log_body_failure(
                    &remote_addr,
                    parts.method.as_str(),
                    parts.uri.path(),
                    &e.to_string(),
                );
            }
            return Err(text_response(status, msg));
        }
        Err(_elapsed) => {
            log_body_failure(
                &remote_addr,
                parts.method.as_str(),
                parts.uri.path(),
                "not complete after 60 s",
            );
            return Err(text_response(
                StatusCode::REQUEST_TIMEOUT,
                "request body read timeout",
            ));
        }
    };
    parts.headers.remove(TRANSFER_ENCODING);
    // An empty body (an HTTP/3 GET, say) gets no header, unless the request claimed a length.
    if !bytes.is_empty() || parts.headers.contains_key(CONTENT_LENGTH) {
        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    }
    let body: ZionBody = Full::new(bytes).map_err(|never| match never {}).boxed();
    Ok(Request::from_parts(parts, body))
}
