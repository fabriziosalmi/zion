// SPDX-License-Identifier: Apache-2.0
//! The WAF stage of the pipeline: scan the target and the headers, then read and scan the body.

// The `Err` of these stages is the response that ends the request, built once on a rejection:
// boxing it would add an allocation to every refused request for nothing.
#![allow(clippy::result_large_err)]

use super::*;
use crate::config::WafProfile;

/// Run the route's WAF profile over the request.
///
/// `Ok` is the request to carry on with (its body, when it was read, put back); `Err` is the
/// response that ends it. In shadow mode a would-be block is counted and logged and the request
/// goes on.
pub(super) async fn run(
    rule: &ResolvedRoute,
    state: &AppState,
    remote_addr: SocketAddr,
    req: Request<ZionBody>,
) -> Result<Request<ZionBody>, Response<ZionBody>> {
    let Some(ref waf_profile) = rule.waf else {
        return Ok(req);
    };
    // Map method to a static str to avoid allocation and lifetime issues
    let method: &'static str = match *req.method() {
        hyper::Method::GET => "GET",
        hyper::Method::POST => "POST",
        hyper::Method::PUT => "PUT",
        hyper::Method::PATCH => "PATCH",
        hyper::Method::DELETE => "DELETE",
        hyper::Method::HEAD => "HEAD",
        hyper::Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    };

    if let Some(resp) = scan_target_and_headers(rule, state, remote_addr, method, waf_profile, &req)
    {
        return Err(resp);
    }

    scan_body(rule, state, remote_addr, method, waf_profile, req).await
}

/// The URI and header scans (and the ML scorer when built in). `Some` ends the request.
fn scan_target_and_headers(
    rule: &ResolvedRoute,
    state: &AppState,
    remote_addr: SocketAddr,
    method: &'static str,
    waf_profile: &WafProfile,
    req: &Request<ZionBody>,
) -> Option<Response<ZionBody>> {
    // Gate: WAF URI scan (catches SQLi/XSS in query parameters for ALL methods)
    let uri_str = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| req.uri().path());
    if let waf::WafVerdict::Deny(reason) = waf::validate_uri(uri_str, waf_profile.mode) {
        if rule.waf_shadow {
            metrics::METRICS
                .waf_shadow_would_block
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            logging::warn(
                "waf_shadow",
                &format!("would_block=true source=uri reason={reason} path={uri_str}"),
            );
            // Fall through — shadow mode never denies the request.
        } else {
            metrics::METRICS
                .waf_denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            logging::info("waf", &format!("URI denied: {reason} ({uri_str})"));
            emit_waf_block(&state, &remote_addr, method, uri_str, "uri", &reason);
            return Some(text_response(StatusCode::BAD_REQUEST, "request rejected"));
        }
    }

    // Gate: WAF header scan (opt-in per profile: `scan_headers`). The URI and the body
    // are not the only places a payload travels: Log4Shell arrived in `User-Agent`.
    if let Some((header, reason)) = waf::validate_headers(req.headers(), waf_profile) {
        if rule.waf_shadow {
            metrics::METRICS
                .waf_shadow_would_block
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            logging::warn(
                "waf_shadow",
                &format!(
                    "would_block=true source=header reason={reason} header={header} path={uri_str}"
                ),
            );
            // Fall through — shadow mode never denies the request.
        } else {
            metrics::METRICS
                .waf_denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // The header's name, never its value: it may be a cookie or a token.
            logging::info("waf", &format!("header denied: {reason} ({header})"));
            emit_waf_block(&state, &remote_addr, method, uri_str, "header", reason);
            return Some(text_response(StatusCode::BAD_REQUEST, "request rejected"));
        }
    }

    // ── Gate: ML scorer (Track C, --features ml-waf) ─────────────
    // Anomaly score over URI + headers. Cheap (~50µs p50, 200µs p99
    // budget enforced via metrics, not active cancel). Returns None
    // when the model is disabled or failed to load — fall through.
    #[cfg(feature = "ml-waf")]
    if let Some(verdict) = crate::waf_ml::evaluate(method, uri_str, req.headers()) {
        if verdict.over_budget {
            logging::warn(
                "waf_ml",
                &format!(
                    "score over budget: elapsed_us={} score={:.3} path={}",
                    verdict.elapsed_us, verdict.score, uri_str
                ),
            );
        }
        if verdict.denies {
            let reason = "ml score above threshold";
            if rule.waf_shadow {
                metrics::METRICS
                    .waf_shadow_would_block
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                logging::warn(
                    "waf_shadow",
                    &format!(
                        "would_block=true source=ml score={:.3} path={uri_str}",
                        verdict.score
                    ),
                );
            } else {
                metrics::METRICS
                    .waf_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                logging::info(
                    "waf_ml",
                    &format!(
                        "denied: score={:.3} elapsed_us={} path={}",
                        verdict.score, verdict.elapsed_us, uri_str
                    ),
                );
                emit_waf_block(&state, &remote_addr, method, uri_str, "ml", reason);
                return Some(text_response(StatusCode::BAD_REQUEST, "request rejected"));
            }
        }
    }

    None
}

/// Read and scan the body of the methods that carry one, and of any other request that has one;
/// a request without one gets the header-only verdict.
async fn scan_body(
    rule: &ResolvedRoute,
    state: &AppState,
    remote_addr: SocketAddr,
    method: &'static str,
    waf_profile: &WafProfile,
    mut req: Request<ZionBody>,
) -> Result<Request<ZionBody>, Response<ZionBody>> {
    // Read and scan the body of the methods that carry one, and of any other request
    // that actually has one (Content-Length / chunked on HTTP/1, an open stream on
    // HTTP/2): a GET body is forwarded to the upstream, so it is scanned like the rest.
    let has_body = !hyper::body::Body::is_end_stream(req.body());
    if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") || has_body {
        let (parts, body) = req.into_parts();

        // Borrow content-type from parts.headers — no String allocation needed.
        // The header lives in `parts` which is alive through this scope.
        let ct: Option<&str> = parts
            .headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        let max_body_bytes = (waf_profile.max_body_mb * 1_048_576) as usize;
        let body_bytes = collect_body(
            rule,
            state,
            remote_addr,
            method,
            waf_profile,
            &parts,
            body,
            max_body_bytes,
        )
        .await?;

        // On the streaming path the raw Aho-Corasick pass already ran
        // incrementally over these bytes, so skip the redundant buffered
        // raw scan; the encoded/entropy/JSON gates still run.
        let verdict = if waf_profile.streaming {
            waf::validate_request_prescanned(method, ct, &body_bytes, waf_profile)
        } else {
            waf::validate_request(method, ct, &body_bytes, waf_profile)
        };
        if let waf::WafVerdict::Deny(reason) = verdict {
            if rule.waf_shadow {
                metrics::METRICS
                    .waf_shadow_would_block
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                logging::warn(
                    "waf_shadow",
                    &format!(
                        "would_block=true source=body method={} reason={} path={}",
                        method,
                        reason,
                        parts.uri.path()
                    ),
                );
                // Fall through — request body is reassembled below.
            } else {
                metrics::METRICS
                    .waf_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                emit_waf_block(
                    &state,
                    &remote_addr,
                    method,
                    parts.uri.path(),
                    "body",
                    &reason,
                );
                return Err(text_response(StatusCode::BAD_REQUEST, "request rejected"));
            }
        }

        // Re-assemble request with validated body for dispatch below.
        // Do NOT return early — fall through to post-response processing
        // (CORS, metrics, request-ID, security headers).
        let body: ZionBody = Full::new(body_bytes)
            .map_err(|never| match never {})
            .boxed();
        req = Request::from_parts(parts, body);
    } else {
        // GET/HEAD/DELETE/OPTIONS — no body to validate
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        let verdict = waf::validate_request(method, ct, &[], waf_profile);
        if let waf::WafVerdict::Deny(reason) = verdict {
            if rule.waf_shadow {
                metrics::METRICS
                    .waf_shadow_would_block
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                logging::warn(
                    "waf_shadow",
                    &format!(
                        "would_block=true source=headers method={} reason={} path={}",
                        method,
                        reason,
                        req.uri().path()
                    ),
                );
                // Fall through — shadow mode never denies the request.
            } else {
                metrics::METRICS
                    .waf_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                emit_waf_block(
                    &state,
                    &remote_addr,
                    method,
                    req.uri().path(),
                    "headers",
                    &reason,
                );
                return Err(text_response(StatusCode::BAD_REQUEST, "request rejected"));
            }
        }
    }
    Ok(req)
}

/// Read the request body whole, within the profile's size cap and the idle/total timeouts. With
/// `streaming = true` each frame is scanned as it arrives, so an injection in the first chunk denies
/// before the rest of the upload is read.
#[allow(clippy::too_many_arguments)]
async fn collect_body(
    rule: &ResolvedRoute,
    state: &AppState,
    remote_addr: SocketAddr,
    method: &'static str,
    waf_profile: &WafProfile,
    parts: &hyper::http::request::Parts,
    body: ZionBody,
    max_body_bytes: usize,
) -> Result<Bytes, Response<ZionBody>> {
    let body_bytes = if waf_profile.streaming {
        let mut scanner = waf::StreamingScanner::new(waf_profile.mode, max_body_bytes as u64);
        let mut chunks: Vec<Bytes> = Vec::new();
        let mut total: usize = 0;
        let mut body = body;
        let mut early_deny: Option<&'static str> = None;
        loop {
            match tokio::time::timeout(BODY_FRAME_IDLE_TIMEOUT, BodyExt::frame(&mut body)).await {
                Ok(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        match scanner.feed(&data) {
                            waf::StreamVerdict::Allow => {}
                            waf::StreamVerdict::Deny(reason) => {
                                early_deny = Some(reason);
                                break;
                            }
                        }
                        total += data.len();
                        chunks.push(data);
                    }
                    // Trailers / non-data frames: ignore (no body bytes).
                    Err(_other) => continue,
                },
                Ok(Some(Err(e))) => {
                    log_body_failure(&remote_addr, method, parts.uri.path(), &e.to_string());
                    return Err(text_response(
                        StatusCode::BAD_REQUEST,
                        "request body read error",
                    ));
                }
                Ok(None) => break, // EOF
                Err(_elapsed) => {
                    log_body_failure(&remote_addr, method, parts.uri.path(), "no data for 30 s");
                    return Err(text_response(
                        StatusCode::REQUEST_TIMEOUT,
                        "request body read timeout",
                    ));
                }
            }
        }

        if let Some(reason) = early_deny {
            if rule.waf_shadow {
                metrics::METRICS
                    .waf_shadow_would_block
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                logging::warn(
                    "waf_shadow",
                    &format!(
                        "would_block=true source=body_streaming method={} reason={} path={}",
                        method,
                        reason,
                        parts.uri.path()
                    ),
                );
                // Shadow mode: don't deny. We did NOT read the rest
                // of the body off the wire; reconstruct from what
                // we have and forward — this produces a truncated
                // request to upstream, which is the correct shadow-
                // mode trade-off (we never silently buffer attacks
                // for the upstream after a streaming match).
            } else {
                metrics::METRICS
                    .waf_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                emit_waf_block(
                    &state,
                    &remote_addr,
                    method,
                    parts.uri.path(),
                    "body",
                    reason,
                );
                return Err(text_response(StatusCode::BAD_REQUEST, "request rejected"));
            }
        }

        // Reassemble Bytes from the frame Vec for the buffered
        // re-validation + upstream forward.
        let mut buf = bytes::BytesMut::with_capacity(total);
        for c in &chunks {
            buf.extend_from_slice(c);
        }
        buf.freeze()
    } else {
        let limited = Limited::new(body, max_body_bytes);
        match tokio::time::timeout(BODY_COLLECT_TIMEOUT, BodyExt::collect(limited)).await {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(e)) => {
                let (status, msg) = body_read_failure(e.as_ref());
                if status != StatusCode::PAYLOAD_TOO_LARGE {
                    log_body_failure(&remote_addr, method, parts.uri.path(), &e.to_string());
                }
                return Err(text_response(status, msg));
            }
            Err(_elapsed) => {
                log_body_failure(
                    &remote_addr,
                    method,
                    parts.uri.path(),
                    "not complete after 60 s",
                );
                return Err(text_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "request body read timeout",
                ));
            }
        }
    };
    Ok(body_bytes)
}
