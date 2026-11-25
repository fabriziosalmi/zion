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
    req: Request<ReqBody>,
) -> Result<Request<ReqBody>, Response<ZionBody>> {
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
    req: &Request<ReqBody>,
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
    mut req: Request<ReqBody>,
) -> Result<Request<ReqBody>, Response<ZionBody>> {
    // Read and scan the body of the methods that carry one, and of any other request
    // that actually has one (Content-Length / chunked on HTTP/1, an open stream on
    // HTTP/2): a GET body is forwarded to the upstream, so it is scanned like the rest.
    let has_body = !hyper::body::Body::is_end_stream(req.body());
    if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") || has_body {
        let (parts, body) = req.into_parts();

        // Borrow content-type from parts.headers — no String allocation needed.
        // The header lives in `parts` which is alive through this scope.
        let mut ct_lines = parts.headers.get_all(hyper::header::CONTENT_TYPE).iter();
        let ct: Option<&str> = ct_lines.next().and_then(|v| v.to_str().ok());
        // Content-Type is a singleton field (RFC 9110 §5.3, §8.3). The gates read the first
        // line, zion forwards every line, and an upstream may act on another one: gunicorn 23
        // hands the app the last. A body that comes with more than one is refused.
        let ct_repeated = ct_lines.next().is_some();

        let max_body_bytes = (waf_profile.max_body_mb * 1_048_576) as usize;
        let body_bytes = match collect_body(
            rule,
            state,
            remote_addr,
            method,
            waf_profile,
            &parts,
            body,
            max_body_bytes,
        )
        .await?
        {
            Collected::Whole(bytes) => bytes,
            // Shadow mode, a pattern flagged while the body streamed in: logged, and the body
            // goes on as it is, held to the profile's cap by the proxy (`413` past it, the
            // upstream request aborted).
            Collected::Flagged(body) => {
                let mut req = Request::from_parts(parts, body);
                req.extensions_mut()
                    .insert(crate::upstream_body::BodyCap(max_body_bytes as u64));
                return Ok(req);
            }
        };

        // On the streaming path the raw Aho-Corasick pass already ran
        // incrementally over these bytes, so skip the redundant buffered
        // raw scan; the encoded/entropy/JSON gates still run.
        let verdict = if ct_repeated && !body_bytes.is_empty() {
            waf::WafVerdict::Deny("repeated content-type header")
        } else if waf_profile.streaming {
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
        let body: ReqBody = Full::new(body_bytes)
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

/// The request body as the WAF stage read it.
enum Collected {
    /// Read whole, to be scanned as a whole and sent on.
    Whole(Bytes),
    /// Shadow mode, where the streaming scan flagged a pattern before the body's end: the
    /// frames read so far, the one that was flagged, then the rest as it arrives, not buffered.
    Flagged(ReqBody),
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
    body: ReqBody,
    max_body_bytes: usize,
) -> Result<Collected, Response<ZionBody>> {
    let body_bytes = if waf_profile.streaming {
        let mut scanner = waf::StreamingScanner::new(waf_profile.mode, max_body_bytes as u64);
        let mut chunks: Vec<Bytes> = Vec::new();
        let mut total: usize = 0;
        let mut body = body;
        let mut early_deny: Option<(&'static str, Bytes)> = None;
        loop {
            match tokio::time::timeout(BODY_FRAME_IDLE_TIMEOUT, BodyExt::frame(&mut body)).await {
                Ok(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        match scanner.feed(&data) {
                            waf::StreamVerdict::Allow => {}
                            waf::StreamVerdict::Deny(reason) => {
                                early_deny = Some((reason, data));
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

        if let Some((reason, flagged)) = early_deny {
            // A body past the cap is refused in shadow mode too, as the buffered path refuses
            // it, which reads no further than the cap.
            if rule.waf_shadow && total.saturating_add(flagged.len()) > max_body_bytes {
                return Err(text_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large",
                ));
            }
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
                // Shadow mode blocks no pattern, so the body goes on whole: what was read, the
                // frame that was flagged, then the rest of it as it arrives. Nothing more is
                // buffered. Sending only what had been read handed the upstream a truncated
                // body, and since the upstream request takes its length from the body it
                // sends, one the upstream took as complete (an upload stored cut short).
                chunks.push(flagged);
                let read: Vec<Result<hyper::body::Frame<Bytes>, crate::http_util::BoxError>> =
                    chunks
                        .into_iter()
                        .map(|c| Ok(hyper::body::Frame::data(c)))
                        .collect();
                use tokio_stream::StreamExt as _;
                let whole = tokio_stream::iter(read).chain(http_body_util::BodyStream::new(body));
                return Ok(Collected::Flagged(
                    http_body_util::StreamBody::new(whole).boxed(),
                ));
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
        let read = read_capped(body, max_body_bytes as u64);
        match tokio::time::timeout(BODY_COLLECT_TIMEOUT, read).await {
            Ok(Ok(bytes)) => bytes,
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
    Ok(Collected::Whole(body_bytes))
}

#[cfg(test)]
mod shadow_tests {
    //! Shadow mode on a streaming profile, end to end: the real `process_request` in front of an
    //! in-process origin that reads each request body by its framing.

    use crate::config::ZionConfig;
    use crate::dispatch::process_request;
    use crate::http_util::{BoxError, ReqBody};
    use crate::state::AppState;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// What the origin made of one request: its path, its `Content-Length`, and its body if the
    /// body ended where its framing said.
    #[derive(Debug, Clone)]
    struct Got {
        path: String,
        declared: Option<String>,
        body: Option<Bytes>,
    }

    async fn origin(got: Arc<Mutex<Vec<Got>>>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let got = got.clone();
                tokio::spawn(async move {
                    let svc =
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let got = got.clone();
                            async move {
                                let path = req.uri().path().to_string();
                                let declared = req
                                    .headers()
                                    .get(hyper::header::CONTENT_LENGTH)
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_string);
                                let body =
                                    req.into_body().collect().await.ok().map(|c| c.to_bytes());
                                got.lock().unwrap().push(Got {
                                    path,
                                    declared,
                                    body,
                                });
                                Ok::<_, std::convert::Infallible>(Response::new(
                                    http_body_util::Full::new(Bytes::from_static(b"ok")),
                                ))
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        port
    }

    /// `/shadow/*` and `/enforce/*` on one streaming profile capped at 1 MiB, the first in shadow
    /// mode.
    fn state(port: u16) -> Arc<AppState> {
        let toml = format!(
            r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"

[tls]
cert_path = "/c"
key_path = "/k"

[upstreams]
o = "http://127.0.0.1:{port}"

[waf_profile.streamed]
streaming = true
max_body_mb = 1
deny_unknown_content_types = false
entropy_check = false

[[route]]
path = "/shadow/{{*rest}}"
upstream = "o"
waf_profile = "streamed"
waf_shadow = true

[[route]]
path = "/enforce/{{*rest}}"
upstream = "o"
waf_profile = "streamed"
"#
        );
        AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).expect("config parses"))
    }

    /// POST `frames` as a body that arrives frame by frame, with `content-length` when
    /// `declared`: the status, and what the origin made of it.
    async fn post(
        st: &Arc<AppState>,
        got: &Arc<Mutex<Vec<Got>>>,
        path: &str,
        frames: &[Bytes],
        declared: bool,
    ) -> (u16, Vec<Got>) {
        let total: usize = frames.iter().map(Bytes::len).sum();
        let frames: Vec<Result<hyper::body::Frame<Bytes>, BoxError>> = frames
            .iter()
            .map(|f| Ok(hyper::body::Frame::data(f.clone())))
            .collect();
        let body: ReqBody = http_body_util::StreamBody::new(tokio_stream::iter(frames)).boxed();
        let mut req = Request::post(path)
            .header("host", "example.test")
            .header("content-type", "application/octet-stream");
        if declared {
            req = req.header("content-length", total.to_string());
        }
        let resp = process_request(
            req.body(body).unwrap(),
            st.clone(),
            "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
            false,
        )
        .await
        .unwrap();
        let status = resp.status().as_u16();
        let _ = resp.into_body().collect().await;
        // let the origin finish reading whatever it was sent
        tokio::time::sleep(Duration::from_millis(100)).await;
        let seen = got
            .lock()
            .unwrap()
            .iter()
            .filter(|g| g.path == path)
            .cloned()
            .collect();
        (status, seen)
    }

    /// A pattern the streaming scan flags in shadow mode is logged and the body still reaches the
    /// upstream whole, under its own length, with and without a declared one. Only what had been
    /// read before the flagged frame went, under the length of what had been read, so the upstream
    /// took a truncated body as a complete request. The profile's cap still holds: a body past it
    /// is refused with `413` and never reaches the upstream whole, flagged for its size or for a
    /// pattern before it got there.
    #[tokio::test]
    async fn a_flagged_body_in_shadow_mode_reaches_the_upstream_whole_within_the_cap() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let st = state(origin(got.clone()).await);
        let a = Bytes::from(vec![b'a'; 64 * 1024]);
        let pattern = Bytes::from_static(b"name=<script>alert(1)</script>");
        let half_mib = Bytes::from(vec![b'b'; 512 * 1024]);
        let flagged = vec![a.clone(), pattern.clone(), a.clone()];
        for declared in [true, false] {
            let sent: Vec<u8> = flagged.iter().flat_map(|f| f.iter().copied()).collect();
            let path = format!("/shadow/pattern-{declared}");
            let (status, seen) = post(&st, &got, &path, &flagged, declared).await;
            assert!(
                status == 200
                    && seen.len() == 1
                    && seen[0].body.as_deref() == Some(&sent[..])
                    && (!declared
                        || seen[0].declared.as_deref() == Some(&sent.len().to_string()[..])),
                "{path}: status {status}, the upstream got {:?} (declared {:?}) of the {} bytes \
                 sent",
                seen.iter()
                    .map(|g| g.body.as_ref().map(Bytes::len))
                    .collect::<Vec<_>>(),
                seen.iter().map(|g| g.declared.clone()).collect::<Vec<_>>(),
                sent.len()
            );
        }

        // Past the 1 MiB cap. Flagged for its size in the third frame: refused before anything
        // goes. Flagged for a pattern in the first frame and past the cap later, while the rest
        // streams on: the upstream request is cut at the cap and never ends whole.
        let over = [
            (
                "over-the-cap",
                vec![half_mib.clone(), half_mib.clone(), half_mib.clone()],
                false,
            ),
            (
                "pattern-then-over-the-cap",
                vec![
                    pattern.clone(),
                    half_mib.clone(),
                    half_mib.clone(),
                    half_mib.clone(),
                ],
                true,
            ),
        ];
        for (case, frames, may_start) in &over {
            for declared in [true, false] {
                let path = format!("/shadow/{case}-{declared}");
                let (status, seen) = post(&st, &got, &path, frames, declared).await;
                assert!(
                    status == 413
                        && seen.iter().all(|g| g.body.is_none())
                        && (*may_start || seen.is_empty()),
                    "{path}: status {status}, the upstream got {:?}",
                    seen.iter()
                        .map(|g| g.body.as_ref().map(Bytes::len))
                        .collect::<Vec<_>>()
                );
            }
        }

        // the pattern on the enforcing route is refused and never forwarded
        let (status, seen) = post(&st, &got, "/enforce/pattern", &flagged, true).await;
        assert_eq!((status, seen.len()), (400, 0), "{seen:?}");
    }

    /// With `require_content_length`, a body flagged in shadow mode is read whole before it goes,
    /// and is held to the profile's `max_body_mb` (12 MiB here), not to the 10 MiB the body stage
    /// reads on a route without a cap: an 11 MiB body reaches the upstream whole with its length,
    /// a 13 MiB one is refused with `413` and never forwarded.
    #[tokio::test]
    async fn a_flagged_body_in_shadow_mode_under_require_content_length_is_held_to_the_profile_cap()
    {
        let got = Arc::new(Mutex::new(Vec::new()));
        let port = origin(got.clone()).await;
        let toml = format!(
            r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"

[tls]
cert_path = "/c"
key_path = "/k"

[upstreams]
o = "http://127.0.0.1:{port}"

[waf_profile.streamed]
streaming = true
max_body_mb = 12
deny_unknown_content_types = false
entropy_check = false

[[route]]
path = "/shadow/{{*rest}}"
upstream = "o"
waf_profile = "streamed"
waf_shadow = true
require_content_length = true
"#
        );
        let st = AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).expect("config parses"));
        let pattern = Bytes::from_static(b"name=<script>alert(1)</script>");
        let one_mib = Bytes::from(vec![b'c'; 1_048_576]);
        let frames = |mib: usize| {
            let mut f = vec![pattern.clone()];
            f.extend(std::iter::repeat_n(one_mib.clone(), mib));
            f
        };

        for declared in [true, false] {
            let body = frames(11);
            let sent: usize = body.iter().map(Bytes::len).sum();
            let path = format!("/shadow/eleven-{declared}");
            let (status, seen) = post(&st, &got, &path, &body, declared).await;
            assert!(
                status == 200
                    && seen.len() == 1
                    && seen[0].body.as_ref().map(Bytes::len) == Some(sent)
                    && seen[0].declared.as_deref() == Some(&sent.to_string()[..]),
                "{path}: status {status}, the upstream got {:?} (declared {:?}) of the {sent} \
                 bytes sent",
                seen.iter()
                    .map(|g| g.body.as_ref().map(Bytes::len))
                    .collect::<Vec<_>>(),
                seen.iter().map(|g| g.declared.clone()).collect::<Vec<_>>(),
            );

            let path = format!("/shadow/thirteen-{declared}");
            let (status, seen) = post(&st, &got, &path, &frames(13), declared).await;
            assert!(
                status == 413 && seen.is_empty(),
                "{path}: status {status}, the upstream got {:?}",
                seen.iter()
                    .map(|g| g.body.as_ref().map(Bytes::len))
                    .collect::<Vec<_>>()
            );
        }
    }
}
