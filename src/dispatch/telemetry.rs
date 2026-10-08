// SPDX-License-Identifier: Apache-2.0
//! What a request leaves behind: its request id and W3C trace context, the access-log line and the
//! request-duration histogram.

use super::*;

/// The identifiers a request carries through the pipeline.
pub(super) struct Trace {
    /// The 16-byte W3C trace id (the histogram exemplar).
    pub(super) trace_id_bytes: [u8; 16],
    /// The same, as 32 lowercase hex: the join key for the access log and the audit record.
    pub(super) trace_hex: String,
    /// The request's `X-Request-ID`, to echo on the response.
    pub(super) request_id: Option<hyper::header::HeaderValue>,
}

/// Give the request an `X-Request-ID` and a valid `traceparent` (the client's, or a fresh one).
pub(super) fn stamp(req: &mut Request<ZionBody>) -> Trace {
    // ── Request ID (preserve client's or generate new) ──
    let has_client_id = req.headers().contains_key("X-Request-ID");
    let generated_id: [u8; 21];
    if !has_client_id {
        generated_id = generate_request_id();
        // SAFETY: all bytes are ASCII hex digits or '-'
        if let Ok(val) = hyper::header::HeaderValue::from_bytes(&generated_id) {
            req.headers_mut().insert("X-Request-ID", val);
        }
    }

    // ── W3C Trace Context propagation ──
    // 1. If the client sent `traceparent`, validate it. A valid header is
    //    propagated unchanged so end-to-end traces stitch in Tempo/Jaeger.
    //    A malformed header is dropped (we replace with a freshly-generated
    //    one) and `zion_traces_invalid_total` is bumped — we never forward
    //    junk to upstreams.
    // 2. If absent (or invalid), generate one with the same zero-alloc
    //    stack-buffer scheme used historically.
    //
    // The 16-byte trace ID is captured into `trace_id_bytes` regardless,
    // so the latency histogram can attach it as an OpenMetrics exemplar.
    let trace_id_bytes: [u8; 16];
    let inbound_valid = req
        .headers()
        .get("traceparent")
        .and_then(|v| observability::parse_traceparent(v.as_bytes()));

    if let Some(ctx) = inbound_valid {
        trace_id_bytes = ctx.trace_id;
    } else {
        // Either no header, or the value was malformed. Bump the invalid
        // counter only when a header was actually present.
        if req.headers().contains_key("traceparent") {
            observability::TRACES_INVALID_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Generate: 00-{32hex trace_id}-{16hex span_id}-01
        // Zero-alloc: stack buffer + hex lookup table (no format! calls).
        let ts_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let seq = REQUEST_COUNTER.load(std::sync::atomic::Ordering::Relaxed);

        // Build the trace ID once, in raw bytes — we both stringify it for
        // the header and keep it for the exemplar.
        let mut tid = [0u8; 16];
        tid[0..8].copy_from_slice(&ts_us.to_be_bytes());
        tid[8..16].copy_from_slice(&seq.to_be_bytes());
        trace_id_bytes = tid;

        let mut buf = [0u8; 55]; // "00-" + 32hex + "-" + 16hex + "-01"
        buf[0..3].copy_from_slice(b"00-");
        for (i, &byte) in tid.iter().enumerate() {
            buf[3 + i * 2] = HEX_DIGITS[(byte >> 4) as usize];
            buf[3 + i * 2 + 1] = HEX_DIGITS[(byte & 0xF) as usize];
        }
        buf[35] = b'-';
        // span_id: same 8 trailing bytes — sequence is unique within a process
        // for the lifetime of `REQUEST_COUNTER`. A future change can split
        // span IDs from request IDs; for now they coincide.
        for i in 0..8 {
            buf[36 + i * 2] = HEX_DIGITS[(tid[8 + i] >> 4) as usize];
            buf[36 + i * 2 + 1] = HEX_DIGITS[(tid[8 + i] & 0xF) as usize];
        }
        buf[52..55].copy_from_slice(b"-01");
        // SAFETY: all bytes are ASCII hex, '-', or '0'/'1'
        if let Ok(val) = hyper::header::HeaderValue::from_bytes(&buf) {
            req.headers_mut().insert("traceparent", val);
        }
    }
    observability::TRACES_EMITTED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // Stringify the trace ID once (32 lowercase hex) so BOTH the access-log
    // line and the audit record can carry it. Without this an operator can see
    // a request in the logs, or a signed audit event, but has no key to join
    // it to the distributed trace in Tempo/Jaeger — the histogram exemplar was
    // the only place the id surfaced.
    let trace_hex: String = trace_id_to_hex(&trace_id_bytes);

    let request_id = req.headers().get("X-Request-ID").cloned();
    Trace {
        trace_id_bytes,
        trace_hex,
        request_id,
    }
}

/// What the access log needs from the request, captured before the pipeline consumes it.
pub(super) struct AccessCapture {
    log_method: hyper::Method,
    log_path_query: String,
    log_headers_json: Option<String>,
    log_mtls_fp: Option<String>,
}

pub(super) fn capture(
    cfg: &ResolvedAppConfig,
    state: &AppState,
    req: &Request<ZionBody>,
) -> AccessCapture {
    // Capture method + path-and-query *before* the request is consumed by
    // the proxy / cache pipeline. Used by the access-log emission below.
    // `Method` and `String` are cheap to materialise once per request.
    let log_method = req.method().clone();
    let log_path_query: String = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Issue #60: snapshot configured headers (redacted) BEFORE the
    // request is consumed by the proxy / cache pipeline. Emitted
    // below as a single `headers` field carrying a JSON object —
    // tracing's macro requires field names to be string literals,
    // so dynamic header lists go through one structured value.
    //
    // mTLS fingerprint is captured separately so the access-log
    // event can put it on a dedicated `mtls_fp` field (the value is
    // a SHA-256 hash, never redacted).
    //
    // Empty/absent by default — the operator opts in via
    // `[access_log] include_headers = [...]`.
    let log_headers_json: Option<String> = if cfg.access_log.include_headers.is_empty() {
        None
    } else {
        let pairs: std::collections::BTreeMap<&str, String> = cfg
            .access_log
            .include_headers
            .iter()
            .filter_map(|name_lc| {
                let value = req
                    .headers()
                    .get(name_lc.as_str())
                    .and_then(|v| v.to_str().ok())?;
                let redacted = state.redact.redact_header_value(name_lc, value);
                Some((name_lc.as_str(), redacted.into_owned()))
            })
            .collect();
        if pairs.is_empty() {
            None
        } else {
            // serde_json on a BTreeMap of plain types can't fail.
            serde_json::to_string(&pairs).ok()
        }
    };
    let log_mtls_fp: Option<String> = if cfg.access_log.mtls_fingerprint {
        req.headers()
            .get("x-client-cert-fingerprint")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    AccessCapture {
        log_method,
        log_path_query,
        log_headers_json,
        log_mtls_fp,
    }
}

/// Record the request-duration histogram and, when enabled, the access-log line and its audit record.
pub(super) fn record(
    state: &AppState,
    cfg: &ResolvedAppConfig,
    remote_addr: SocketAddr,
    resp: &Response<ZionBody>,
    request_elapsed: std::time::Duration,
    trace: &Trace,
    capture: &AccessCapture,
) {
    let trace_id_bytes = trace.trace_id_bytes;
    let trace_hex = &trace.trace_hex;
    let AccessCapture {
        log_method,
        log_path_query,
        log_headers_json,
        log_mtls_fp,
    } = capture;

    // Record request duration histogram, attaching the request's trace ID
    // as an OpenMetrics exemplar so /metrics consumers can jump straight
    // from a slow-bucket count to the matching trace in Tempo/Jaeger.
    metrics::METRICS
        .request_duration
        .observe_with_trace(request_elapsed, trace_id_bytes);

    // GDPR-aware access log (Track E). One structured event per request:
    //   * status, method, latency_us — per-request metric data, no PII;
    //   * path with the query string redacted via state.redact (the same
    //     compiled policy used by audit::emit_waf_block);
    //   * remote_ip — necessary for forensics, classified under GDPR
    //     Art. 6(1)(f) "legitimate interest" of operating the service.
    //
    // The event is a no-op when no tracing subscriber consumes it. With
    // the JSON subscriber attached, fields are written directly to the
    // subscriber's buffer — no `format!` allocation, redaction is the
    // only owned-`String` produced.
    if cfg.access_log.enabled {
        // Redact the query string per the operator's [redact] policy.
        // Path itself is rarely sensitive and the auditor needs it; we
        // only rewrite the part after the first `?`.
        let path_safe: std::borrow::Cow<'_, str> = match log_path_query.split_once('?') {
            Some((p, q)) => {
                let q_redacted = state.redact.redact_query_string(q);
                std::borrow::Cow::Owned(format!("{p}?{q_redacted}"))
            }
            None => std::borrow::Cow::Borrowed(log_path_query.as_str()),
        };
        tracing::info!(
            target: "access",
            status = resp.status().as_u16(),
            latency_us = request_elapsed.as_micros() as u64,
            method = %log_method,
            path = %path_safe,
            remote_ip = %state.redact.ip_label(remote_addr.ip()),
            // 32-hex W3C trace id — the join key from this log line to the
            // distributed trace (and to the matching audit record).
            trace_id = %trace_hex,
            // Issue #60: configured request headers, redacted via the
            // [redact.headers] policy, packed into one JSON object so
            // dynamic field names don't fight the tracing macro.
            // `tracing::field::Empty` collapses absent fields to no-op.
            headers = log_headers_json.as_deref().unwrap_or(""),
            // mTLS fingerprint (SHA-256 hex; never redacted — already a hash).
            mtls_fp = log_mtls_fp.as_deref().unwrap_or(""),
            "request",
        );

        // Issue #60: when the audit log is enabled, emit a parallel
        // `request_completed` event so compliance reviewers have a
        // signed, HMAC-chained record alongside the unsigned tracing
        // line. Same field set; the audit handle's `try_send` is
        // non-blocking, so a saturated audit queue silently drops
        // (counted via `zion_audit_events_dropped_total`).
        if !cfg.access_log.include_headers.is_empty() || cfg.access_log.mtls_fingerprint {
            // Compose the detail string out-of-band — keeps the audit
            // event small and lets the operator filter by kind.
            let mut detail_parts: Vec<String> = Vec::with_capacity(3);
            detail_parts.push(format!(
                "status={} latency_us={}",
                resp.status().as_u16(),
                request_elapsed.as_micros()
            ));
            if let Some(ref h) = log_headers_json {
                detail_parts.push(format!("headers={h}"));
            }
            if let Some(ref fp) = log_mtls_fp {
                detail_parts.push(format!("mtls_fp={fp}"));
            }
            let _ = state.audit.emit(audit::AuditEvent {
                seq: 0,
                ts: String::new(),
                kind: audit::kind::REQUEST_COMPLETED,
                trace_id: Some(trace_hex.clone()),
                remote_ip: Some(state.redact.ip_label(remote_addr.ip()).to_string()),
                method: Some(log_method.to_string()),
                path: Some(path_safe.to_string()),
                detail: Some(detail_parts.join(" ")),
            });
        }
    }
}
