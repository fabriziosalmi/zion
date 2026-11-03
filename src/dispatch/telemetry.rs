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
    /// The 8-byte span id this request's own span was stamped with (#640): the client's
    /// `traceparent` span id when one was valid (so the exported span's parent context
    /// matches what was propagated), or the freshly generated one otherwise.
    #[cfg(feature = "otel")]
    pub(super) span_id_bytes: [u8; 8],
}

/// Give the request an `X-Request-ID` and a valid `traceparent` (the client's, or a fresh one).
pub(super) fn stamp(req: &mut Request<ReqBody>) -> Trace {
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
    #[cfg(feature = "otel")]
    let span_id_bytes: [u8; 8];
    let inbound_valid = req
        .headers()
        .get("traceparent")
        .and_then(|v| observability::parse_traceparent(v.as_bytes()));

    if let Some(ctx) = inbound_valid {
        trace_id_bytes = ctx.trace_id;
        #[cfg(feature = "otel")]
        {
            span_id_bytes = ctx.span_id;
        }
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
        // Same 8 trailing bytes as the span_id below (header and exported span agree).
        #[cfg(feature = "otel")]
        {
            span_id_bytes = tid[8..16].try_into().unwrap();
        }

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
        #[cfg(feature = "otel")]
        span_id_bytes,
    }
}

/// The root span for this request's own processing, exported as an OpenTelemetry span when
/// `--features otel` has an OTLP exporter installed (#640). Its trace id and span id are the
/// SAME ones `stamp()` already decided -- the client's own `traceparent` when it sent a valid
/// one, a freshly generated one otherwise -- so the exported span's trace id matches the
/// access-log `trace_id` and the `traceparent` this request propagates.
#[cfg(feature = "otel")]
pub(super) fn otel_span(trace: &Trace) -> tracing::Span {
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let span = tracing::info_span!(target: "zion", "request");
    let parent_cx = opentelemetry::Context::new().with_remote_span_context(SpanContext::new(
        TraceId::from_bytes(trace.trace_id_bytes),
        SpanId::from_bytes(trace.span_id_bytes),
        TraceFlags::SAMPLED,
        true, // is_remote: this context did not originate in this process either way
        TraceState::default(),
    ));
    // tracing-opentelemetry's set_parent fails closed (LayerNotFound, AlreadyStarted, or
    // SpanDisabled -- the span was filtered out at creation and has no id, so nothing done
    // to it afterward takes effect) rather than panicking, and is not expected to fail in
    // this configuration (the otel layer is installed before any span is created, and this
    // is the very first thing done to a freshly-built one) -- but a silently unparented span
    // would still export, just as its own untraceable root, so a regression here is worth a
    // log line rather than disappearing into an unused Result.
    if let Err(e) = span.set_parent(parent_cx) {
        crate::logging::warn("otel", &format!("span.set_parent failed: {e}"));
    }
    span
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
    req: &Request<ReqBody>,
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

#[cfg(all(test, feature = "otel"))]
mod otel_tests {
    use super::*;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing_subscriber::prelude::*;

    fn trace_with(trace_id_bytes: [u8; 16], span_id_bytes: [u8; 8]) -> Trace {
        Trace {
            trace_id_bytes,
            trace_hex: trace_id_to_hex(&trace_id_bytes),
            request_id: None,
            span_id_bytes,
        }
    }

    /// `otel_span()` must produce a span that, once CLOSED, is actually exported with the
    /// trace id `stamp()` already decided (not a fresh, unrelated one -- what a failed
    /// `set_parent` would produce) and the given span id as its PARENT (an OpenTelemetry
    /// child always gets its own freshly generated id; the id passed in is what the remote
    /// parent context carries, read back as `parent_span_id` on the exported span -- this
    /// distinction is why an earlier draft of this test asserted the wrong field and failed
    /// even though the real, live export this was verified against was already correct: see
    /// #640's PR description for the real OTLP collector output that caught the mistake).
    /// `InMemorySpanExporter`, paired with a SIMPLE (synchronous) processor, exports the
    /// instant the span is dropped -- no network, no batching delay, deterministic.
    #[test]
    fn the_request_span_is_exported_with_the_requests_trace_id_and_parent_span_id() {
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let tracer = provider.tracer("test");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let subscriber = tracing_subscriber::registry().with(otel_layer);

        let trace_id = [0x11u8; 16];
        let span_id = [0x22u8; 8];

        tracing::subscriber::with_default(subscriber, || {
            let span = otel_span(&trace_with(trace_id, span_id));
            assert!(!span.is_disabled(), "the span must not be filtered out");
            drop(span); // on_close fires here: the simple processor exports synchronously
        });

        let spans = exporter
            .get_finished_spans()
            .expect("exporter not shut down");
        assert_eq!(spans.len(), 1, "exactly one span must have been exported");
        let exported = &spans[0];
        assert_eq!(exported.name, "request");
        assert_eq!(
            exported.span_context.trace_id().to_bytes(),
            trace_id,
            "the exported trace id must be the request's own, not a freshly generated one"
        );
        assert_eq!(
            exported.parent_span_id.to_bytes(),
            span_id,
            "the exported parent span id must be the one stamp() decided"
        );
        assert!(
            exported.span_context.is_sampled(),
            "an unsampled span is dropped before export"
        );
    }

    /// Break-test for the fix itself: `set_parent` on `tracing-opentelemetry` 0.34 returns a
    /// `Result` (LayerNotFound / AlreadyStarted / SpanDisabled) that an earlier draft of this
    /// code discarded -- a silently-unparented span would still export, just with a FRESH,
    /// unrelated trace id (the SDK's own default, not this request's), which the trace-id
    /// assertion above exists specifically to catch. Confirmed by temporarily skipping
    /// `set_parent` in `otel_span()` and rerunning this test: it fails on the trace id
    /// assertion, not the parent id one, exactly as this comment predicts.
    #[test]
    fn a_request_with_no_active_otel_layer_still_returns_a_usable_span() {
        // No `with_default` scope at all: the global default test-runner subscriber (plain,
        // no otel layer) is whatever is active. otel_span() must not panic either way --
        // `set_parent`'s Result is logged, not unwrapped.
        let span = otel_span(&trace_with([0x33; 16], [0x44; 8]));
        let _ = span; // must not have panicked to get here
    }
}
