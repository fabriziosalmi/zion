//! Observability — distributed tracing, W3C Trace Context, OTLP export.
//!
//! Two layers:
//!   - **Always-on**: a `tracing` subscriber renders structured events as
//!     JSON to stderr (or pretty text if attached to a TTY). This costs
//!     ~zero on the hot path: spans without a subscriber are no-ops, and
//!     the JSON layer only fires on `tracing::info!` / `warn!` / `error!`.
//!   - **Opt-in (`--features otel`)**: spans are forwarded to an OTLP
//!     gRPC collector (Tempo, Jaeger, Honeycomb, Datadog Agent…). Off by
//!     default — keeps tonic/prost out of the lean binary.
//!
//! On top of that this module owns the W3C **Trace Context** wire format
//! (RFC, <https://www.w3.org/TR/trace-context/>). Inbound `traceparent` is
//! parsed once at the request edge; outbound calls to upstreams reuse the
//! same context so distributed traces stitch end-to-end.
//!
//! Hot-path traceparent *generation* (when no inbound header exists)
//! still lives in `dispatch.rs` — it uses a stack buffer + hex lookup
//! and we don't want to interpose any allocation here.

use std::sync::atomic::{AtomicU64, Ordering};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Counters that observability emits to /metrics.
// Defined here so panic-hook / audit-log can bump them without holding an Arc
// to AppState (which the panic hook can't safely access during unwind).
// ─────────────────────────────────────────────────────────────────────────────

pub static PANICS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static AUDIT_EVENTS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static AUDIT_EVENTS_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static TRACES_EMITTED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static TRACES_INVALID_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Render the observability counters in Prometheus text format. Called from
/// `metrics::render`. Keeps the metrics module unaware of tracing internals.
pub fn render_counters(out: &mut bytes::BytesMut) {
    let mut buf = itoa::Buffer::new();
    for (name, help, val) in [
        (
            "zion_panics_total",
            "Total worker panics caught by the panic hook.",
            PANICS_TOTAL.load(Ordering::Relaxed),
        ),
        (
            "zion_audit_events_total",
            "Total audit-log events emitted (signed + chained).",
            AUDIT_EVENTS_TOTAL.load(Ordering::Relaxed),
        ),
        (
            "zion_audit_events_dropped_total",
            "Audit events dropped because the writer queue was full.",
            AUDIT_EVENTS_DROPPED_TOTAL.load(Ordering::Relaxed),
        ),
        (
            "zion_traces_emitted_total",
            "Total request spans emitted (one per request).",
            TRACES_EMITTED_TOTAL.load(Ordering::Relaxed),
        ),
        (
            "zion_traces_invalid_total",
            "Inbound traceparent headers rejected as malformed.",
            TRACES_INVALID_TOTAL.load(Ordering::Relaxed),
        ),
    ] {
        out.extend_from_slice(b"# HELP ");
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b" ");
        out.extend_from_slice(help.as_bytes());
        out.extend_from_slice(b"\n# TYPE ");
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b" counter\n");
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b" ");
        out.extend_from_slice(buf.format(val).as_bytes());
        out.extend_from_slice(b"\n");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. W3C Trace Context — `traceparent` parser + helpers.
//    RFC: https://www.w3.org/TR/trace-context/
//    Format (v0):  "00-<32 hex trace_id>-<16 hex span_id>-<2 hex flags>"
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed W3C Trace Context. 16-byte trace ID, 8-byte span ID, 1-byte flags.
/// `Copy`-able so it can ride along on the request handler stack with no
/// allocation. Use [`TraceContext::is_sampled`] to decide whether to emit
/// detailed events for this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub flags: u8,
}

impl TraceContext {
    /// Bit 0 of the flags byte = "sampled" (RFC §3.2.2.4). Currently used
    /// by the test suite and reserved for future per-request export gating.
    #[allow(dead_code)]
    #[inline]
    pub fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Render the 32-char hex trace ID. Caller-owned buffer to keep this
    /// allocation-free at the call-site. Currently used by tests and the
    /// audit-log subsystem; the dispatch fast path uses raw bytes directly.
    #[allow(dead_code)]
    pub fn write_trace_id_hex(&self, out: &mut [u8; 32]) {
        write_hex(&self.trace_id, out);
    }

    /// Render the 16-char hex span ID.
    #[allow(dead_code)]
    pub fn write_span_id_hex(&self, out: &mut [u8; 16]) {
        write_hex(&self.span_id, out);
    }
}

/// Parse a `traceparent` header value per W3C Trace Context v0.
///
/// Returns `None` if the header is malformed, version is unsupported, or
/// the IDs are all-zero (the spec says recipients MUST treat all-zero IDs
/// as invalid). On `None` the caller bumps `TRACES_INVALID_TOTAL` and
/// generates a fresh context as if the header were absent.
pub fn parse_traceparent(value: &[u8]) -> Option<TraceContext> {
    // Minimum length: "00-" (3) + 32 + "-" (1) + 16 + "-" (1) + 2 = 55 bytes.
    if value.len() < 55 {
        return None;
    }

    // Version must be 00 (v0). Future versions are optional to support,
    // but per RFC §3.2 we MUST attempt to parse vN as v0 if length is
    // >= the v0 minimum and the prefix is hex. We choose strict parsing —
    // an unknown version with a leading byte we don't recognize is rejected.
    if &value[0..3] != b"00-" {
        return None;
    }

    let trace_id = parse_hex_fixed::<16>(&value[3..35])?;
    if value[35] != b'-' {
        return None;
    }
    let span_id = parse_hex_fixed::<8>(&value[36..52])?;
    if value[52] != b'-' {
        return None;
    }
    let flags = parse_hex_fixed::<1>(&value[53..55])?[0];

    // RFC §3.2.2.2 / §3.2.2.3: all-zero IDs are invalid.
    if trace_id.iter().all(|&b| b == 0) || span_id.iter().all(|&b| b == 0) {
        return None;
    }

    Some(TraceContext {
        trace_id,
        span_id,
        flags,
    })
}

/// Parse a fixed-length hex string into a byte array. Strict — any non-hex
/// digit returns `None`. Branch-free per byte (table lookup).
fn parse_hex_fixed<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_val(s[i * 2])?;
        let lo = hex_val(s[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Write `src` as lowercase hex into `dst`. `dst.len() == 2 * src.len()` is
/// the caller's invariant (compile-time-checked at call sites).
#[allow(dead_code)] // Used by `write_trace_id_hex` / `write_span_id_hex` (also gated above).
fn write_hex(src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(dst.len(), src.len() * 2);
    const LUT: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in src.iter().enumerate() {
        dst[i * 2] = LUT[(b >> 4) as usize];
        dst[i * 2 + 1] = LUT[(b & 0x0F) as usize];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Subscriber init.
// ─────────────────────────────────────────────────────────────────────────────

/// Output format for the always-on subscriber.
#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    /// Pretty multi-line text, ANSI-colored on a TTY. Default for `cargo run`.
    Text,
    /// One JSON object per line. Default for production.
    Json,
}

impl LogFormat {
    pub fn from_str(s: &str) -> Self {
        match s {
            "json" => Self::Json,
            _ => Self::Text,
        }
    }
}

/// Initialize the global tracing subscriber. Idempotent — safe to call
/// from `main()` after `logging::init()`. The two systems coexist:
/// `logging::*` keeps emitting boot/lifecycle text directly to stderr,
/// while `tracing::*` routes through the subscriber installed here.
///
/// Filtering precedence:
///   1. `RUST_LOG` env var if present (full `tracing-subscriber` syntax)
///   2. fall back to `info` level for the `zion` target, `warn` elsewhere
///
/// The OTLP layer is wired separately by `init_otel_layer()` when the
/// `otel` feature is enabled — kept apart so toggling it doesn't risk
/// double-installing the global subscriber.
pub fn init_subscriber(format: LogFormat) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("zion=info,warn"));

    // The registry composition produces a different concrete type per layer
    // permutation, so we cannot easily store an intermediate as a `Box<dyn>`
    // and still call `try_init`. We therefore inline the four (format ×
    // otel) cases — small duplication, zero dynamic dispatch.

    match format {
        LogFormat::Json => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .flatten_event(true)
                .with_target(true)
                .with_writer(std::io::stderr);

            #[cfg(feature = "otel")]
            if let Some(otel_layer) = otel::build_layer() {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .with(otel_layer)
                    .try_init()
                    .ok();
                return;
            }

            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .try_init()
                .ok();
        }
        LogFormat::Text => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_writer(std::io::stderr);

            #[cfg(feature = "otel")]
            if let Some(otel_layer) = otel::build_layer() {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .with(otel_layer)
                    .try_init()
                    .ok();
                return;
            }

            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .try_init()
                .ok();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3b. Panic hook — structured JSON event + last-gasp file before abort.
// ─────────────────────────────────────────────────────────────────────────────

/// Install a process-wide panic hook that emits a structured JSON record to
/// stderr and to a "last-gasp" file before the process aborts.
///
/// The release profile sets `panic = "abort"`, so a panicking worker is
/// fatal. The default Rust panic hook prints a backtrace to stderr — fine
/// for `cargo run`, useless for a structured log pipeline. This hook:
///
///   - increments [`PANICS_TOTAL`] (visible on `/metrics` even after the
///     last metric scrape, since the OS process is gone — but the hook
///     also writes to disk so the *next* boot can self-report the prior
///     death);
///   - emits a single-line JSON record to stderr (pickable up by Loki /
///     ELK / Datadog without any further parsing);
///   - persists the same record to `last_gasp_path` so a sidecar can
///     surface it on restart;
///   - chains to whatever panic hook was already installed (so test
///     harnesses keep their pretty unwind output).
///
/// Idempotent: calling it twice is harmless, the second call is a no-op.
pub fn install_panic_hook(last_gasp_path: Option<std::path::PathBuf>) {
    use std::sync::Once;
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICS_TOTAL.fetch_add(1, Ordering::Relaxed);

            // Pull what we can without itself panicking.
            let payload = info
                .payload()
                .downcast_ref::<&'static str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string panic payload>");

            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "<unknown location>".into());

            let thread = std::thread::current();
            let thread_name = thread.name().unwrap_or("<unnamed>");

            let ts_us = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_micros() as u64)
                .unwrap_or(0);

            // Hand-rolled JSON — we may be panicking inside serde itself,
            // so we cannot rely on a derive-based serializer here.
            let line = format!(
                concat!(
                    r#"{{"ts_us":{ts},"level":"FATAL","event":"panic","#,
                    r#""thread":"{thread}","location":"{loc}","msg":"{msg}"}}"#,
                    "\n",
                ),
                ts = ts_us,
                thread = json_escape(thread_name),
                loc = json_escape(&location),
                msg = json_escape(payload),
            );

            // 1. Stderr (best effort — never propagate panic from inside a panic).
            let _ = std::io::Write::write_all(&mut std::io::stderr().lock(), line.as_bytes());

            // 2. Disk (best effort — same caveat). Use append so a flurry of
            //    panics in the seconds before abort is preserved.
            if let Some(path) = last_gasp_path.as_ref() {
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
            }

            // 3. Chain to the previous hook so tests / cargo run keep their
            //    pretty output. This must be last — the previous hook may
            //    consume `info` semantically.
            prev(info);
        }));
    });
}

/// JSON-escape per RFC 8259 §7. We only worry about the small set of bytes
/// actually present in panic payloads / locations / thread names; this
/// keeps the panic-time path allocation-light.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. OTLP exporter (feature-gated).
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "otel")]
mod otel {
    //! OTLP gRPC exporter — installed only when `--features otel`.
    //!
    //! Endpoint resolution (in order):
    //!   1. `OTEL_EXPORTER_OTLP_ENDPOINT` env var
    //!   2. `http://127.0.0.1:4317` (the conventional collector default)
    //!
    //! The exporter ships `tracing` events as OpenTelemetry spans.

    use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{trace::TracerProvider, Resource};
    use opentelemetry_semantic_conventions as semconv;
    use tracing::Subscriber;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::Layer;

    pub fn build_layer<S>() -> Option<impl Layer<S>>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:4317".into());

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .ok()?;

        let resource = Resource::new(vec![
            KeyValue::new(semconv::resource::SERVICE_NAME, "zion"),
            KeyValue::new(
                semconv::resource::SERVICE_VERSION,
                env!("CARGO_PKG_VERSION"),
            ),
        ]);

        let provider = TracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .build();

        let tracer = provider.tracer("zion");
        global::set_tracer_provider(provider);

        Some(OpenTelemetryLayer::new(tracer))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Tests — RFC vectors for the traceparent parser.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = b"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    #[test]
    fn parses_canonical_rfc_example() {
        let ctx = parse_traceparent(VALID).expect("valid example must parse");
        // Trace ID
        let mut hex = [0u8; 32];
        ctx.write_trace_id_hex(&mut hex);
        assert_eq!(&hex, b"0af7651916cd43dd8448eb211c80319c");
        // Span ID
        let mut hex16 = [0u8; 16];
        ctx.write_span_id_hex(&mut hex16);
        assert_eq!(&hex16, b"b7ad6b7169203331");
        assert!(ctx.is_sampled());
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse_traceparent(b"00-foo").is_none());
        assert!(parse_traceparent(b"").is_none());
    }

    #[test]
    fn rejects_wrong_version() {
        let ff = b"ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert!(parse_traceparent(ff).is_none());
    }

    #[test]
    fn rejects_non_hex_in_trace_id() {
        let bad = b"00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01";
        assert!(parse_traceparent(bad).is_none());
    }

    #[test]
    fn rejects_zero_trace_id() {
        let zero = b"00-00000000000000000000000000000000-b7ad6b7169203331-01";
        assert!(parse_traceparent(zero).is_none());
    }

    #[test]
    fn rejects_zero_span_id() {
        let zero = b"00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01";
        assert!(parse_traceparent(zero).is_none());
    }

    #[test]
    fn rejects_missing_separator() {
        let nodash = b"00:0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert!(parse_traceparent(nodash).is_none());
    }

    #[test]
    fn flags_unsampled() {
        let unsampled = b"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00";
        let ctx = parse_traceparent(unsampled).expect("must parse");
        assert!(!ctx.is_sampled());
    }

    #[test]
    fn write_hex_roundtrips() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let mut out = [0u8; 8];
        write_hex(&bytes, &mut out);
        assert_eq!(&out, b"deadbeef");
    }

    #[test]
    fn json_escape_handles_quotes_and_control() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape(r#"a "b" c"#), r#"a \"b\" c"#);
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\tb"), "a\\tb");
        // Unicode passes through unescaped (RFC 8259 allows it).
        assert_eq!(json_escape("héllo"), "héllo");
        // Control byte under 0x20 → \uXXXX.
        assert_eq!(json_escape("\x01"), "\\u0001");
    }

    // Note: we deliberately do NOT call `install_panic_hook` from tests.
    // It mutates the process-wide panic hook, which interferes with other
    // tests running concurrently (cargo test parallelizes by default).
    // The hook's behaviour is exercised in integration tests instead, where
    // we run a single binary in a child process.

    #[test]
    fn render_counters_emits_all_five() {
        PANICS_TOTAL.store(7, Ordering::Relaxed);
        AUDIT_EVENTS_TOTAL.store(13, Ordering::Relaxed);
        let mut out = bytes::BytesMut::new();
        render_counters(&mut out);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("zion_panics_total 7"));
        assert!(text.contains("zion_audit_events_total 13"));
        assert!(text.contains("zion_audit_events_dropped_total"));
        assert!(text.contains("zion_traces_emitted_total"));
        assert!(text.contains("zion_traces_invalid_total"));
    }
}
