# ADR-0006: `tracing` always-on, OTLP gated by `--features otel`

- **Status**: accepted
- **Date**: 2026-05-05 (Track B)
- **Tags**: observability, build-flavors

## Context

Zion's previous logging was a hand-rolled `logging::{info,warn,error}`
macro layer that printed text or JSON to stderr. Adequate for boot /
lifecycle events, useless for distributed tracing — no spans, no parent
context propagation, no exemplars on histograms.

Two questions:

1. Adopt `tracing` (de-facto standard for the Tokio ecosystem) or stay
   on the bespoke macros?
2. Bring OpenTelemetry export — and therefore `tonic` + `prost` — into
   the default binary?

## Decision

Adopt `tracing` as the always-on emission path. Layer composition:

- `tracing-subscriber::fmt::layer().json()` (or `.text` if the operator
  set `[server.log_format] = "text"`).
- `EnvFilter` honours `RUST_LOG` with the same syntax everyone already
  knows; default is `zion=info,warn`.

OpenTelemetry / OTLP gRPC export is **gated behind `--features otel`**.
That feature pulls in:

- `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`
- `opentelemetry-semantic-conventions`
- `tracing-opentelemetry` (the bridge)
- transitively: `tonic`, `prost`, `hyper-timeout`, `axum` — significant
  binary-size cost.

When the feature is enabled, the OTLP layer is composed onto the
subscriber and reads `OTEL_EXPORTER_OTLP_ENDPOINT` (default
`http://127.0.0.1:4317`). The W3C Trace Context parser
(`observability::parse_traceparent`) is always-on regardless of
the feature flag — inbound `traceparent` is still validated and
propagated to upstreams in the lean build, just without remote export.

The historical `logging::{info,warn,error}` API is preserved for boot
output (which runs before the runtime exists, so it cannot depend on
tracing's executor-aware machinery). Both systems coexist; nothing
existing has to migrate at once.

## Consequences

- **Positive**: every event gets the standard tracing structure
  (target, level, fields, parent span). Anything in the Tokio
  ecosystem that produces tracing events automatically appears in
  the same JSON stream.
- **Positive**: no OTLP machinery in the lean default binary —
  release artifact stays comparable in size to v0.1.7.
- **Positive**: feature gating is at the layer-composition level,
  not at every call site. `tracing::info!()` works whether OTLP is
  on or off.
- **Negative**: the `--features otel` build is meaningfully bigger
  (~3 MB binary delta) and slower to compile (~10 s extra cold).
  Operators choose.
- **Negative**: two emission paths (`logging::*` + `tracing::*`)
  during the transition period. Boot lines still go through
  `logging::*`; everything else should land on tracing over time.

## Alternatives considered

- **Stay on `logging::*`** — punt the W3C / OTLP question. Rejected:
  the gap analysis flagged "no distributed tracing" as an enterprise
  blocker; downstream users want to pipe Zion into Tempo/Datadog/Honeycomb.
- **Always-on OTLP** — operators without a collector get a noisy
  retry loop and a fatter binary. Rejected.
- **Custom OpenMetrics-only flow** — exemplars are now in `metrics.rs`
  ([Track B commit](../../CHANGELOG.md)) so we already wire the trace
  ID into the histogram. OTLP gives the *spans* dimension that
  metrics-only can't.

## References

- [src/observability.rs](../../src/observability.rs)
- [docs/guide/observability.md](../guide/observability.md)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [OpenTelemetry Rust SDK](https://github.com/open-telemetry/opentelemetry-rust)
