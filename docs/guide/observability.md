# Observability

Zion's observability stack covers four concerns:

1. **Distributed tracing** — `tracing` everywhere, optional OTLP gRPC export.
2. **Metrics with exemplars** — Prometheus text format upgraded to OpenMetrics so each histogram bucket can carry the trace ID of the latest observation that fell into it.
3. **Audit log** — HMAC-SHA256-chained JSON-Lines, opt-in.
4. **Panic hook** — every panic emits one structured JSON record to stderr and to a "last-gasp" file before the process aborts.

All four are always linked into the binary; they're cheap when idle. OTLP export is the only feature gated behind a build flag (`--features otel`) because it pulls in tonic + prost.

## Distributed tracing

The `tracing` crate is initialized at boot. Filtering follows `RUST_LOG` (full `tracing-subscriber` syntax); the default is `zion=info,warn`. Output format mirrors `[server.log_format]`:

| `log_format` | Output |
|---|---|
| `text` *(default)* | pretty multi-line, ANSI-colored on a TTY |
| `json` | one JSON object per line — wire-compatible with Loki / ELK / Datadog |

### W3C Trace Context propagation

Every request carries a `traceparent` header. The dispatcher:

1. Parses the inbound header per [W3C Trace Context v0](https://www.w3.org/TR/trace-context/). All-zero IDs and malformed values are rejected (`zion_traces_invalid_total` counter ticks).
2. If the inbound header was valid, it is forwarded unchanged.
3. Otherwise, Zion generates one and forwards it.

The parsed 16-byte trace ID is attached to the latency histogram as an OpenMetrics exemplar (see below) and to every audit event for the request.

### Optional OTLP export

```bash
cargo build --release --features otel
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo.observability.svc:4317 \
    ZION_CONFIG=zion.toml ./target/release/zion
```

The exporter ships every span emitted by `tracing::info_span!` / `#[instrument]` to the configured collector. Resource attributes are populated from `service.name=zion` and `service.version` (compile-time crate version). No batching parameters are exposed yet; the SDK default (5-second batch, 512-span queue) is in effect.

To verify export end-to-end without a collector, point `OTEL_EXPORTER_OTLP_ENDPOINT` at `http://127.0.0.1:4317` and run `otel-cli` or the [collector contrib distribution](https://github.com/open-telemetry/opentelemetry-collector-contrib) locally.

## Metrics with exemplars

`/metrics` is now OpenMetrics-compatible. Histogram buckets gain a per-bucket exemplar suffix that links to the latest slow request:

```
zion_request_duration_seconds_bucket{le="0.512"} 17 # {trace_id="0af7651916cd43dd8448eb211c80319c"} 0.481234 1714896000.123
```

The exemplar update cost is 4 relaxed atomic stores on a cache line we just touched — measurable in benchmarks at sub-percent overhead, hidden by the existing histogram observation cost.

Five new counters are exposed alongside the existing ones:

| Counter | Meaning |
|---|---|
| `zion_panics_total` | Worker panics caught by the panic hook. |
| `zion_audit_events_total` | Audit-log events emitted (signed + chained). |
| `zion_audit_events_dropped_total` | Audit events dropped because the writer queue was full. Non-zero values mean either the disk is slow or `audit.queue_depth` is too small. |
| `zion_traces_emitted_total` | Request spans observed (one per request). |
| `zion_traces_invalid_total` | Inbound `traceparent` headers rejected as malformed. |

## Audit log

The audit log is a tamper-evident, HMAC-SHA256-chained JSON-Lines file. It is **disabled by default**.

### Configuration

```toml
[audit]
enabled = true
path = "/var/log/zion/audit.jsonl"
key_env = "ZION_AUDIT_HMAC_KEY"   # default; the secret never lives in zion.toml
queue_depth = 4096                # bounded mpsc — events overflow ⇒ dropped + counted

[redact]
headers      = ["authorization", "cookie", "x-api-key"]
query_params = ["token", "api_key", "session"]
```

The HMAC key is taken from the named environment variable. RFC 2104 recommends ≥ 32 bytes for HMAC-SHA256; shorter keys are accepted but Zion logs a warning at boot.

### Wire format

One JSON object per line. Fields:

| Field | Type | Notes |
|---|---|---|
| `seq` | u64 | Monotonic within a process. Resets on restart. |
| `ts` | string | RFC 3339 / ISO 8601 with microsecond precision. |
| `kind` | string | `chain_init`, `auth_success`, `auth_failure`, `request_blocked`, `config_reload`, `admin_access`, `panic`. |
| `trace_id` | string | Optional. 32-char hex. |
| `remote_ip`, `method`, `path`, `detail` | string | Optional. `path`'s query string is redacted per `[redact.query_params]`. |
| `prev_hash` | string | 64-char hex. The HMAC of the previous record (or the genesis tag for `seq=0`). |
| `hmac` | string | 64-char hex. `HMAC-SHA256(key, canonical_event_json + "|" + prev_hash)`. |

### Verification

A simple shell pipeline verifies the chain:

```bash
KEY="$(cat /etc/zion/audit.key)"   # the HMAC key, kept off-config
python3 - <<'PY'
import hmac, hashlib, json, sys, os

key = os.environ["KEY"].encode()
prev = hmac.new(key, b"ZION-AUDIT-GENESIS-V1", hashlib.sha256).hexdigest()
ok = 0
for i, line in enumerate(open("/var/log/zion/audit.jsonl")):
    rec = json.loads(line)
    body = rec.copy()
    expected_prev = body.pop("prev_hash")
    expected_hmac = body.pop("hmac")
    if expected_prev != prev:
        sys.exit(f"chain break at line {i}: prev mismatch")
    canon = json.dumps(body, separators=(",", ":"))  # match serde compact
    sig = hmac.new(key, canon.encode() + b"|" + prev.encode(), hashlib.sha256).hexdigest()
    if sig != expected_hmac:
        sys.exit(f"signature mismatch at line {i}")
    prev = expected_hmac
    ok += 1
print(f"verified {ok} records")
PY
```

The verifier walks top-down and stops at the first inconsistency. Tamper, deletion, or reordering of any record is detected.

### Failure semantics

The writer task runs in `tokio::spawn`. If:

- the queue is full, events are **dropped** and `zion_audit_events_dropped_total` ticks. The hot path never blocks.
- the file cannot be opened at startup, audit is **silently disabled** (with an error log) and the rest of the daemon continues.
- a write fails mid-run (disk full, fd revoked), the writer task exits and subsequent events are dropped. A monitor on `zion_audit_events_dropped_total > 0` is the recommended alert.

Each restart begins a **fresh chain** anchored at the genesis tag. A `chain_init` record is emitted as `seq=0` so a verifier can spot the boundary. Continuing a chain across restarts would require trusting the on-disk tail value, which defeats tamper-evidence.

## Panic hook

Installed before any worker thread is spawned. On a panic anywhere in the process:

1. `zion_panics_total` is incremented.
2. A single-line JSON record is written to stderr — including thread name, source location, and the panic payload, with all control bytes JSON-escaped.
3. The same record is appended to a "last-gasp" file. Default: `/var/lib/zion/last_panic.jsonl`. Override with `ZION_LAST_GASP_PATH`.
4. The previous panic hook (Rust default, or whatever the test harness installed) is chained — no loss of dev-mode backtrace UX.

Because the release profile ships `panic = "abort"`, the hook runs once and the process exits. A sidecar / next-boot probe surfaces the persisted record. Liveness probes detect the corresponding restart through the orchestrator (Helm probes on `/healthz` flap; readiness goes red until a fresh process is up).

## Mesh (`--features sovereign-aimp`)

The mesh layer surfaces its own observability through the same triad
(audit log + counters + structured boot log). When zion is built with
`--features sovereign-aimp` and the mesh is enabled in `zion.toml`,
the following are exposed alongside the core surfaces above:

- `zion_mesh_claims_published_total{kind=...}` — outbound counter per claim type.
- `zion_mesh_claims_received_total{kind=...}` — inbound counter.
- `zion_mesh_claims_rejected_total{reason=...}` — verification failures bucketed by `signature` / `unknown_peer` / `replay`.
- `zion_mesh_peers` — current peer-set size.
- Audit events with `kind=mesh_publish` / `kind=mesh_receive` — every publish + receive carries the envelope's signature, the resolved `node_id`, and the local HMAC chain `prev_hash`.

The full operator-facing guide (topology, identity rotation,
debugging) lives at [docs/mesh/integration.md](../mesh/integration.md).
Threat-model addendum specific to the mesh surface:
[docs/security/threat-model.md §10](../security/threat-model.md#10-mesh-aimp-integration).

## What's next

- **Span instrumentation** — automatic span creation around `process_request` is wired through the W3C parser; richer per-stage spans (WAF, cache, upstream) will follow in a small follow-up.
- **PII redaction in access logs** — the `[redact]` config is consumed by the audit log today; extending it to the structured access-log path is a small, additive change.
- **OTLP metrics** — the SDK supports it; we have not enabled the export path yet because the lock-free metrics module already covers the use cases. We may add it for parity if a downstream consumer needs an OTLP-only ingest.
