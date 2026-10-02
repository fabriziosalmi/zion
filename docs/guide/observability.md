# Observability internals

> Looking for the operator how-to — health probes, Prometheus scrape config, the
> Grafana dashboard, and the full metric reference? See
> [Metrics & health endpoints](../deploy/observability). This page is the
> feature/internals reference.

Zion's observability stack covers four concerns:

1. **Distributed tracing** — `tracing` everywhere, optional OTLP gRPC export.
2. **Metrics with exemplars** — Prometheus text format upgraded to OpenMetrics so each histogram bucket can carry the trace ID of the latest observation that fell into it.
3. **Audit log** — HMAC-SHA256-chained JSON-Lines, opt-in.
4. **Panic hook** — every panic emits one structured JSON record to stderr and to a "last-gasp" file before the process aborts.

All four are always linked into the binary; they're cheap when idle. OTLP export is the only feature gated behind a build flag (`--features otel`) because it pulls in tonic + prost.

## Distributed tracing

The `tracing` crate is initialized at boot. Filtering follows `RUST_LOG` (full `tracing-subscriber` syntax); the default is `zion=info,access=info,sovereign=info,warn` (zion's own events, the access log and the sovereign classification log at `info`, dependencies at `warn`). Output format mirrors `[server.log_format]`:

| `log_format` | Output |
|---|---|
| `text` *(default)* | on a TTY: pretty, ANSI-colored. When stderr is **not** a terminal (journald, `docker logs`, a file): one line per event, `<UTC timestamp> <LEVEL> <event>: <message>`, so lines can be ordered and filtered by subsystem |
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

```text
zion_request_duration_seconds_bucket{le="0.512"} 17 # {trace_id="0af7651916cd43dd8448eb211c80319c"} 0.481234 1714896000.123
```

The exemplar update cost is 4 relaxed atomic stores on a cache line we just touched — measurable in benchmarks at sub-percent overhead, hidden by the existing histogram observation cost.

Six reliability counters are exposed alongside the existing ones:

| Counter | Meaning |
|---|---|
| `zion_panics_total` | Worker panics caught by the panic hook. |
| `zion_audit_events_total` | Audit-log events emitted (signed + chained). |
| `zion_audit_events_dropped_total` | Audit events dropped: the queue was full (slow disk or `audit.queue_depth` too small) **or** the writer has exited. Use `zion_audit_writer_up` to tell them apart. |
| `zion_audit_write_failures_total` | Write, flush or fsync errors on the audit log. Non-zero means records are at risk. |
| `zion_audit_enabled` (gauge) | `1` when `[audit] enabled = true` started a writer. |
| `zion_audit_writer_up` (gauge) | `1` while the writer task is running, `0` once it has exited (disk full, fd revoked, reopen failure). Alert on `zion_audit_enabled == 1 and zion_audit_writer_up == 0`. |
| `zion_audit_last_write_timestamp_seconds` (gauge) | Unix time of the last record flushed successfully. |
| `zion_traces_emitted_total` | Request spans observed (one per request). |
| `zion_traces_invalid_total` | Inbound `traceparent` headers rejected as malformed. |
| `zion_admin_rejects_total` | Admin-API requests rejected (auth or rate-limit) at `[admin]`. |

## Sovereign IP classification (`--features geo-ita` / `geo-eu`)

When the `[sovereign]` block is enabled, every request's client IP is
classified against the baked-in CIDR dataset (an O(log N) binary search
+ one relaxed `fetch_add` — no allocation, no syscall, no external GeoIP
DB) and tallied:

```text
zion_sovereign_classifications_total{class="eu"}              42891
zion_sovereign_classifications_total{class="gov_eu"}            317
zion_sovereign_classifications_total{class="residential_eu"}  18044
zion_sovereign_classifications_total{class="datacenter_eu"}    9210
zion_sovereign_classifications_total{class="unknown"}         15538
...
```

The dataset is generated by `scripts/generate_sovereign_data.py` and
refreshed weekly via the `sovereign-data` workflow (RIPE NCC delegated
stats + Team Cymru IPtoASN). The `eu` class is the EU-27 country-level
baseline; `gov_eu` / `residential_eu` / `datacenter_eu` are the more
specific curated-ASN roles that override it.

**Reading "% EU vs non-EU traffic"** — sum the EU-family classes over the
grand total. In PromQL:

```text
sum(zion_sovereign_classifications_total{class=~"eu|gov_eu|residential_eu|datacenter_eu"})
  / ignoring(class) sum(zion_sovereign_classifications_total)
```

Both IPv4 and IPv6 clients are classified (the dataset bakes a `u32`
table and a parallel `u128` table; IPv4-mapped IPv6 folds onto the v4
path). `unknown` therefore means an IP in no dataset — genuinely non-EU
on the `geo-eu` build, or unclassified-by-ASN on `geo-ita`.

**Tag-driven enforcement (`[sovereign.enforce]`).** By default the class
is a pure *signal*. The operator can opt a class (or an AIMP
mesh-reputation threshold) into a hard `403` deny — e.g. `deny =
["unknown"]` on a `geo-eu` build blocks every non-EU source while the EU
classes pass (the sovereign allowlist *by complement*). Denials are
counted, split by reason:

```text
zion_enforcement_denied_total{reason="class"}       1043
zion_enforcement_denied_total{reason="mesh_score"}    77
```

The local WAF / rate-limiter / auth gates stay authoritative — enforcement
only *adds* a deny on top, and is off until configured.

**L7 tarpit (`[sovereign.enforce.tarpit]`, #151).** When enforcement is on,
the operator can escalate a deny from a cheap `403` to a *held* connection:
a flagged source is parked `hold_secs` before the refusal so a backed flood
pays wall-clock and socket budget. A hard global ceiling (`max_concurrent`)
sheds back to an immediate `403` at capacity, and is clamped at config-load
to ¼ of the global connection pool so held connections can't pin admission.

```text
zion_tarpit_active        12     # gauge: connections currently held
zion_tarpit_total       4310     # counter: total ever held
zion_tarpit_shed_total   118     # counter: shed to immediate 403 at the ceiling
zion_tarpit_held_ms_total 43100  # counter: cumulative held wall-clock (ms)
```

Mean hold ≈ `rate(zion_tarpit_held_ms_total[5m]) / rate(zion_tarpit_total[5m])`.
A rising `zion_tarpit_shed_total` means the ceiling is saturated — raise
`max_concurrent` (bounded by the ¼-pool clamp) or lower `hold_secs`. The
ceiling counts in-flight held *requests* (HTTP/2 streams), so size it with
stream fan-out in mind.

## Access log

Every request emits one structured `tracing::info!` event under the `access` target
(on by default; before 0.9.8 the default log filter dropped it unless `RUST_LOG` named
`access`). It costs throughput: one formatted line per request, measured at roughly
15 % of peak req/s on a laptop writing to a file. Turn it off with `[access_log]
enabled = false`. Fields:

| Field        | Type   | Notes                                                        |
|--------------|--------|--------------------------------------------------------------|
| `status`     | u16    | HTTP response status.                                        |
| `latency_us` | u64    | Total request duration (client → response sent), in µs.      |
| `method`     | str    | HTTP method.                                                 |
| `path`       | str    | URI path with query-string redacted via `[redact.query_params]`. |
| `remote_ip`  | str    | The TCP peer address (raw socket peer). Behind a trusted proxy, the XFF-resolved client IP drives rate limiting and the security gates but is **not** what this field logs — read the forwarded chain from your upstream's own logs. |
| `headers`    | json   | Configured headers, redacted per `[redact.headers]`. Empty when `[access_log] include_headers` is empty (default). |
| `mtls_fp`    | str    | `X-Client-Cert-Fingerprint` value (SHA-256 hex), when present and `[access_log] mtls_fingerprint = true`. Never redacted — the value is already a hash. |

### Configuration (issue #60)

```toml
[access_log]
enabled = true            # default; false = no per-request line
# Headers to emit on every access-log line. Lowercased on parse;
# values pass through `[redact.headers]` before serialisation.
include_headers   = ["user-agent", "authorization", "host", "x-forwarded-for"]
# Surface the mTLS leaf-cert SHA-256 fingerprint as a dedicated
# `mtls_fp` field. Default true — set false to omit even when mTLS
# is configured.
mtls_fingerprint  = true

[redact]
# headers in this list are replaced by `<redacted:N>` (N = byte
# length of the original value). Same policy already protects the
# audit log's request_blocked / auth_failure events.
headers       = ["authorization", "cookie", "x-api-key"]
```

### Client IP privacy (`[redact] ip`)

The client address is personal data under GDPR. `[redact] ip` controls how it is written to the
access log (`remote_ip`), the audit trail (`remote_ip`), the TLS-handshake failure lines and the
sovereign classification log (applied at start-up):

| `ip` | Written as | Use |
|---|---|---|
| `"full"` (default) | `203.0.113.9` | forensics and per-client debugging |
| `"truncate"` | `203.0.113.0/24` (IPv4) / `2001:db8:1::/48` (IPv6) | keeps the network (abuse by ISP, rough geography), drops the host; not reversible |
| `"hmac"` | `ip:3f9a1c7e5b2d8a40` | the same client always gets the same token, so a session or an attacker can still be followed across the logs, but the address cannot be recovered without `ip_hmac_key` |

```toml
[redact]
ip = "hmac"
ip_hmac_key = "<at least 16 bytes of secret, from your secret store, not from git>"
```

An IPv4-mapped IPv6 address is treated as IPv4. `hmac` needs `ip_hmac_key` (config validation
refuses it otherwise, and refuses the key with any other mode); a missing key can never fall
back to the raw address. Rotating the key breaks correlation with older logs, which is also
how you "forget" them. Not covered: an `X-Forwarded-For` value you ask to be logged with
`[access_log] include_headers` (redact it with `[redact] headers`), and addresses an upstream
writes in its own logs.

### Storage budget

Each line is a JSON object. With the default fields plus 5 headers
emitted, expect **~500 B per request**. At 100 k rps that's
~50 MB/s of access-log volume — operators sizing log shippers
(Vector, Fluent Bit, Loki agent) should account for this when
opting into `include_headers`. When the list is empty (default),
the line stays at ~120 B.

### Audit-log mirror (`request_completed`)

When `[access_log]` opts in (any header configured OR
`mtls_fingerprint = true` AND `[audit].enabled = true`), every
access-log line is mirrored as a signed audit event with
`kind = "request_completed"`. The `detail` field carries
`status=N latency_us=N headers={…} mtls_fp=…` so a compliance
reviewer querying the audit log sees the same shape they'd see in
the access log, with the HMAC chain attached. The audit kind is
defined as the canonical constant `audit::kind::REQUEST_COMPLETED`.

## Audit log

The audit log is a tamper-evident, HMAC-SHA256-chained JSON-Lines file. It is **disabled by default**.

### Configuration

```toml
[audit]
enabled = true
path = "/var/log/zion/audit.jsonl"
key_env = "ZION_AUDIT_HMAC_KEY"   # default; the secret never lives in zion.toml
queue_depth = 4096                # bounded mpsc — events overflow ⇒ dropped + counted
max_size_mb = 100                 # rotate the active segment at this size; null/0 ⇒ unbounded
max_files   = 10                  # rotated segments to keep (oldest pruned first); 0 ⇒ keep all
sync_interval_ms = 1000           # fsync the active segment this often; 0 ⇒ page cache only
# key_id = "2026-10"              # label for the HMAC key, written into every chain marker
# previous_key_env = "ZION_AUDIT_HMAC_KEY_PREV"   # outgoing key during a rotation (never signs)

[redact]
headers      = ["authorization", "cookie", "x-api-key"]
query_params = ["token", "api_key", "session"]
```

The HMAC key is taken from the named environment variable and must be **at least 32 bytes** (the SHA-256 output size). With `enabled = true`, a missing `path`, an unset or empty key variable, or a key under 32 bytes makes Zion **refuse to start**: a typo in `key_env` or a missing secret mount must not silently remove the tamper-evident trail you asked for. (`enabled = false`, the default, never reads the variable.)

On `SIGTERM` the writer is stopped after the connections have drained: it writes everything still queued, flushes and `fsync`s, and Zion waits up to 5 seconds for it. If that takes longer the daemon logs `audit writer did not finish within 5s`.

### Key rotation

Each chain begins with a `chain_init` / `chain_rotate` marker whose signed `detail` carries `key_id=<label>`. Set `[audit] key_id` to a label of your choosing (`[A-Za-z0-9._-]`, up to 64 characters); if you don't, Zion derives a 16-hex fingerprint from the key, which identifies it without revealing it. A verifier reads the marker to learn which key signed the records that follow.

To rotate without losing the ability to verify history:

1. Keep the outgoing key available to whoever verifies the log, filed under its `key_id`.
2. Put the new key in the environment variable named by `key_env`, set a new `key_id`, and set `previous_key_env` to a variable holding the outgoing key. Restart.
3. The first marker after the restart records `prev_head=…; prev_seq=…; prev_key=previous` when the tail of the existing segment verified under the outgoing key, so continuity across the rotation is checkable. Without `previous_key_env` it reads `prev_head=unverified`.
4. Once the old segments are archived, drop `previous_key_env`.

The previous key is only ever used to check the tail; it never signs anything. Verifying old segments is done with the old key, chosen by the `key_id` in each chain's marker.

### Durability

Every record is flushed to the OS page cache as it is written, which survives `kill -9` but **not** a power loss or kernel crash. `sync_interval_ms` (default `1000`) bounds that exposure: the writer `fsync`s the active segment at that interval — including when the log has gone idle — so a power loss can take at most the last interval of records. Set `0` to skip the periodic sync and accept the page-cache-only behaviour for throughput. Independently of this setting, a segment is `fsync`ed before it is sealed at rotation and the directory is `fsync`ed after the rename, so a sealed segment and its name survive power loss. A failing `fsync` is logged once (`audit log fsync failing`) and never stops the writer.

### Rotation and disk usage

The log is append-only, so it would grow without bound if left uncapped. By default the active segment **rotates** once it reaches `max_size_mb` (100 MB): the file is sealed as `audit.jsonl.<timestamp>` and a fresh segment is opened, so the on-disk ceiling is `max_size_mb × (max_files + 1)` — about **1.1 GB** with the defaults. The oldest rotated segments are pruned first; set `max_files = 0` to keep them all and manage retention out-of-band (e.g. shipping segments to cold storage), or `max_size_mb = 0` to disable rotation entirely (the pre-v0.7 behavior — then **watch disk usage yourself**).

Each segment **re-anchors the HMAC chain at genesis** and opens with a `chain_rotate` marker (a `chain_init` marker for the first segment / a process restart), so every segment verifies independently — the same tamper-evidence model already used across restarts. To verify a full history, concatenate the segments in timestamp order before running the [verifier](#verification). A rotation that cannot rename (e.g. a read-only directory) is logged once and the writer continues on the current segment rather than dropping events — monitor the daemon log for `audit log rotation failed`.

### Wire format

One JSON object per line. Fields:

| Field | Type | Notes |
|---|---|---|
| `seq` | u64 | Monotonic within a process. Resets on restart. |
| `ts` | string | RFC 3339 / ISO 8601 with microsecond precision. |
| `kind` | string | `chain_init`, `chain_rotate` (segment boundary after rotation), `auth_success`, `auth_failure`, `request_blocked`, `config_reload`, `admin_access`, `panic`. |
| `trace_id` | string | Optional. 32-char hex. |
| `remote_ip`, `method`, `path`, `detail` | string | Optional. `path`'s query string is redacted per `[redact.query_params]`. |
| `prev_hash` | string | 64-char hex. The HMAC of the previous record (or the genesis tag for `seq=0`). |
| `hmac` | string | 64-char hex. `HMAC-SHA256(key, canonical_event_json + "|" + prev_hash)`. |

### Verification

The binary verifies segments offline:

```bash
export ZION_AUDIT_HMAC_KEY="$(cat /etc/zion/audit.key)"
zion audit verify /var/log/zion/audit.jsonl /var/log/zion/audit.jsonl.*
# ok   /var/log/zion/audit.jsonl: 4312 records, 3 chain(s)
```

Each segment is checked on its own: every record's HMAC, and that each `prev_hash` is the previous record's HMAC. A chain starts at a `chain_init` / `chain_rotate` marker signed from genesis. `--key-env VAR` picks another key variable, and `--previous-key-env VAR` supplies the outgoing key for segments written before a [key rotation](#key-rotation). The exit code is `0` when everything verified, `1` when a segment failed (the message names the line), `2` for a usage or key error.

It catches a record that was edited, removed or reordered inside a chain. It cannot see the **end** of a chain being cut off, because nothing after it commits to it; the `prev_head=` in the next marker is what covers that. A last line with no newline is reported as a torn tail and not counted.

The same check, as a script, for hosts without the binary:

```bash
KEY="$(cat /etc/zion/audit.key)"   # the HMAC key, kept off-config
python3 - <<'PY'
import hmac, hashlib, json, sys, os

key = os.environ["KEY"].encode()
genesis = hmac.new(key, b"ZION-AUDIT-GENESIS-V1", hashlib.sha256).hexdigest()
prev = genesis
last_head = None   # hmac of the last record of the previous chain
ok = 0
for i, line in enumerate(open("/var/log/zion/audit.jsonl")):
    rec = json.loads(line)
    body = rec.copy()
    expected_prev = body.pop("prev_hash")
    expected_hmac = body.pop("hmac")
    if rec["kind"] in ("chain_init", "chain_rotate"):
        # A new chain starts at genesis. A restart onto an existing segment
        # also states the head it found; it must match what we just verified.
        prev = genesis
        detail = rec.get("detail", "")
        if "prev_head=" in detail and last_head is not None:
            claimed = detail.split("prev_head=")[1].split(";")[0]
            if claimed not in ("none", "unverified") and claimed != last_head:
                sys.exit(f"line {i}: marker says the previous chain ended at "
                         f"{claimed[:16]}, but it ends at {last_head[:16]} "
                         "(records removed or altered)")
    if expected_prev != prev:
        sys.exit(f"chain break at line {i}: prev mismatch")
    canon = json.dumps(body, separators=(",", ":"))  # match serde compact
    sig = hmac.new(key, canon.encode() + b"|" + prev.encode(), hashlib.sha256).hexdigest()
    if sig != expected_hmac:
        sys.exit(f"signature mismatch at line {i}")
    prev = expected_hmac
    last_head = expected_hmac
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

Each restart begins a **fresh chain** anchored at the genesis tag. A `chain_init` record is emitted as `seq=0` so a verifier can spot the boundary. The writer never *continues* a chain from the on-disk tail, since that would mean trusting an unverified value. Instead the signed marker records what it found there, in its `detail`:

- `prev_head=<64 hex>; prev_seq=<n>` — the last record of the existing segment was well-formed and its HMAC verified under the current key; the hex is that record's `hmac`.
- `prev_head=none` — the segment was new or empty.
- `prev_head=unverified` — the segment ended in something that is not a valid signed record (a write cut short by a crash, tampering, or a different HMAC key). The daemon also logs a warning, and the fragment is closed with a newline so the marker stays on its own line.

A verifier can compare `prev_head` with the `hmac` of the last record of the preceding chain in the same file. A mismatch means records were removed from, or altered at, the end of that chain after the restart. Removing the tail of the *last* chain before a restart is still invisible, exactly as before: nothing has been written after it yet to contradict it. Ship segments to write-once storage if you need that.

## Panic hook

Installed before any worker thread is spawned. On a panic anywhere in the process:

1. `zion_panics_total` is incremented.
2. A single-line JSON record is written to stderr — including thread name, source location, and the panic payload, with all control bytes JSON-escaped.
3. The same record is appended to a "last-gasp" file. Default: `/var/lib/zion/last_panic.jsonl`. Override with `ZION_LAST_GASP_PATH`.
4. The previous panic hook (Rust default, or whatever the test harness installed) is chained — no loss of dev-mode backtrace UX.

Because the release profile ships `panic = "abort"`, the hook runs once and the process exits. A sidecar / next-boot probe surfaces the persisted record. Liveness probes detect the corresponding restart through the orchestrator (Helm probes on `/healthz` flap; readiness goes red until a fresh process is up).

## Mesh (`--features sovereign-aimp`)

The mesh layer surfaces its observability through the same triad
(audit log + counters + structured boot log). All mesh counters are
**always rendered on `/metrics`**, zero on builds without
`--features sovereign-aimp` — operators can grep for the same metric
name regardless of which build their distro produced.

Counters wired today (issue #69):

| Metric | Type | What it counts |
|--------|------|----------------|
| `zion_mesh_claims_emitted_total` | counter | Successful local emits (`aimp_cp::publish_block`). |
| `zion_mesh_claims_received_total` | counter | Inbound envelopes that passed *all* policy gates and merged into local state. |
| `zion_mesh_claims_dropped_total{reason="signature"}` | counter | Inbound envelopes rejected on Ed25519 signature verification. |
| `zion_mesh_claims_dropped_total{reason="replay"}` | counter | Inbound envelopes rejected as duplicates (seen-signature filter). |
| `zion_mesh_claims_dropped_total{reason="rate"}` | counter | Inbound envelopes rejected by the per-source claim rate-cap (flood protection). |
| `zion_mesh_claims_dropped_total{reason="other"}` | counter | Other rejections — timestamp skew (past/future), magic-prefix mismatch, payload decode error, revocation by non-original source. |
| `zion_mesh_score_lookups_total` | counter | Dispatcher hits that found a mesh score for the client IP — the `X-Zion-Mesh-Score` header rate. |
| `zion_mesh_gossip_bytes_in_total` | counter | Total bytes received on the gossip socket (covers malformed packets too). |
| `zion_mesh_gossip_bytes_out_total` | counter | Total bytes sent on the gossip socket. |

Audit kinds (see [`src/audit.rs`](../../src/audit.rs)
`mod kind` for the canonical reference list):

- `mesh_publish` / `mesh_receive` — every publish + receive can be
  recorded as a signed audit event carrying the envelope's signature,
  the resolved `node_id`, and the local HMAC chain `prev_hash`.
- `mesh_peer_joined` / `mesh_peer_dropped` — reserved for the mesh
  peer-state tracker (issue [#68](https://github.com/fabriziosalmi/zion/issues/68)).
- `mesh_quorum_decision` — reserved for the quorum aggregator
  ([#66](https://github.com/fabriziosalmi/zion/issues/66) /
   [#67](https://github.com/fabriziosalmi/zion/issues/67)).

Cost: see [`docs/perf/mesh-overhead.md`](../perf/mesh-overhead.md) for
the budget the observability surface is allowed to spend.

The full operator-facing guide (topology, identity rotation,
debugging) lives at [docs/mesh/integration.md](../mesh/integration.md).
Threat-model addendum specific to the mesh surface:
[docs/security/threat-model.md §10](../security/threat-model.md#10-mesh-aimp-integration).

## What's next

- **Span instrumentation** — automatic span creation around `process_request` is wired through the W3C parser; richer per-stage spans (WAF, cache, upstream) will follow in a small follow-up.
- ~~**PII redaction in access logs**~~ — landed via [`[access_log]`](#access-log) (issue #60). Configured headers pass through the same `[redact.headers]` policy that protects audit events.
- **OTLP metrics** — the SDK supports it; we have not enabled the export path yet because the lock-free metrics module already covers the use cases. We may add it for parity if a downstream consumer needs an OTLP-only ingest.
