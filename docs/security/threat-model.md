# Threat Model — STRIDE

This document maps each major external surface of Zion to the six STRIDE
categories — **S**poofing, **T**ampering, **R**epudiation, **I**nformation
disclosure, **D**enial of service, **E**levation of privilege — and lists
the in-binary mitigations and residual risk for each.

It is the authoritative starting point for security review and is updated
on every change that adds a new external surface (a new listener, a new
header parsed in the hot path, a new admin endpoint, a new feature flag
exposed at runtime).

Surfaces covered:

1. TLS termination (rustls + aws-lc-rs)
2. WAF gates (URI / body / headers / entropy / structural validation)
3. Request dispatch (router, rate-limit, CORS, traceparent)
4. Hot-reload (file watcher → `ArcSwap`, listener rebind)
5. Audit log (HMAC chain on disk)
6. Panic hook (last-gasp file)
7. Internal endpoints (`/metrics`, `/_zion/snapshot.json`, ACME challenge)
8. ACME / auth (opt-in feature paths)
9. Container / Helm deployment

Each entry uses this template:

> **Risk** — concrete attack scenario.
> **Mitigation** — what's already in the binary or chart.
> **Residual** — what's not covered, with the rationale.

---

## 1. TLS termination

**S — spoofing**: a client presenting a forged certificate against an mTLS
route, or an MITM exploiting a TLS downgrade.
- **Mitigation**: TLS 1.3 enforced on all `[tls]` paths (no 1.2 fallback);
  `client_auth` is config-gated — without an explicit CA bundle no client
  auth is attempted. mTLS leaf is hashed (SHA-256) and forwarded as
  `X-Client-Cert-Fingerprint` so upstreams can pin without trusting the
  client's claimed identity. Session tickets are encrypted with rustls'
  rotating server keys.
- **Residual**: trust anchors are whatever the operator places in
  `client_ca_path`. We do not enforce CT, OCSP stapling, or CRL distribution
  for client certs — this is a deliberate scope choice for v0.1.x
  (re-evaluate at v0.2 along with the [ADR-0001 hot-reload model](../adr/0001-arcswap-config-hot-reload.md)).

**T — tampering**: in-flight injection of WAF-bypass payloads on a hijacked
TLS session.
- **Mitigation**: TLS 1.3 AEAD ciphersuites (`TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) — record-level
  integrity is the spec's job. Boot-time AES-GCM calibration verifies that
  the chosen cipher is hardware-accelerated; the *Performance Tier* badge
  surfaces a regression to the operator at startup.
- **Residual**: ciphersuite list is rustls-default; we do not expose a
  per-deployment override. Acceptable — rustls's defaults are conservative.

**R — repudiation**: a client claims they never sent a particular request.
- **Mitigation**: when audit is enabled, every `request_blocked` event ties
  the WAF deny (URI / body / headers) to the resolved client IP and the
  request's W3C trace ID. Chain HMAC means the operator (with the key) can
  prove the event was emitted at the recorded time.
- **Residual**: audit covers gates that *deny* — successful requests are
  not individually signed (out of scope for compliance use cases that need
  full request-level non-repudiation, which would require a TLS proxy with
  a signed access log).

**I — information disclosure**: leak of session keys, of cert/key file
contents, or of upstream URLs through error messages.
- **Mitigation**: cert/key paths are loaded once at boot and during hot
  reload; the file contents never appear in any log or HTTP response.
  Server identity is stripped (`Server` header removed by
  `inject_security_headers`). HSTS is preloaded.
- **Residual**: an operator can paste a `zion.toml` with secret paths into
  a public issue. Docs flag this; not a code-level mitigation.

**D — denial of service**: TLS handshake flooding, slow-loris on the TLS
ClientHello stream.
- **Mitigation**: explicit TLS handshake timeout (10s, hardcoded);
  per-connection semaphore (`AppState::conn_limit`) caps in-flight
  connections at the platform-detected ceiling; `SO_REUSEPORT` lets the
  kernel load-balance handshake work across worker threads.
- **Residual**: no SYN cookies / connection-rate cap at L4 — that belongs
  to the network layer (LB, AWS Shield, ipset).

**E — elevation of privilege**: cert reload races with in-flight handshake,
allowing an attacker to keep using a revoked cert.
- **Mitigation**: hot-reload is `ArcSwap` ([ADR-0001](../adr/0001-arcswap-config-hot-reload.md))
  — readers acquire an `Arc<ServerConfig>` snapshot for the duration of one
  handshake; new connections use the new config; old connections finish on
  the old config. There is no "torn" config because reads never observe a
  partial write.
- **Residual**: a long-lived TLS session continues to use the *session
  ticket* keys it was issued with even after a config rotation. Sessions
  expire on their own TTL (rustls default 8h); operators that need
  immediate revocation must restart the daemon.

## 2. WAF gates

**S — spoofing**: smuggling a payload past the body scanner via
content-type confusion (e.g. claiming JSON but sending form data).
- **Mitigation**: WAF gate 1 enforces a strict Content-Type allowlist with
  delimiter parsing — `application/json` must be exactly that, not
  `application/json/x-bypass`. Gate 4 runs `simd-json` structural
  validation when the type *is* JSON and rejects malformed input
  before any deserialization happens downstream.
- **Residual**: inspection is per-route, gated by `[waf_profile]`. A route
  without a profile gets no WAF — operator decision, called out in the
  config example.

**T — tampering**: encoding tricks (double-percent, mixed case, SQL
comment) used to slip a payload past the multi-pattern scanner.
- **Mitigation**: WAF gate 2 normalizes URLs iteratively (URL-decode →
  strip `--` / `/* */` SQL comments → unescape JSON unicode) before running
  Aho-Corasick, see [ADR-0002 Aho-Corasick over regex](../adr/0002-aho-corasick-over-regex.md).
  Gate 3 measures Shannon entropy on JSON string literals and trips on
  packed/obfuscated payloads (default 6.5 bits/byte, configurable).
- **Residual**: no semantic SQL/JS parser — heuristic pattern matching by
  design. The trade-off is documented in the ADR.

**R — repudiation**: a deny event without enough context for forensics.
- **Mitigation**: every WAF deny path emits a `request_blocked` audit
  event with `kind=request_blocked`, `remote_ip`, `method`, `path`
  (query string redacted per `[redact]`), and `detail=waf:<source>:<reason>`.
  When audit is disabled, the same fields are logged via `tracing::info!`.
- **Residual**: shadow-mode (`waf_shadow = true`) suppresses the deny — by
  design — and only logs `would_block=true`. Operators in shadow mode
  must scrape that field separately.

**I — information disclosure**: error messages leaking which rule fired.
- **Mitigation**: deny responses are a fixed `400` with the body
  `"request rejected"`; the rule name appears only in operator logs and
  audit, never on the wire.

**D — denial of service**: huge bodies, deeply-nested JSON, header
explosions.
- **Mitigation**: `max_body_mb` per profile (default 10 MB, configurable).
  `simd-json` depth/size limits in gate 4 reject payloads that would push
  the parser into pathological time. `max_headers=64` and `max_buf_size=16K`
  on the hyper builder cap header-bomb attempts. Per-IP rate limiter is
  *upstream* of the WAF so a flood can't even reach the scanner.
- **Residual**: a single very large body that's *just under* the limit
  still costs a full scan. Streaming-scan with early-exit is the planned
  follow-up under Track D ("Performance ceiling").

**E — elevation of privilege**: a route configured with no WAF profile
because of a typo.
- **Mitigation**: config validation at boot rejects unknown profile names
  ([ADR-0001](../adr/0001-arcswap-config-hot-reload.md)). A profile name
  in `route.waf_profile` that doesn't exist in `[waf_profile]` fails the
  entire reload and the previous snapshot survives.

## 3. Request dispatch

**S — spoofing**: client-supplied `X-Forwarded-For` lying about the real
IP, bypassing rate-limit / `internal_only` gates.
- **Mitigation**: `[server.trusted_proxies]` defines CIDRs that may speak
  XFF. The dispatcher uses *rightmost-untrusted-hop* resolution, not "first
  XFF". Outbound XFF policy is `append` / `rewrite` / `drop` per
  `xff_mode`; the `rewrite` mode is recommended when Zion is the front
  edge — it strips inbound XFF entirely.
- **Residual**: misconfiguring `trusted_proxies` to include 0.0.0.0/0
  would un-do the protection. Boot config validation flags an empty list
  but does not block 0.0.0.0/0 — that's a legitimate, if rare, deployment.

**T — tampering**: malformed `traceparent` polluting downstream tracing.
- **Mitigation**: `observability::parse_traceparent` validates per W3C v0
  spec and rejects malformed / all-zero IDs. Invalid headers are dropped,
  counted (`zion_traces_invalid_total`), and replaced with a freshly
  generated context — never forwarded.

**R — repudiation**: untraceable request.
- **Mitigation**: every request gets an `X-Request-ID` (preserved if the
  client sent one, else generated as `<ts>-<seq>`) and a W3C
  `traceparent` (parsed if valid, else generated). Both are echoed back
  to the client and forwarded to upstreams.

**I — information disclosure**: query-string secrets leaking into access
logs / audit.
- **Mitigation**: `[redact.query_params]` lowercases and matches keys
  case-insensitively; values become `<redacted:N>`. Applied at audit-event
  construction *before* HMAC, so the on-disk record carries no secret.
- **Residual**: structured access log integration is a follow-up
  (the audit log is the authoritative privacy-respecting trail today).

**D — denial of service**: resource exhaustion through requests Zion
admits and processes (large bodies, slow upstream, rate-limit bypass).
- **Mitigation**: lock-free rate-limiter with packed `(window, count)` u64
  per IP; bounded `MAX_RATE_MAP_ENTRIES=100_000` with fail-closed eviction;
  `MAX_URI_LEN=8192`; method allowlist (7 methods); upstream timeout via
  hyper's pool config; 1h connection ceiling for H2/WS/SSE.

**E — elevation of privilege**: routing a request to a more privileged
upstream than the route definition allows.
- **Mitigation**: routes are matched by a radix-tree (matchit) against the
  full path; the resolved upstream is computed from the *snapshot* the
  request was admitted under, so a hot-reload mid-flight cannot retarget
  in-flight requests.

## 4. Hot-reload

**S — spoofing**: an attacker writes a malicious zion.toml, hoping the
watcher swaps it in.
- **Mitigation**: file-system permissions are the owning operator's
  responsibility. The watcher does NOT authenticate the change; it is the
  *integrity* of the underlying filesystem that matters (chmod 0640
  + chown root:zion in the systemd unit, read-only mount in the container).

**T — tampering**: a partial-write or truncated config visible mid-rename.
- **Mitigation**: parse + full validation happens off-thread in a
  `spawn_blocking`; only a successfully validated config swaps in via
  `ArcSwap::store()`. A partial write fails parsing and the previous
  snapshot survives.

**R — repudiation**: silent reload that the operator can't reconstruct.
- **Mitigation**: `zion_config_generation` counter ticks on every
  successful swap; a `tracing::info!` event is emitted with the new
  generation number; `/_zion/snapshot.json` exposes it. Operators can
  alert on stale generation or unexpected churn.

**I — information disclosure**: not applicable — config is
operator-controlled, not user-controlled.

**D — denial of service**: a flapping config file (CI auto-write loop)
trashing the daemon.
- **Mitigation**: the watcher debounces and runs a single reload at a time
  (next event during a parse waits). A bad reload doesn't change state.
- **Residual**: a write-storm is bounded by the disk's IOPS, not by Zion.
  A future enhancement could add a "min interval" gate.

**E — elevation of privilege**: a reload that re-binds a privileged port
and bypasses CAP_NET_BIND_SERVICE checks.
- **Mitigation**: the listener supervisor honours kernel rules — a port
  change that the running UID/GID can't bind fails the rebind, leaves the
  old listener alone, and surfaces a structured warning. No privilege
  is acquired by reload.

## 5. Audit log

**S — spoofing**: an event that claims to come from a different source.
- **Mitigation**: all events are emitted by Zion's own writer task with a
  `source=zion` implicit by file ownership (the operator scopes write
  access to the `zion` UID).

**T — tampering**: a malicious operator (or attacker with file-write
access) modifying a past event to hide an action.
- **Mitigation**: HMAC-SHA256 chain over canonical(event)|prev_hash. A
  modified event breaks the next event's `prev_hash`. The verifier walks
  top-down and stops at the first mismatch. The HMAC key is held in an
  env var, never in the config file or on disk next to the log.
- **Residual**: an attacker who has the HMAC key can forge a chain.
  Mitigated by storing the key separately (e.g. in a sealed Vault path
  that `systemd-creds` materialises into the env at start). Documented
  in [docs/guide/observability.md](../guide/observability.md).

**R — repudiation**: an operator denies that an action happened.
- **Mitigation**: the chain root is anchored at a deterministic genesis
  tag derived from the key; verifying the chain proves the events were
  signed by someone who had the key at the time.

**I — information disclosure**: the audit log itself leaks PII.
- **Mitigation**: `[redact.headers]` and `[redact.query_params]` apply
  *before* signing — the on-disk record carries `<redacted:N>` rather
  than the secret. Default lists are empty (back-compat); operators
  opt in.

**D — denial of service**: flooding the audit queue.
- **Mitigation**: bounded `mpsc` (default `queue_depth=4096`); overflow
  drops the event and ticks `zion_audit_events_dropped_total`; the hot
  path *never* blocks on the audit writer.
- **Residual**: the dropped counter is the operator's signal — alert on
  it or raise the queue.

**E — elevation of privilege**: not applicable.

## 6. Panic hook

**R — repudiation**: a worker panics silently and the process restarts
with no record.
- **Mitigation**: `observability::install_panic_hook` writes one
  structured JSON record to stderr *and* to a "last-gasp" file
  (`/var/lib/zion/last_panic.jsonl`, override `ZION_LAST_GASP_PATH`)
  before the process aborts. Every panic increments
  `zion_panics_total` so the next scrape catches it; the next boot's
  startup probe / sidecar surfaces the persisted record.

**I — information disclosure**: a panic message containing user data.
- **Mitigation**: payload bytes < 0x20 are JSON-escaped. The hook does
  not include thread-local payloads beyond what Rust's panic info
  itself carries. Production code paths use `?` propagation, not
  `panic!`, on user-controlled data.
- **Residual**: a third-party crate's panic could carry user-controlled
  bytes in its message. Mitigated by the JSON-escape helper; not
  blocked.

## 7. Internal endpoints

**E — elevation of privilege**: scraping `/metrics` or
`/_zion/snapshot.json` from an external IP.
- **Mitigation**: both endpoints check the resolved client IP against
  `is_internal_ip` (RFC 1918 + loopback + ULA + link-local) and return
  403 to anything else. The check uses the *resolved* IP, not the
  TCP peer, so a trusted-proxy header that names a public IP doesn't
  grant access either.

**I — information disclosure**: the snapshot reveals upstream URLs.
- **Mitigation**: same internal-only gate as `/metrics`. URLs in the
  JSON are operator-supplied and never include credentials (they
  cannot — the URL parser would have rejected them at config load).

## 8. ACME / auth (opt-in)

**Out of band — feature-gated**. When `--features acme` or
`--features auth` are enabled:

- **ACME**: HTTP-01 challenges land in an in-memory store and are served
  *only* under `/.well-known/acme-challenge/<token>`. The store auto-
  expires entries and the renewal task is the sole writer.
- **Auth**: JWT signature verification uses pinned algorithms via
  `[auth_profile.<name>.algorithms]`; JWKS fetch is rate-limited and
  cached.

Both expand the threat surface; operators opting in must re-read the
[hardening guide](hardening.md) for the per-feature checklist.

## 9. Container / Helm deployment

**E — elevation of privilege**: container break-out, host kernel access,
volume tampering.
- **Mitigation**: distroless runtime image (no shell, no apt, no SUID
  binaries); UID 65532 non-root by default; HEALTHCHECK NONE in the image
  — probes live in the orchestrator. Helm chart sets:
  `runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
  `allowPrivilegeEscalation: false`, drops `ALL` capabilities,
  `seccompProfile: RuntimeDefault`.
- **Residual**: the container still has `CAP_NET_BIND_SERVICE` if the
  pod manifest grants it (needed for port 80/443 < 1024). Documented
  in the Helm chart `values.yaml`.

**D — denial of service**: pod scheduled on a node with no CPU left;
fluctuating audit-disk; OOM-kill loop.
- **Mitigation**: Helm chart sets `resources.requests` and
  `resources.limits` with conservative defaults (250m CPU, 256Mi RAM);
  `PodDisruptionBudget` (`minAvailable: 1`) protects against rolling
  drains; `NetworkPolicy` restricts egress to the upstreams declared in
  the chart values.

---

## Out of scope

The following surfaces are intentionally out of scope for this iteration
of the threat model and tracked as roadmap items:

- **Full distributed tracing chain-of-trust** — currently the OTLP
  collector is trusted (any process on the path can mint spans). Adding
  collector-side cryptographic signing or ingress mTLS is the next
  iteration's work.
- **TLS conformance suite** (BoGo, RFC 8446 vectors) — deferred to
  Track E.
- **FIPS 140-3 mode** — `aws-lc-rs` supports it; exposing as a `fips`
  feature is on Track E.
- **Side-channel timing** of the WAF entropy gate — currently a
  short-circuit on first-match. Explored under Track D.

## Updating this document

If you add a new external surface, add a new section here BEFORE the PR
merges. Each section must enumerate STRIDE categories, name the
mitigation, and call out the residual.
