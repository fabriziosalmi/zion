# OWASP ASVS L2 mapping

This document maps each [OWASP Application Security Verification
Standard](https://owasp.org/www-project-application-security-verification-standard/)
v4.0.3 control at **Level 2** (the standard target for production-grade
applications) to where it is implemented in Zion and how it is verified.

ASVS L1 is implicitly covered (L2 is a superset). L3 controls that
require per-deployment policy (HSM, formal-methods proofs) are out of
scope for the binary itself; the chart and the threat model document
the L3 lift in
[`docs/security/threat-model.md`](threat-model.md).

Each row of the table follows the format:

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|

Implementation column links to a file or module where the control lives.
Test / Evidence column links to a unit test, integration test, or
external scan whose green status is the operational evidence.

## V1 — Architecture, Design and Threat Modeling

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 1.1.4 | Threat model documented | [threat-model.md](threat-model.md) | Doc reviewed; STRIDE table covers all surfaces, including [§10 Mesh (AIMP)](threat-model.md#10-mesh-aimp-integration) for `--features sovereign-aimp` |
| 1.1.7 | Architecture documented | [adr/](../adr/) (8 ADRs) | ADR index in [adr/README.md](../adr/README.md); mesh integration captured in [ADR-0008](../adr/0008-mesh-aimp-integration.md) |
| 1.4.5 | Data classification documented | [redact](../../src/audit.rs) policy + [`zion.toml`] `[redact]` block | proptest `redact_drops_secret_values` |
| 1.5.2 | Serialization rejected for untrusted input | `simd-json` validation gate in [waf.rs](../../src/waf.rs) | `denies_long_string_value`, fuzz target `redact_query_string` |

## V2 — Authentication

`auth` is feature-gated. When disabled, V2 controls are not applicable
to the binary path. Enabling `--features auth` brings:

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 2.1.1 | Passwords ≥ 12 chars | N/A — Zion is a token-bearing proxy, no password store | — |
| 2.5.1 | Anti-bruteforce | Per-IP rate limit ([security.rs](../../src/security.rs)) | proptest `rate_limiter_caps_at_rps_within_window` |
| 2.10.4 | Cryptographic algorithms current | rustls 0.23 + aws-lc-rs (≥ TLS 1.3) | `--features fips` enforces FIPS subset |

## V3 — Session Management

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 3.5.2 | Session tokens cryptographically signed | TLS 1.3 session tickets via `Ticketer` ([tls.rs](../../src/tls.rs)) | Boot logs show `ticketer` enabled; `cargo test --features fips` |
| 3.7.1 | Session timeout enforcement | rustls default 8 h | rustls upstream tests |

## V4 — Access Control

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 4.1.1 | Trusted enforcement at server side | All gates run server-side ([dispatch.rs](../../src/dispatch.rs)) | integration test suite |
| 4.2.1 | Sensitive endpoints internal-only | `is_internal_ip` gate on `/metrics`, `/_zion/snapshot.json` | `tests/integration.rs` `internal_only_*` |
| 4.3.1 | Admin endpoints separated | `/_zion/*` namespace + IP allowlist | code-review (no admin routes outside namespace) |

## V5 — Validation, Sanitization and Encoding

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 5.1.1 | Server validates all input | WAF 5-gate pipeline ([waf.rs](../../src/waf.rs)) | 60+ unit tests, 4 proptest properties, 3 fuzz targets |
| 5.1.2 | HTTP parameter pollution defence | `matchit` exact-path routing; query rebuilt by [proxy.rs](../../src/proxy.rs) | unit test `denies_double_encoded_traversal` |
| 5.1.3 | URI length limited | `MAX_URI_LEN = 8192` ([dispatch.rs](../../src/dispatch.rs)) | unit test `uri_too_long_returns_414` |
| 5.1.4 | Header count limited | `max_headers = 64` on hyper builder ([main.rs](../../src/main.rs)) | hyper-level enforcement |
| 5.2.x | Encoding output | hyper's serializer; security headers via `inject_security_headers` | unit test `inject_security_headers_*` |
| 5.5.1 | XML parsing disabled / hardened | No XML in default path; `simd-json` covers JSON | code-review |

## V7 — Error Handling and Logging

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 7.1.1 | Centralized logging | tracing subscriber in [observability.rs](../../src/observability.rs) | `cargo test observability` |
| 7.1.2 | Sensitive data NOT in logs | `[redact]` policy applied at audit-event construction | proptest `redact_drops_secret_values` |
| 7.1.3 | Log integrity | HMAC-SHA256 chain ([audit.rs](../../src/audit.rs)) | unit test `tampering_an_event_breaks_the_next_hmac` |
| 7.4.1 | Generic error messages to client | `text_response(StatusCode::BAD_REQUEST, "request rejected")` — no stack traces leaked | manual review of `dispatch.rs` deny paths |

## V8 — Data Protection

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 8.2.1 | Sensitive data redacted in transit logs | `[redact.headers]`, `[redact.query_params]` | proptest matrix |
| 8.3.4 | TLS for sensitive data in transit | rustls 0.23 (TLS 1.3) | `--features fips` validates with NIST CMVP cert |

## V9 — Communication

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 9.1.1 | TLS for all client traffic | HTTPS listener mandatory; HTTP listener optional + redirects | `tls.rs` config validation |
| 9.1.2 | Strong ciphersuite list | rustls default + optional FIPS subset | [docs/security/fips.md](fips.md) |
| 9.1.3 | TLS configuration external evidence | Pending [ssllabs.com](https://www.ssllabs.com/ssltest/) test against canonical deploy — tracked in `tls-conformance.md` |
| 9.2.1 | TLS for outbound calls | hyper-rustls with webpki-roots | upstream connectivity tests |
| 9.2.4 | Authenticated peer-to-peer (mesh) | Ed25519-signed `AimpEnvelope` over Noise AEAD ([aimp_cp.rs](../../src/aimp_cp.rs)) | [threat-model.md §10 Spoofing/Tampering](threat-model.md#10-mesh-aimp-integration) |

## V10 — Malicious Code

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 10.2.1 | No outbound calls to dev infrastructure | No telemetry beacons, no analytics — fully self-contained | code-review |
| 10.3.2 | Dependencies vetted | `cargo audit`, `cargo deny` ([deny.toml](../../deny.toml)) | CI `.github/workflows/supply-chain.yml` |
| 10.3.3 | Build pipeline tamper-evident | SLSA L3 provenance ([release.yml](../../.github/workflows/release.yml)) | `gh attestation verify` recipe in [supply-chain.md](supply-chain.md) |

## V11 — Business Logic

Business logic resides in upstream services. Zion is the L7 ingress
gateway; V11 maps to upstream applications, not to Zion itself.

## V12 — File and Resources

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 12.1.1 | Upload size limited | `max_body_mb` per profile ([waf.rs](../../src/waf.rs)) | unit test `denies_oversize_body` |
| 12.3.1 | File path traversal blocked | URL normalization + WAF Aho-Corasick patterns | unit test `uri_denies_encoded_traversal` |

## V13 — API and Web Service

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 13.1.1 | API exposes only intended methods | Method allowlist (GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS) ([dispatch.rs](../../src/dispatch.rs)) | unit test `disallows_TRACE` |
| 13.2.1 | Rate limit per identity | per-IP rate limiter | proptest `rate_limiter_isolates_ips` |

## V14 — Configuration

| ID | Requirement | Implementation | Test / Evidence |
|---|---|---|---|
| 14.1.1 | Build toolchain pinned | [`rust-toolchain.toml`](../../rust-toolchain.toml), `Cargo.lock` committed | CI `--locked` |
| 14.1.4 | Reproducible builds | `SOURCE_DATE_EPOCH`, `cargo-zigbuild`, deterministic tar | [supply-chain.md](supply-chain.md) "Reproducing a build" |
| 14.2.1 | Components inventoried (SBOM) | CycloneDX 1.5 generated by `cargo cyclonedx` | release artifact `zion-sbom.cdx.json` |
| 14.2.5 | Components signed | cosign keyless on container digest, SLSA on binaries | `cosign verify` recipe in supply-chain.md |
| 14.3.2 | Server hardening | distroless image, non-root UID 65532, dropped capabilities, `seccompProfile=RuntimeDefault` | [Helm chart values.yaml](../../deploy/helm/zion/values.yaml) |
| 14.4.1 | Common security headers | HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy ([security.rs](../../src/security.rs)) | unit test `inject_security_headers_*` |
| 14.5.1 | HTTP method allowlist | dispatch.rs gate | unit test `disallows_TRACE` |

## Coverage summary

| Section | Total L2 controls | Mapped | Notes |
|---|---|---|---|
| V1 Architecture | 12 | 4 | Application-specific items not applicable |
| V2 Auth | 23 | 3 | Feature-gated; bulk lives in upstream |
| V3 Session | 8 | 2 | TLS-only; no app sessions in proxy |
| V4 Access Control | 12 | 3 | Routing-level; upstream owns finer-grained ACL |
| V5 Validation | 23 | 6 | WAF + simd-json |
| V7 Error/Logging | 11 | 4 | Audit + tracing |
| V8 Data | 8 | 2 | Redaction + TLS |
| V9 Comms | 6 | 4 | rustls + FIPS path |
| V10 Malicious | 7 | 3 | Supply-chain pipeline |
| V12 Files | 5 | 2 | Body size + traversal |
| V13 API | 12 | 2 | Method + rate-limit |
| V14 Config | 22 | 7 | SBOM + cosign + Helm |

The total mapped count is conservative — many controls are satisfied by
TLS / hyper / rustls upstream defaults that we don't list here because
they don't produce a useful "test / evidence" link in the Zion
codebase. Operators with a checklist obligation should walk the
official ASVS spreadsheet against this map and tick the boxes that
overlap.

## Update procedure

When adding a new external surface:

1. Walk the ASVS L2 controls relevant to the surface.
2. Add a row here per control. Implementation column must point to a
   file path; Test / Evidence column to a test or external scan.
3. If a control cannot be met, write the gap into
   [threat-model.md](threat-model.md) "Out of scope" and reference
   that section here.
