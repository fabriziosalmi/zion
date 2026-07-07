# Compliance mapping — SOC 2 + FedRAMP Moderate

This is the **input an operator brings to their auditor**, not a
certification claim. Zion is a component; the certified system is the
operator's deployment that runs Zion. The tables below name the
controls each framework asks about and split each into:

* **Where Zion satisfies it** — the in-binary code path, workflow file,
  or shipped artefact that addresses the control.
* **Operator-side residual** — the deployment-level evidence the
  auditor will still ask the operator to produce (KMS rotation
  schedule, on-call runbooks, identity-provider integration, etc).
* **Out of scope** — controls Zion deliberately doesn't address (and
  why), so the operator can document the boundary cleanly.

Cross-references:

* [STRIDE threat model](threat-model.md) — risk → mitigation → residual.
* [OWASP ASVS L2 mapping](asvs.md) — V1–V14 control evidence.
* [Hardening guide](hardening.md) — runtime config knobs the operator
  flips for the deployment-side rows.
* [Supply chain](supply-chain.md) — SLSA L3 provenance, cosign, SBOM.
* [Architecture decisions](../adr/README.md) — load-bearing engineering
  choices, dated and indexed.

---

## SOC 2 — Trust Service Criteria

The 2017 AICPA TSC are organised under five categories:
**Security (CC)**, **Availability (A)**, **Confidentiality (C)**,
**Processing integrity (PI)**, **Privacy (P)**. Privacy (P) is
service-specific (PII handling) and depends on what data the
*upstream application* processes — Zion as a proxy doesn't store
business-PII, so P is operator-side. Each row below names the
relevant criterion, what Zion satisfies, and what the operator owns.

### CC — Common Criteria (Security)

| TSC | Requirement | Where Zion satisfies it | Operator-side residual |
|-----|-------------|--------------------------|------------------------|
| CC1.1 | Integrity & ethical values codified | Apache-2.0 LICENSE, [CONTRIBUTING.md](../../CONTRIBUTING.md), [DCO sign-off](../../.github/workflows/dco.yml) gate | Operator publishes their own code-of-conduct + reviewer policy |
| CC2.1 | Risk-relevant information communicated | [`docs/security/threat-model.md`](threat-model.md), [`asvs.md`](asvs.md), structured boot log + `/metrics` | Operator runbook covers escalation paths |
| CC3.1 | Risks identified & analysed | STRIDE table covers all 10 surfaces incl. the v0.2.x mesh addendum (§10) | Risk register for the deployment topology (HA, DR) |
| CC4.1 | Internal monitoring | OpenMetrics on `/metrics` (latency histograms, counters, exemplars), audit log (HMAC-chained, JSON-Lines) | SIEM ingest; alert thresholds; incident runbook |
| CC5.1 | Control activities mitigate risk | WAF gates, rate limit, mTLS, audit log, panic hook | Operator's WAF profile choice + rate-limit tuning |
| CC6.1 | Logical access — authentication | mTLS (client cert validation, [`tls.rs`](../../src/tls.rs)); JWT/OIDC under `--features auth` | Identity provider, key rotation, access-review schedule |
| CC6.2 | Logical access — provisioning | Internal-only endpoints (`/metrics`, `/_zion/*`) gated by IP allowlist | LDAP/SCIM provisioning |
| CC6.3 | Logical access — least privilege | Distroless image, UID 65532 non-root, dropped capabilities, `seccompProfile=RuntimeDefault` (Helm chart) | Pod-level NetworkPolicies, RBAC bindings |
| CC6.6 | Boundary protection | TLS 1.3 only ([`tls.rs`](../../src/tls.rs)), `internal_only` route flag, security headers ([`security.rs`](../../src/security.rs)) | Edge firewall, DDoS scrubbing service |
| CC6.7 | Restrict mobile + storage media | N/A — Zion has no client / storage component | — |
| CC6.8 | Detection of unauthorized actions | Audit log records auth_failure / waf_block / config_reload / admin_access; `/metrics` exposes `zion_waf_denied`, `zion_rate_limited` | SIEM correlation rules; on-call paging |
| CC7.1 | Vulnerability identification | `cargo-audit`, `cargo-deny`, `cargo-vet`, `cargo-geiger` workflows in [`supply-chain.yml`](../../.github/workflows/supply-chain.yml); CodeQL workflow | CVE triage cadence, patching SLA |
| CC7.2 | Anomaly detection | Latency histograms with exemplars, panic hook last-gasp file | Operator-side log aggregation + alerting |
| CC7.3 | Incident response process | Panic hook persists root cause; audit log preserves the trail | Operator IR plan + runbooks |
| CC7.4 | Recovery from incident | Hot-reload of TLS + config without restart ([ADR-0001](../adr/0001-arcswap-config-hot-reload.md)) | Backup/DR procedures |
| CC8.1 | Change management | Signed commits, branch protection, mandatory CI on PR (clippy across feature matrix, MSRV, integration tests, supply-chain) | Production change-approval process |
| CC9.1 | Risk mitigation in vendor relationships | SBOM (CycloneDX) per release; pinned crate hashes in `Cargo.lock` | Vendor-risk reviews, contractual provisions |

### A — Availability

| TSC | Requirement | Where Zion satisfies it | Operator-side residual |
|-----|-------------|--------------------------|------------------------|
| A1.1 | Capacity planning | `bootstrap::Platform.tier_score()` projects throughput; criterion microbench harness publishes per-component baselines under [`benchmarks/results/criterion/baseline.json`](../../benchmarks/results/criterion/baseline.json) | Load testing against the operator's actual upstream + traffic mix |
| A1.2 | Environmental protections | N/A in software | Datacentre / cloud-provider SLAs |
| A1.3 | Recovery testing | Chaos suite ([`tests/chaos.rs`](../../tests/chaos.rs)) covers audit-queue overflow, panic recovery, TCP-reset mid-read | Operator DR drills |

### C — Confidentiality

| TSC | Requirement | Where Zion satisfies it | Operator-side residual |
|-----|-------------|--------------------------|------------------------|
| C1.1 | Identification of confidential information | `[redact]` config policy ([`audit.rs`](../../src/audit.rs)) — headers + query params marked sensitive are redacted in audit + access-log paths | Operator chooses `[redact]` keys per data-classification policy |
| C1.2 | Disposal of confidential information | Audit log rotation handled by operator's logrotate (Zion does not retain in-memory state across restart by design) | Retention schedule, deletion procedures |

### PI — Processing Integrity

| TSC | Requirement | Where Zion satisfies it | Operator-side residual |
|-----|-------------|--------------------------|------------------------|
| PI1.1 | Quality of input data | WAF 5-gate pipeline ([`waf.rs`](../../src/waf.rs)): size, content-type, Aho-Corasick scan (raw + decoded), entropy, JSON structural | Application-side schema validation |
| PI1.5 | Records protected from unauthorised modification | HMAC-SHA256-chained audit log ([ADR-0004](../adr/0004-hmac-chained-audit-log.md)); Cargo.lock + cosign-signed releases | Audit-log key custody (HSM / KMS) |

---

## FedRAMP Moderate baseline (NIST 800-53 rev5)

Scoped to the control families relevant to an L7 reverse proxy: **AC**
(Access Control), **AU** (Audit and Accountability), **CM**
(Configuration Management), **IA** (Identification and Authentication),
**SC** (System and Communications Protection), **SI** (System and
Information Integrity), and **SA** (System and Services Acquisition,
where it touches build provenance).

### AC — Access Control

| Control | Requirement | Where Zion satisfies it | Operator-side residual |
|---------|-------------|--------------------------|------------------------|
| AC-2 | Account management | mTLS leaf SHA-256 fingerprint forwarded as `X-Client-Cert-Fingerprint` for upstream identity binding | Identity-provider integration, account lifecycle |
| AC-3 | Access enforcement | Per-route `auth_profile` gate (`--features auth`); per-route `internal_only` IP allowlist | RBAC at upstream |
| AC-4 | Information flow enforcement | Trusted-proxy / xff_mode policy ([`config.rs`](../../src/config.rs)); CORS allowlist | Egress firewall |
| AC-7 | Unsuccessful logon attempts | Per-IP rate limiter ([`security.rs`](../../src/security.rs)); audit `auth_failure` events | Lockout / step-up auth at IdP |
| AC-12 | Session termination | TLS session ticket lifetime (rustls default); idle connection timeout per accepted stream | — |
| AC-17 | Remote access | TLS 1.3 mandatory on `[server.listen_https]`; mTLS optional | VPN / bastion if required |

### AU — Audit and Accountability

| Control | Requirement | Where Zion satisfies it | Operator-side residual |
|---------|-------------|--------------------------|------------------------|
| AU-2 | Auditable events | Audit kinds: `auth_success`, `auth_failure`, `config_reload`, `request_blocked`, `admin_access`, `panic`, `mesh_publish`, `mesh_receive` ([ADR-0004](../adr/0004-hmac-chained-audit-log.md)) | Retention policy |
| AU-3 | Content of audit records | Each event carries `kind`, `ts`, `trace_id`, `remote_ip`, `method`, `path`, `detail` + HMAC chain links | — |
| AU-6 | Audit review, analysis, and reporting | Audit log is JSON-Lines, ingestible by any SIEM | Detection rules, analyst workflow |
| AU-9 | Protection of audit information | HMAC-SHA256 chain breaks on any single tampered line ([ADR-0004](../adr/0004-hmac-chained-audit-log.md)) | Chain-key (`ZION_AUDIT_HMAC_KEY`) stored outside the host (KMS / sealed secret) |
| AU-10 | Non-repudiation | HMAC chain + per-event signature; mesh claims additionally Ed25519-signed | — |
| AU-12 | Audit generation | Bounded mpsc writer with overflow counter (`zion_audit_events_dropped_total`) | Disk capacity monitoring |

### CM — Configuration Management

| Control | Requirement | Where Zion satisfies it | Operator-side residual |
|---------|-------------|--------------------------|------------------------|
| CM-2 | Baseline configuration | `zion.toml` is the single source of truth; [`zion.example.toml`](../../zion.example.toml) is the documented baseline | Operator's GitOps-managed baseline |
| CM-3 | Configuration change control | Hot-reload watcher (notify-rs) + structured `config_reload` audit events; failed reloads rolled back to last good snapshot | Change-approval workflow |
| CM-6 | Configuration settings | All settings live in `zion.toml` + env vars; no hidden runtime mutation | Operator's CIS-benchmark mapping |
| CM-7 | Least functionality | All optional features (`acme`, `auth`, `http3`, `tui`, `ktls`, `numa-aware`, `ml-waf`, `sovereign-aimp`) are off by default | Operator opts in only to features they need |
| CM-8 | System component inventory | CycloneDX SBOM per release artefact; SLSA in-toto attestation | Operator merges SBOM into asset inventory |

### IA — Identification and Authentication

| Control | Requirement | Where Zion satisfies it | Operator-side residual |
|---------|-------------|--------------------------|------------------------|
| IA-2 | Identification & authentication (org users) | mTLS leaf cert validation; JWT/OIDC validation under `--features auth` | IdP integration |
| IA-5 | Authenticator management | TLS 1.3 session tickets via `Ticketer` ([`tls.rs`](../../src/tls.rs)); cert + key hot-reload via `notify` | Cert lifecycle (renewal, revocation distribution) |
| IA-7 | Cryptographic module authentication | aws-lc-rs backend (FIPS 140-3 path under `--features fips`) | FIPS module activation in the deployment if required |
| IA-9 | Service identification & authentication | AIMP node identity Ed25519 keypair persisted under `[sovereign_aimp].identity_path` (when `--features sovereign-aimp`); `node_id` is the public key | Identity backup, rotation cadence |

### SC — System and Communications Protection

| Control | Requirement | Where Zion satisfies it | Operator-side residual |
|---------|-------------|--------------------------|------------------------|
| SC-7 | Boundary protection | HTTPS-only listener mandatory; HTTP listener optional + redirect | Edge firewall, WAF profile choice |
| SC-8 | Transmission confidentiality and integrity | TLS 1.3 AEAD ([`TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`]) | TLS conformance evidence ([tls-conformance.md](tls-conformance.md)) |
| SC-12 | Cryptographic key establishment | rustls 0.23 + aws-lc-rs default groups (X25519, secp256r1, secp384r1) | Key escrow if required |
| SC-13 | Cryptographic protection | aws-lc-rs primitives; `--features fips` for FIPS-validated build ([`fips.md`](fips.md)) | FIPS attestation in deployment if required |
| SC-17 | Public Key Infrastructure certificates | ACME issuance under `--features acme` | Cert-authority choice; revocation distribution |
| SC-23 | Session authenticity | TLS 1.3 ticket signing; mTLS client cert SHA-256 forwarded | — |
| SC-28 | Protection of information at rest | N/A — Zion is stateless across restart by design (caches are volatile) | Application-side encryption-at-rest |

### SI — System and Information Integrity

| Control | Requirement | Where Zion satisfies it | Operator-side residual |
|---------|-------------|--------------------------|------------------------|
| SI-2 | Flaw remediation | Daily `cargo-audit` + `cargo-deny` runs ([`supply-chain.yml`](../../.github/workflows/supply-chain.yml)); CodeQL scheduled scans | CVE response SLA |
| SI-3 | Malicious code protection | WAF Aho-Corasick patterns ([`waf.rs`](../../src/waf.rs)); ML-WAF scoring under `--features ml-waf` | EDR / antimalware on the host |
| SI-4 | System monitoring | OpenMetrics on `/metrics`; structured tracing via `tracing` crate ([ADR-0006](../adr/0006-tracing-with-optional-otlp.md)) | SIEM, on-call rotation |
| SI-7 | Software, firmware, and information integrity | SLSA Level 3 build provenance via Sigstore + Rekor; cosign keyless signature on container; HMAC-chained audit log | Image-pull policy + signature verification at admission |
| SI-10 | Information input validation | WAF 5-gate pipeline ([`waf.rs`](../../src/waf.rs)); `simd-json` structural validation | Application-side schema |
| SI-11 | Error handling | Panic hook last-gasp file; structured error type ([`error.rs`](../../src/error.rs)) | Alert on `zion_panics_total` |

### SA — System and Services Acquisition (build provenance)

| Control | Requirement | Where Zion satisfies it | Operator-side residual |
|---------|-------------|--------------------------|------------------------|
| SA-12 | Supply chain risk management | `cargo-vet` workflow (gated by `supply-chain/audits.toml`); SBOM + SLSA per release; OSSF Scorecard public badge | Vendor-risk acceptance for the upstream crates' authors |
| SA-15 | Development process, standards, and tools | Branch-protected `master`, mandatory CI matrix (clippy across all features, MSRV 1.82, integration tests, supply-chain audits) on every PR | Operator's own SDLC |

---

## Out of scope

Zion does not address — and the operator's auditor should NOT expect
it to — the following control families:

* **Physical and environmental protection (PE)** — datacentre /
  cloud-provider responsibility.
* **Maintenance (MA)** — host-level patching is operator-side.
* **Personnel security (PS)** — organisational, not software.
* **Awareness and training (AT)** — organisational.
* **Privacy (P)** TSC criteria — Zion is a stateless proxy; it does
  not store or process business-PII. Privacy obligations attach to
  the upstream application, not to Zion.
* **Continuous monitoring** at the SIEM/SOAR layer — Zion provides
  the *signals* (`/metrics`, audit log, tracing); the SIEM is operator-
  side.

## How to use this document

1. Auditor asks "show me your evidence for AU-9".
2. Operator hands them this row + the ADR-0004 link + the audit log
   sample.
3. Auditor asks "show me your operator-side audit-log key custody
   evidence".
4. Operator hands them their KMS rotation log + sealed-secret
   manifest. **That part is not in this document.**

The boundary is deliberate — the *system being certified* is the
operator's deployment, not Zion.

## Update procedure

When a PR adds a new feature with compliance-relevant surface (a new
audit kind, a new auth path, a new boundary) the same PR should add
or update a row here, citing the code path that satisfies it. Reviewers
catch drift via the diff.
