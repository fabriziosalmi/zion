# ADR-0004: HMAC-SHA256-chained audit log

- **Status**: accepted
- **Date**: 2026-05-05 (Track B)
- **Tags**: observability, security, compliance

## Context

Compliance reviewers (SOC 2, ISO 27001, GDPR) want a tamper-evident audit
trail for security-relevant events: WAF denies, auth failures, config
reloads, admin endpoint access. Two formats were on the table:

1. **Plain JSON-Lines** — easy to consume, but a malicious operator can
   silently delete or rewrite past entries.
2. **Hash-chained signed records** — each record carries a hash linking
   it to the previous; tamper with any record and the chain breaks at
   the next.

Standalone signature schemes (each record signed independently) detect
modification but not deletion or reordering.

## Decision

Use HMAC-SHA256 over `canonical_json(event) || "|" || prev_hash`. Each
record is a `SignedAuditEvent { event, prev_hash, hmac }`:

- `prev_hash` for the very first record in a process is
  `HMAC(key, "ZION-AUDIT-GENESIS-V1")` — the **genesis tag**.
- Subsequent records use the previous record's `hmac` as their
  `prev_hash`.
- The `|` byte separates event JSON from `prev_hash` in the MAC input.
  A literal `|` cannot appear immediately after a balanced JSON
  top-level `}`, so the boundary is unambiguous.

Verification walks the chain top-down; one mismatched record fails the
whole verification. A small Python verifier ships in
[docs/guide/observability.md](../guide/observability.md).

The HMAC key is sourced from an env var (default
`ZION_AUDIT_HMAC_KEY`) so it never lives in `zion.toml`. RFC 2104
recommends a key of at least the SHA-256 block size (32 bytes); we
warn at boot if shorter.

Each process restart begins a **fresh chain** anchored at the genesis
tag, with a `kind=chain_init` record at `seq=0`. Continuing a chain
across restarts would require trusting the on-disk tail — exactly what
the chain is designed to detect — so we accept the boundary in
exchange for the tamper-evidence property.

## Consequences

- **Positive**: O(n) verification, O(1) per-event cost. Detects
  modification, deletion, and reordering simultaneously.
- **Positive**: reuses `aws-lc-rs::hmac` already in the dep tree (via
  rustls). No new transitive surface.
- **Positive**: the writer task is async + bounded — the hot path
  emits via a non-blocking `try_send`. Queue overflow drops the event
  and increments `zion_audit_events_dropped_total`. Documented as the
  design choice (durability-of-throughput trade-off favours throughput;
  the dropped counter is the alert signal).
- **Negative**: an attacker with the HMAC key can forge a chain.
  Mitigated by sealing the key in a vault path / `systemd-creds` /
  K8s secret with restricted RBAC. Not a code-level mitigation.
- **Negative**: each restart creates a chain boundary; cross-restart
  forensic continuity requires reading multiple chains and confirming
  the timestamps line up. We chose tamper-evidence over continuity.

## Alternatives considered

- **Ed25519 signatures per record** — strictly stronger (asymmetric:
  the verifying key can be public), but each signature is 64 bytes vs.
  the HMAC's 32, the verifier needs the public key distributed
  separately, and our use case is auditor-with-shared-secret, not
  open-public-verifiability. Revisit if a "publish audit logs"
  requirement appears.
- **Merkle tree (instead of a linear chain)** — gives O(log n) inclusion
  proofs but adds significant write-side complexity. Linear is enough
  for compliance; we skipped the tree.
- **External signing service (KMS / HSM)** — one MAC per event becomes
  a network round trip; unacceptable for the audit-event volume we
  expect (10s–100s/s). Local key wins.

## References

- [src/audit.rs](../../src/audit.rs)
- [docs/guide/observability.md](../guide/observability.md) — verification
  recipe.
- RFC 2104, "HMAC: Keyed-Hashing for Message Authentication".
- Crosby & Wallach, "Efficient Data Structures for Tamper-Evident
  Logging", USENIX Sec 2009 — design rationale for hash chains over
  per-record signatures.
