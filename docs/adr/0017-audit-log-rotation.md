# ADR-0017: Audit-log rotation with per-segment chain re-anchoring

- **Status**: accepted
- **Date**: 2026-07-31
- **Deciders**: fabriziosalmi
- **Tags**: audit, observability, operations, security

## Context

The HMAC-SHA256-chained audit log (ADR-0004) is append-only JSON-Lines. In
memory it is a bounded `mpsc` holding one constant FD, so the RSS/FD stability
soak does not flag it — but **on disk it was unbounded**: an operator who enables
audit gets a file that grows until the volume fills (issue #288). A full disk is
a production outage, and the audit writer itself would then start dropping
events. The log needs a size ceiling.

## Decision

Add **size-based rotation** to the writer task, on by default when audit is
enabled.

- **Config** (`[audit]`): `max_size_mb` (default 100; `null`/`0` = unbounded, the
  pre-v0.7 behavior) and `max_files` (default 10; `0` = keep all). The on-disk
  ceiling is `max_size_mb × (max_files + 1)` ≈ 1.1 GB with the defaults.
- **Rotate** when the active segment crosses the byte cap: flush + close it,
  `rename` it to `<path>.<epoch_nanos>`, open a fresh `<path>`, and prune the
  oldest rotated segments (by mtime) beyond `max_files`.

### Per-segment re-anchor (the load-bearing choice)

Each new segment **re-anchors the HMAC chain at genesis** and opens with a
`chain_rotate` marker, rather than carrying `prev_hash` across the rotation
boundary. This is deliberate and matches ADR-0004's existing model: the chain
**already** re-anchors at every process restart (a fresh chain from the genesis
tag + a `chain_init` marker), because continuing from an on-disk tail would mean
trusting an unverified value and so defeats tamper-evidence. Rotation is just
another boundary of the same kind.

Consequences of re-anchoring:

- **Each segment verifies independently** from genesis — a reader can validate
  one rotated file without holding the others.
- **Full-history verification** concatenates the segments in timestamp order,
  exactly as it already concatenates across restarts.
- Cross-segment deletion is not self-detecting within a single segment's chain —
  but this is **no weaker than the pre-rotation guarantee**, which already reset
  per restart. Operators who need append-only durability across the whole history
  ship segments to write-once storage (the `max_files = 0` retention mode exists
  for this).

### Failure handling

- **Rename fails** (read-only dir, cross-device): logged once, and the writer
  reopens the current segment and continues **unbounded** rather than crashing or
  spinning (re-anchor → still over cap → rename fails → repeat). Disk-hygiene
  degrades to the old behavior with a loud `audit log rotation failed` warning;
  audit events are never dropped for a rotation problem.
- **Prune fails**: non-fatal and best-effort — retention slippage never blocks a
  write.
- **Reopen after a successful rename fails**: the writer exits (same terminal
  posture as an un-openable log at boot).

## Consequences

- **Positive**: audit is safe to enable in production; disk is bounded by config;
  the tamper-evidence model is unchanged (same re-anchor semantics as restarts).
- **Negative**: verifying a full history requires ordering the segments (a
  one-line `cat` in timestamp order). A rotated boundary is a `chain_rotate`
  marker, not a continuous hash link — documented in the wire format.
- **Neutral**: rotation is size-based only; time-based rotation (daily segments)
  is a possible follow-up if a compliance regime requires calendar alignment.

## Relationship to ADR-0004

A **follow-up**, not a supersession. ADR-0004 (HMAC-chained audit log) stays
`accepted`; its chain, redaction, and non-blocking-emission properties are
untouched. This ADR only bounds the file on disk and formalizes that a rotation
boundary re-anchors exactly like a process restart.

## References

- ADR-0004 (HMAC-chained audit log)
- `src/audit.rs` (`writer_loop`, `open_and_anchor`, `rotate_paths`, `prune_old_segments`)
- `docs/guide/observability.md` (Rotation and disk usage)
- Issue #288
