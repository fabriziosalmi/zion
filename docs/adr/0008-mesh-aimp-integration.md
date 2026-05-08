# ADR-0008: Embed AIMP as the mesh control-plane bus

- **Status**: accepted
- **Date**: 2026-05-08 (v0.2.x mesh wire-up)
- **Tags**: mesh, aimp, gossip, identity, federated-state

## Context

A single zion instance is autonomous: WAF gates, rate-limit windows,
upstream-health probes — all run from local state. That works at one
node and falls apart at fleet scale: an attacker probing instance A
hits instance B unmarked, an upstream that flapped on C is still in
the active pool on D, and a rate-limit window saturating on E doesn't
trigger any caution on F. The fleet behaves like N independent
proxies, not one edge.

Track B (v0.2.0) introduced [`aimp_node`](https://github.com/fabriziosalmi/aimp)
— a serverless gossip + Merkle-CRDT + Ed25519-identity primitive
designed precisely for "edge nodes share signed evidence without a
central coordinator". The decision in front of us was not "should we
share state" but "what's the bus".

## Decision

Embed `aimp_node` as an **optional cargo feature** (`sovereign-aimp`,
implies `sovereign-signals`). AIMP carries the wire — Ed25519-signed
envelopes over UDP, anti-entropy SyncReq rounds, Sybil-resistant
peer enrollment. Zion sits *above* AIMP as a typed claim layer:
local subsystems publish typed `MeshClaim`s (WAF block, rate
saturation, upstream unhealthy), the mesh aggregates and re-broadcasts,
and consumers subscribe via `tokio::sync::watch`.

**Local decisions remain authoritative.** A mesh signal influences
*scoring* — a known-malicious score forwarded to upstream as
`X-Zion-Mesh-Score`, an XDP install only at high-confidence consensus
— but never overrides the local WAF / auth / rate-limit gate. That
gate is the trust boundary; the mesh is a force multiplier, not a
delegated authority.

## Consequences

- **Positive — federated state without central infrastructure.** A
  five-node fleet running on three continents can converge on shared
  WAF reputation, rate-saturation alerts, and upstream-health quorum
  in seconds, with zero coordinator process to operate, scale, or
  page on at 03:00.
- **Positive — signed evidence.** Every claim carries an Ed25519
  signature against a per-node identity. The audit log records the
  publish + the receive; a forensic trail survives any single node's
  compromise.
- **Positive — out-of-process viable.** AIMP runs as a library today
  (in-process gossip task), but the protocol is identical to the
  sidecar mode `aimp_node` ships. Nothing about the integration
  forecloses operating it as a separate daemon for blast-radius
  reasons later.
- **Positive — correlation-aware aggregation.** AIMP's CRDT layer
  drops duplicates and merges concurrent edits; we don't have to
  hand-roll that on the zion side.
- **Negative — new dep.** `aimp_node` is research-grade (the protocol
  hasn't yet hit semver-stable); we pin to a specific commit hash in
  Cargo.toml and treat the integration as experimental.
- **Negative — new attack surface.** UDP gossip listener exposes
  envelope-parse + signature-verify code to peers. The threat model
  addendum ([ADR-companion: docs/security/threat-model.md
  §10](../security/threat-model.md)) walks the STRIDE rows — Spoofing
  is countered by Ed25519, Tampering by AEAD on Noise transport, etc.
- **Negative — new operator surface.** Operators have to manage a
  peer list and an Ed25519 identity file per instance. Defaults
  (auto-generate identity on first boot, `chmod 600`, persist under
  `[sovereign_aimp].identity_path`) keep the floor low.
- **Neutral — versioned wire format.** Envelope versioning is
  AIMP-side. A future major bump would require fleet-wide rollout
  coordination; the documented protocol stability is sufficient for
  v0.2.x but tracked for v0.4 mesh hardening.

## Alternatives considered

- **etcd / Consul.** Both solve federated state correctly, but they
  require central infrastructure (a 3- or 5-node coordinator
  cluster). That breaks the "edge / autonomous" use case zion is
  designed for: an operator deploying one zion per region cannot
  also operate a coordinator quorum per region without doubling
  their on-call surface. Lost.
- **Custom gossip protocol (NIH).** We'd reinvent: signed envelopes,
  CRDT integrity, Sybil resistance, anti-entropy, peer enrollment.
  Each of those is a multi-week effort done *correctly*. AIMP
  already has them under test. Lost.
- **OpenTelemetry as the bus.** OTLP is built for telemetry export,
  not state replication: no quorum semantics, no convergence
  guarantees on partition heal, no cryptographic identity per
  emitter. Wrong tool. Lost.
- **Out-of-process AIMP node from day one (sidecar).** Possible —
  the protocol is wire-compatible — but trades one less in-process
  task for an extra network hop on every claim publish/receive. We
  start in-process to keep the latency budget tight; sidecar mode is
  reserved as a future enhancement when the blast-radius reasoning
  flips (e.g. running AIMP under a different uid for capability
  isolation).

## References

- Source: [`src/aimp_cp.rs`](../../src/aimp_cp.rs),
  [`src/aimp_xdp_sync.rs`](../../src/aimp_xdp_sync.rs)
- AIMP project: <https://github.com/fabriziosalmi/aimp>
- AIMP security model: <https://github.com/fabriziosalmi/aimp/blob/master/SECURITY.md>
- Operator-facing integration guide:
  [`docs/mesh/integration.md`](../mesh/integration.md)
- Threat-model addendum: [`docs/security/threat-model.md`](../security/threat-model.md) §10 (mesh)
- v0.2.2 wire-up commit: `2490fe8`
- v0.2.1 mesh-score signal: PR #65
