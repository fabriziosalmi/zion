# Mesh integration — operator guide

Architectural decision: [ADR-0008](../adr/0008-mesh-aimp-integration.md).
Threat-model addendum: [`docs/security/threat-model.md`](../security/threat-model.md) §10.
Source: [`src/aimp_cp.rs`](../../src/aimp_cp.rs).

This guide is for operators wiring zion's mesh layer into a fleet —
deployment topology, peer discovery, key management, and the
diagnostics surface that exists *today*. Anything tracked-but-not-shipped
is called out explicitly.

## What the mesh does

Each zion instance gossips signed claims to a configured peer set:

| Claim                       | Emitted by                                  | Consumed by                                      |
|-----------------------------|---------------------------------------------|--------------------------------------------------|
| `WafReputationDelta`        | every local WAF block                       | dispatcher pre-WAF lookup → `X-Zion-Mesh-Score`  |
| `RateSaturation` (*)        | rate-limit window crossing the threshold    | rate gate's neighbour-aware backoff (track #66)  |
| `UpstreamUnhealthy` (*)     | upstream prober marking a backend down      | health quorum gate (track #67)                   |
| `IdentityRevoked` (*)       | revocation-key holders                      | envelope verifier (rejects future claims from N) |

(*) Track and identifier reserved; the typed surface lands with the
v0.4 mesh slice. The bus already carries the envelope shape.

**Local decisions remain authoritative.** The mesh score is forwarded
to upstreams as a *signal* (`X-Zion-Mesh-Score: 0.NN`) so backends can
apply additional friction (CAPTCHA, longer rate windows). Zion's own
WAF / auth / rate-limit gates are unchanged by mesh state — the mesh
does NOT short-circuit those gates.

## Enabling the feature

Build flag (Cargo features):

```bash
cargo build --release --features sovereign-aimp
# implies sovereign-signals; see Cargo.toml feature graph
```

Runtime config (zion.toml):

```toml
[sovereign_aimp]
enabled        = true
listen         = "0.0.0.0:7777"            # UDP, gossip ingress
peers          = ["10.0.1.10:7777", "10.0.2.10:7777"]
identity_path  = "/var/lib/zion/aimp.identity"
anti_entropy_secs = 60                     # 0 to disable

# Inbound claim rate-cap (issue #71). Per-source-node token bucket on the
# merge path: a flooding peer (even a compromised one with a valid key) is
# capped, while every other source keeps flowing through its own bucket.
# 0 = disabled (default) — leaves the legitimate anti-entropy full-map
# re-broadcast unthrottled. Set only when you expect adversarial gossip.
inbound_claims_per_sec = 0                 # 0 = no cap
inbound_claim_burst    = 256               # headroom, used when cap > 0

# RESERVED / inert: the AIMP→XDP reconciler is not shipped — the in-kernel
# pre-filter track is frozen (issue #53). The key is kept so the TOML schema
# stays stable if that work is ever picked up; setting it has no effect today.
# (It would be the score above which a consensus block installs an LPM-trie drop.)
xdp_block_threshold = 0.95
```

`ZION_AIMP_*` env vars override the TOML for backwards compatibility
with v0.2.0 deployments — encouraged to migrate to TOML for diffability.

## Identity management

The first time zion boots with `[sovereign_aimp].enabled = true` AND
`identity_path` is empty/unreadable:

1. A fresh Ed25519 keypair is generated.
2. The 32-byte secret is written to `identity_path` with `chmod 600`.
3. The `node_id` (Ed25519 public key) is logged once, structured.

Subsequent boots load the secret from disk, so the `node_id` is
**stable across restarts** — peers don't have to re-classify the node
on every cycle. This was tracked as part of issue #68.

Backup: `identity_path`'s 32 bytes are the only secret material the
mesh uses for that node. Treat it like a TLS private key — daily
restic snapshot, restricted ACL, never log the secret.

Rotation (manual, until rotation-claim track lands):

```bash
# 1. Stop zion.
# 2. Move the old identity aside (pubkey peers can no longer
#    verify claims signed by it after this; they'll drop them).
mv /var/lib/zion/aimp.identity /var/lib/zion/aimp.identity.old
# 3. Restart zion — it'll generate a fresh identity.
# 4. Notify peers (out-of-band) of the new node_id.
```

Future: signed `IdentityRevoked` + `IdentityIntroduced` claims will
let peers transition without operator coordination. Tracked at
[#68](https://github.com/fabriziosalmi/zion/issues/68).

## Topology

The simplest viable mesh is **all-peers-with-everyone**: each node
lists every other in `peers`. Works to ~50 nodes; the gossip cost is
quadratic and the convergence time grows with the peer-set size.

Beyond ~50 nodes:

* **Hierarchical**: split fleet into regions; each region runs a
  full mesh internally; one or two cross-region peers per region act
  as gateways. Anti-entropy carries delta updates across regions on
  the configured period.
* **Hub-and-spoke**: dedicate one or two instances as gossip
  aggregators; spokes peer only with the hub. Higher availability
  risk (hub failure partitions the mesh) but simpler peer config.

The protocol does NOT prescribe a topology. Mesh resilience is a
function of how many distinct paths a claim can travel between any
two nodes — full mesh maximises that, hub-and-spoke minimises it.

## Anti-entropy

Set `anti_entropy_secs = 60` (the default) to have each node
re-broadcast its current reputation map to all peers every minute,
ensuring eventual convergence even if delta gossip is dropped (UDP
loss, partition heal). Tracked as part of issue #88.

* **0** disables anti-entropy. Delta gossip only — not recommended on
  lossy networks.
* **60** balances bandwidth (small per-round) against convergence
  delay (≤ 2× period to converge a fresh claim across the fleet).
* **30** halves convergence at 2× the bandwidth — sensible on
  high-latency links where round-trips dominate.

The bandwidth ceiling per round is small: one `SyncReq` envelope per
peer, response capped at the smaller of `claim_store.len()` and a
default 8K entries.

## Peer discovery

V1 ships **static peer lists** (the `[sovereign_aimp].peers` array).
mDNS / DNS-SD discovery is reserved as a future enhancement; the
existing static-list shape is fine for any cloud / data-centre
deployment with a known IP plan.

For Kubernetes deployments, populate `peers` from a DaemonSet
service template; the gossip listener is a `:7777/udp` `ClusterIP`
service. NetworkPolicies should allow inbound on the gossip port
**only** from peer IPs in the same DaemonSet — that's the trust
boundary.

## Observability

Three surfaces today; richer mesh-specific metrics + tracing are
tracked at [#69](https://github.com/fabriziosalmi/zion/issues/69):

* **Boot log**: `aimp_cp` info line emitted on successful bootstrap
  with the resolved `node_id` and peer count.
* **Per-block log**: when zion publishes a `WafReputationDelta`, an
  `aimp_cp` info line records the IP, score, and peer recipients.
* **Audit log**: (when `[audit].enabled = true`) every publish + receive
  is captured as an HMAC-chained audit event with `kind=mesh_publish`
  / `kind=mesh_receive`.

`/metrics` exposes:

* `zion_mesh_claims_emitted_total` — outbound claim count.
* `zion_mesh_claims_received_total` — inbound count.
* `zion_mesh_claims_dropped_total{reason=...}` — verification / admission
  failures bucketed by reason (`signature`, `replay`, `rate`, `other`).
* `zion_mesh_score_lookups_total` — reputation lookups on the request path.
* `zion_mesh_gossip_bytes_in_total` / `zion_mesh_gossip_bytes_out_total` —
  gossip wire volume.

## Debugging

Common diagnostic commands once the mesh is up:

```bash
# Verify the gossip listener is bound.
sudo ss -uap | grep ':7777'

# Inspect mesh counters (claims emitted/received/dropped, gossip bytes).
# There is no HTTP reputation-map dump endpoint; use /metrics + the audit log.
curl -s http://127.0.0.1:80/metrics | grep '^zion_mesh_'

# Observe live publish/receive events from the audit log.
tail -f /var/log/zion/audit.jsonl | jq 'select(.kind | startswith("mesh_"))'

# Verify a peer is reachable AND signing claims correctly: send a
# canary delta from node A and check the audit log on node B for a
# `mesh_receive` event with the matching trace_id.
```

If a node never converges with the rest of the fleet, walk the
checklist:

1. **Listener bound?** `ss -uap | grep ':7777'`. If not, check the
   bootstrap log for an `aimp_cp` warn / error line.
2. **Peers reachable?** `nc -uvz peer-ip 7777`. UDP is connectionless,
   so a successful `nc` only tells you the kernel didn't refuse —
   confirm via the peer's `mesh_receive` audit count.
3. **Identity consistent?** `cat /var/lib/zion/aimp.identity | xxd -l 32 |
   head -1` to inspect the secret prefix; the public-key `node_id`
   should match what `/metrics` reports.
4. **Anti-entropy on?** If `anti_entropy_secs = 0`, delta-only gossip
   relies on no UDP loss between nodes A and B. Set to 60 and
   convergence happens on the next round.
5. **Clock skew?** AIMP envelopes include a timestamp; large skews
   may cause replays to be rejected. NTP is required.

## Deferred / Tracked

Items listed in ADR-0008 "Negative consequences" or referenced above:

* **Sidecar-mode AIMP node** — protocol-compatible alternative to
  in-process. Not on the v0.2.x roadmap; revisited if blast-radius
  reasoning flips (e.g. uid-isolated AIMP under capability sandbox).
* **Identity rotation claims** — [#68](https://github.com/fabriziosalmi/zion/issues/68).
* **Mesh observability metrics** — [#69](https://github.com/fabriziosalmi/zion/issues/69).
* **Federated rate-limit / upstream-health quorum** — [#66](https://github.com/fabriziosalmi/zion/issues/66),
  [#67](https://github.com/fabriziosalmi/zion/issues/67).
* **Chaos coverage (split-brain, claim flood, slow gossip)** —
  [#71](https://github.com/fabriziosalmi/zion/issues/71).
* **Bench: --features sovereign-aimp idle vs saturation cost** —
  [#72](https://github.com/fabriziosalmi/zion/issues/72).
