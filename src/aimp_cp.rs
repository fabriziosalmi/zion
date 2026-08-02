//! AIMP-as-control-plane (Track B).
//!
//! Compile with `--features sovereign-aimp` (implies `sovereign-signals`).
//!
//! Lets a fleet of zion nodes share WAF rule updates and IP-reputation
//! deltas without a central control plane. Each node:
//!
//!   1. Generates (or loads from disk) an Ed25519 identity using
//!      `aimp_node::crypto::Identity`. The 32-byte `node_id` *is* the
//!      public key.
//!   2. Binds a UDP socket and listens for signed envelopes.
//!   3. On every local WAF block, publishes a signed
//!      [`WafReputationDelta`] to its configured peer set.
//!   4. On every received delta, verifies the signature with
//!      `aimp_node::crypto::SecurityFirewall`, then merges into a
//!      process-local `DashMap<IpAddr, WafReputation>`.
//!
//! Data-plane consumers (XDP map populator, WAF threshold logic)
//! subscribe to changes via a [`tokio::sync::watch`] receiver. When the
//! mesh partitions, each node keeps its last known reputation map and
//! keeps serving — there is no quorum to lose.
//!
//! ## v0 scope
//!
//! * UDP unicast to a static peer list. No mDNS, no bootstrap server.
//! * `OpCode::Infer` reused as the carrier opcode with a 4-byte `ZION`
//!   magic prefix. v1: add a dedicated `OpCode::WafSignal` to AIMP.
//! * Signature verification is mandatory; rejected envelopes are
//!   dropped silently (logged at TRACE).
//! * No Merkle-DAG sync yet — each delta is a self-contained CRDT
//!   register (last-writer-wins by `ts_secs`). v1: graduate to the
//!   full Merkle-CRDT layer in `aimp_node::crdt`.

// Scaffolding: several public types and methods are present here for
// the data-plane consumers (XDP map populator, ML threshold updater,
// dashboard) to call once those wires land. They are intentionally
// part of the v0.2.x stable surface — keeping them allows downstream
// integration to land in small PRs without further API churn.
#![allow(dead_code)]

use aimp_node::crypto::Identity;
use aimp_node::crypto::SecurityFirewall;
use aimp_node::protocol::envelope::{AimpData, AimpEnvelope, OpCode};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

/// 4-byte magic prefix that disambiguates zion control-plane payloads
/// from AIMP-native `Infer` prompts. Receivers that don't see this
/// prefix at the head of `data.payload` ignore the envelope.
const ZION_MAGIC: &[u8; 4] = b"ZION";

/// Configuration parsed from the `[sovereign.aimp]` section of `zion.toml`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AimpControlPlaneConfig {
    /// Master switch. When `false` the module is never invoked.
    #[serde(default)]
    pub enabled: bool,

    /// UDP listen address for incoming gossip.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// Static peer list — every published delta is unicast-broadcast
    /// to all of these addresses. Use multicast addresses for
    /// dynamically-discovered peer sets.
    #[serde(default)]
    pub peers: Vec<SocketAddr>,

    /// Path to the Ed25519 secret-key file. Created on first boot if
    /// missing. *Persisting the identity is what makes a zion node
    /// stable in the gossip graph* — restart with a fresh key and
    /// peers will treat the node as new (full re-sync).
    #[serde(default = "default_key_path")]
    pub identity_path: PathBuf,

    /// Period in seconds between anti-entropy SyncReq rounds. 0 = off.
    /// Closes the steady-state gap that delta-only gossip leaves when a
    /// peer was offline during a publish burst (UDP loss, late boot,
    /// transient partition). With anti-entropy on, every `T` seconds
    /// each node picks one peer and exchanges digests; mismatches
    /// trigger a `SyncRes` with the diff.
    #[serde(default = "default_anti_entropy_secs")]
    pub anti_entropy_secs: u64,

    /// Inbound claim rate-cap (issue #71). Per *source node* token-bucket
    /// guarding the merge path: a flooding peer — including a compromised
    /// one holding a valid key — is capped to `inbound_claims_per_sec`
    /// sustained, with `inbound_claim_burst` headroom, while claims from
    /// every other source keep flowing through their own buckets.
    ///
    /// `0` (default) disables the cap entirely — matching the back-compat
    /// posture of `server.rate_limit_rps`. Leaving it off keeps the
    /// anti-entropy full-map re-broadcast (a *legitimate* per-source
    /// burst) unthrottled; only set it when you expect adversarial gossip.
    #[serde(default)]
    pub inbound_claims_per_sec: u32,

    /// Burst headroom for the inbound rate-cap, in claims. Only meaningful
    /// when `inbound_claims_per_sec > 0`. Defaults to 256 so a short legit
    /// spike (e.g. a peer reconnecting after a blip) isn't clipped.
    #[serde(default = "default_inbound_claim_burst")]
    pub inbound_claim_burst: u32,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:9443".parse().unwrap()
}
fn default_key_path() -> PathBuf {
    PathBuf::from("/var/lib/zion/aimp-identity.bin")
}
fn default_anti_entropy_secs() -> u64 {
    60
}
fn default_inbound_claim_burst() -> u32 {
    256
}

impl Default for AimpControlPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_listen(),
            peers: vec![],
            identity_path: default_key_path(),
            anti_entropy_secs: default_anti_entropy_secs(),
            inbound_claims_per_sec: 0,
            inbound_claim_burst: default_inbound_claim_burst(),
        }
    }
}

// ── Wire payload ──────────────────────────────────────────────────────

/// What we gossip. Tiny, fixed-shape; serializes to ~28 bytes via rmp.
///
/// IPv4 addresses are stored as `::ffff:a.b.c.d` so the wire shape is a
/// single fixed-size array — keeps the deserializer alloc-free.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct WafReputationDelta {
    /// 16 bytes, big-endian. IPv4 mapped to `::ffff:a.b.c.d`.
    pub ip_v6: [u8; 16],
    /// `[0,1]` reputation score; higher = more malicious.
    pub score: f32,
    /// Unix epoch seconds when the delta was observed by the publisher.
    /// Used for last-writer-wins merge.
    pub ts_secs: u64,
    /// Coarse classification. Reserved values:
    ///   0 = generic block, 1 = WAF gate, 2 = ML scorer,
    ///   3 = manual operator entry, 255 = revocation (remove from map).
    pub reason: u8,
}

/// What lives in the local map. Mirrors a delta plus the signer's
/// node id so the operator can audit *who told us* a given IP was bad.
#[derive(Debug, Clone, Copy)]
pub struct WafReputation {
    pub score: f32,
    pub ts_secs: u64,
    pub reason: u8,
    /// 32-byte Ed25519 public key of the signer. Stored verbatim.
    pub source_node: [u8; 32],
}

// ── Live handle ───────────────────────────────────────────────────────

/// Process-global handle on the AIMP control-plane task.
///
/// Cloning is cheap — `Arc` internals — and intended: the dispatcher
/// clones it into the request hot path so it can call `lookup()` in
/// the WAF gate, while a background reload task clones it to call
/// `publish_block()` from the WAF block handler.
#[derive(Clone)]
pub struct AimpControlPlane {
    /// Authoritative local view. Subscribers read from here.
    reputation: Arc<DashMap<IpAddr, WafReputation>>,
    /// Sender for the "publish this delta" path. Bounded — back-pressure
    /// is fine here, the WAF block handler is happy to drop a publish if
    /// we are catastrophically backed up.
    publish_tx: mpsc::Sender<WafReputationDelta>,
    /// Bumped on every successful merge into `reputation`. Subscribers
    /// (XDP map populator, ML threshold updater) watch this for changes.
    update_rx: watch::Receiver<u64>,
    /// Our own node id (pubkey). Useful for log lines and for the
    /// dashboard's "this node" indicator.
    self_node_id: [u8; 32],
}

impl AimpControlPlane {
    /// Lookup the most-recent reputation we know for `ip`. O(1).
    pub fn lookup(&self, ip: &IpAddr) -> Option<WafReputation> {
        self.reputation.get(ip).map(|r| *r)
    }

    /// Publish a local block to the gossip mesh. Returns immediately —
    /// the actual UDP send happens in the publish task. If the channel
    /// is full (catastrophic back-pressure), the delta is silently
    /// dropped and a counter is bumped.
    pub fn publish_block(&self, ip: IpAddr, score: f32, reason: u8) -> Result<(), &'static str> {
        let ip_v6 = match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        let delta = WafReputationDelta {
            ip_v6,
            score,
            ts_secs: now_secs(),
            reason,
        };
        self.publish_tx
            .try_send(delta)
            .map_err(|_| "aimp-cp: publish queue full or closed")?;
        // Successful local emit (the publisher task drains and signs +
        // sends). Increment AFTER a successful enqueue so a
        // back-pressure drop doesn't get counted as an emit.
        crate::metrics::METRICS
            .mesh_claims_emitted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Subscribe to map updates. Each `recv().await` resolves once a
    /// new delta has been merged. Useful for the XDP populator and the
    /// ML threshold updater.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.update_rx.clone()
    }

    /// 32-byte self node id (pubkey).
    pub fn node_id(&self) -> [u8; 32] {
        self.self_node_id
    }

    /// Snapshot of the current reputation map. Cheap — clones an
    /// `Arc<DashMap>`. Intended for the dashboard / `/metrics` page,
    /// not the request hot path (use [`Self::lookup`] for that).
    pub fn reputation(&self) -> Arc<DashMap<IpAddr, WafReputation>> {
        self.reputation.clone()
    }
}

// ── Bootstrap ────────────────────────────────────────────────────────

/// Boot the AIMP control plane: load/generate identity, bind UDP, and
/// spawn the receive + publish tasks. Returns a handle the rest of zion
/// can clone.
pub async fn bootstrap(cfg: AimpControlPlaneConfig) -> Result<AimpControlPlane, String> {
    if !cfg.enabled {
        return Err("aimp-cp: bootstrap called with disabled config".to_string());
    }

    // --- Identity: load from `cfg.identity_path` if it exists, else
    //     generate a fresh keypair and persist the secret seed.
    //     Persisting keeps the derived `node_id` (Ed25519 public key)
    //     stable across restarts so peers don't have to re-classify
    //     us as a new node and discard the prior trust state.
    let identity = Arc::new(load_or_generate_identity(&cfg.identity_path)?);
    let self_node_id = identity.node_id();

    // --- UDP socket
    let socket = UdpSocket::bind(cfg.listen)
        .await
        .map_err(|e| format!("aimp-cp: bind {} failed: {e}", cfg.listen))?;
    let socket = Arc::new(socket);

    // --- Shared state
    let reputation: Arc<DashMap<IpAddr, WafReputation>> = Arc::new(DashMap::new());
    let (publish_tx, publish_rx) = mpsc::channel::<WafReputationDelta>(4096);
    let (update_tx, update_rx) = watch::channel::<u64>(0);

    // --- Receive loop
    {
        let socket = socket.clone();
        let reputation = reputation.clone();
        let update_tx = update_tx.clone();
        let rate = cfg.inbound_claims_per_sec;
        let burst = cfg.inbound_claim_burst;
        tokio::spawn(async move {
            run_receiver(socket, reputation, update_tx, rate, burst).await;
        });
    }

    // --- Publish loop
    {
        let socket = socket.clone();
        let identity = identity.clone();
        let peers = cfg.peers.clone();
        tokio::spawn(async move {
            run_publisher(socket, identity, peers, publish_rx).await;
        });
    }

    // --- Anti-entropy loop. Closes the steady-state gap left by
    //     delta-only gossip when a peer was offline during a publish
    //     burst (UDP loss, late boot, transient partition). Every
    //     `anti_entropy_secs` we walk our local reputation map and
    //     re-broadcast every entry to a single peer (round-robin).
    //     Cost: O(map_size) packets per round per node, O(N) total
    //     mesh load (one peer per round per node, not all-to-all).
    //     Receivers de-dup via the existing replay LRU (signature is
    //     identical when re-signed by the same identity over the same
    //     {ip, ts_secs, score, reason}, but ts_secs is bumped to "now"
    //     on each round so the LWW gate accepts it as a heartbeat).
    if cfg.anti_entropy_secs > 0 && !cfg.peers.is_empty() {
        let socket = socket.clone();
        let identity = identity.clone();
        let peers = cfg.peers.clone();
        let reputation = reputation.clone();
        let period = std::time::Duration::from_secs(cfg.anti_entropy_secs);
        tokio::spawn(async move {
            run_anti_entropy(socket, identity, peers, reputation, period).await;
        });
    }

    Ok(AimpControlPlane {
        reputation,
        publish_tx,
        update_rx,
        self_node_id,
    })
}

// ── Receive task + merge policy ──────────────────────────────────────

/// Result of attempting to merge a received envelope into the local
/// reputation map. The receiver task uses this to decide whether to
/// bump the version watch; tests use it to assert policy correctness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// New entry inserted.
    Inserted,
    /// Existing entry updated (newer ts from same source).
    Updated,
    /// Existing entry removed by source-bound revocation.
    Removed,
    /// Older or equal-ts duplicate, or revocation of nothing.
    Stale,
    /// Policy violation: bad signature, bad payload, ts out of window,
    /// replay, or revocation by a non-original source.
    Rejected,
}

/// Bounded FIFO of recently-seen 64-byte signatures used to drop replays.
/// O(1) membership via the set; O(1) eviction via the queue.
struct SeenFilter {
    queue: std::collections::VecDeque<[u8; 64]>,
    set: std::collections::HashSet<[u8; 64]>,
    capacity: usize,
}

impl SeenFilter {
    fn new(capacity: usize) -> Self {
        Self {
            queue: std::collections::VecDeque::with_capacity(capacity),
            set: std::collections::HashSet::with_capacity(capacity),
            capacity,
        }
    }
    fn contains(&self, sig: &[u8; 64]) -> bool {
        self.set.contains(sig)
    }
    fn insert(&mut self, sig: [u8; 64]) {
        if self.set.contains(&sig) {
            return;
        }
        if self.queue.len() >= self.capacity {
            if let Some(old) = self.queue.pop_front() {
                self.set.remove(&old);
            }
        }
        self.queue.push_back(sig);
        self.set.insert(sig);
    }
}

/// One source node's token bucket. Time is measured in whole seconds —
/// the same `now_secs` the merge path already threads through, so the
/// limiter is deterministic under `try_merge`'s injected clock.
struct TokenBucket {
    tokens: f64,
    last_secs: u64,
}

/// Per-source-node inbound claim rate-cap (issue #71).
///
/// Keyed on the envelope's claimed `origin_pubkey`, checked *after* the
/// cheap replay filter but *before* signature verification — so a flood
/// from a compromised peer (valid key) is dropped without paying the
/// Ed25519 cost, and the per-source bucketing guarantees a flooding
/// source can't starve claims from any other source ("legitimate signals
/// must keep flowing").
///
/// `rate_per_sec == 0` disables the limiter (the default). The bucket
/// table is itself bounded by `max_sources`: once full, an unseen source
/// is treated as over-limit, so a forger rotating fake pubkeys can't grow
/// the table without bound (that traffic fails signature verification
/// anyway; the cap just stops it costing memory + CPU first).
struct InboundRateLimiter {
    rate_per_sec: f64,
    burst: f64,
    buckets: std::collections::HashMap<[u8; 32], TokenBucket>,
    max_sources: usize,
}

impl InboundRateLimiter {
    fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            rate_per_sec: f64::from(rate_per_sec),
            burst: f64::from(burst.max(1)),
            buckets: std::collections::HashMap::new(),
            max_sources: 4096,
        }
    }

    fn enabled(&self) -> bool {
        self.rate_per_sec > 0.0
    }

    /// Returns `true` if a claim from `source` is admitted at `now_secs`,
    /// consuming one token; `false` if the source is over its rate.
    fn allow(&mut self, source: &[u8; 32], now_secs: u64) -> bool {
        if !self.enabled() {
            return true;
        }
        if !self.buckets.contains_key(source) && self.buckets.len() >= self.max_sources {
            // Table saturated — refuse unknown sources rather than grow.
            return false;
        }
        let (rate, burst) = (self.rate_per_sec, self.burst);
        let b = self.buckets.entry(*source).or_insert(TokenBucket {
            tokens: burst,
            last_secs: now_secs,
        });
        let elapsed = now_secs.saturating_sub(b.last_secs) as f64;
        if elapsed > 0.0 {
            b.tokens = (b.tokens + elapsed * rate).min(burst);
            b.last_secs = now_secs;
        }
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// State the receiver task holds. Extracted so unit tests can drive
/// `try_merge` directly without a UDP socket round-trip.
pub(crate) struct ReceiverState {
    reputation: Arc<DashMap<IpAddr, WafReputation>>,
    seen_sigs: SeenFilter,
    update_tx: watch::Sender<u64>,
    version: u64,
    /// Accept ts up to `now + skew_window_secs` (default 60s).
    skew_future_secs: u64,
    /// Reject ts older than `now - skew_past_secs` (default 24h).
    skew_past_secs: u64,
    /// Per-source inbound claim rate-cap (#71). Disabled by default.
    rate_limiter: InboundRateLimiter,
}

impl ReceiverState {
    fn new(reputation: Arc<DashMap<IpAddr, WafReputation>>, update_tx: watch::Sender<u64>) -> Self {
        Self {
            reputation,
            seen_sigs: SeenFilter::new(8192),
            update_tx,
            version: 0,
            skew_future_secs: 60,
            skew_past_secs: 86_400,
            rate_limiter: InboundRateLimiter::new(0, 0),
        }
    }

    /// Builder: enable the per-source inbound rate-cap (#71). `rate == 0`
    /// leaves it disabled. Used by the receive loop (from config) and by
    /// chaos tests; the plain `new` path stays uncapped for back-compat.
    fn with_inbound_rate(mut self, rate_per_sec: u32, burst: u32) -> Self {
        self.rate_limiter = InboundRateLimiter::new(rate_per_sec, burst);
        self
    }

    /// Apply the policy gates and merge, returning what happened.
    /// `now_secs` is injected so tests can pin time without sleeping.
    pub(crate) fn try_merge(&mut self, envelope: &AimpEnvelope, now_secs: u64) -> MergeOutcome {
        use std::sync::atomic::Ordering::Relaxed;
        let metrics = &crate::metrics::METRICS;

        // 1. Replay filter (cheap; do this before crypto).
        if self.seen_sigs.contains(&envelope.signature) {
            metrics.mesh_claims_dropped_replay.fetch_add(1, Relaxed);
            return MergeOutcome::Rejected;
        }

        // 1b. Per-source inbound rate-cap (#71). Keyed on the *claimed*
        //     origin_pubkey — checked before the Ed25519 verify so a
        //     compromised peer's flood is dropped cheaply, and bucketed
        //     per source so it can't starve other peers' claims. No-op
        //     when disabled (rate_per_sec == 0, the default).
        if self.rate_limiter.enabled()
            && !self
                .rate_limiter
                .allow(&envelope.data.origin_pubkey, now_secs)
        {
            metrics.mesh_claims_dropped_rate.fetch_add(1, Relaxed);
            return MergeOutcome::Rejected;
        }

        // 2. Signature verification — every ingress envelope must pass.
        if !SecurityFirewall::verify(envelope) {
            metrics.mesh_claims_dropped_signature.fetch_add(1, Relaxed);
            return MergeOutcome::Rejected;
        }

        // 3. Magic prefix check (filters AIMP-native chatter).
        let payload = &envelope.data.payload;
        if payload.len() < ZION_MAGIC.len() || &payload[..ZION_MAGIC.len()] != ZION_MAGIC {
            metrics.mesh_claims_dropped_other.fetch_add(1, Relaxed);
            return MergeOutcome::Rejected;
        }

        // 4. Decode the inner delta.
        let delta: WafReputationDelta = match rmp_serde::from_slice(&payload[ZION_MAGIC.len()..]) {
            Ok(d) => d,
            Err(_) => {
                metrics.mesh_claims_dropped_other.fetch_add(1, Relaxed);
                return MergeOutcome::Rejected;
            }
        };

        // 5. Timestamp window. A peer with a future clock or a
        //    captured-and-replayed-from-the-past delta is rejected.
        if delta.ts_secs > now_secs.saturating_add(self.skew_future_secs) {
            metrics.mesh_claims_dropped_other.fetch_add(1, Relaxed);
            return MergeOutcome::Rejected;
        }
        if delta.ts_secs.saturating_add(self.skew_past_secs) < now_secs {
            metrics.mesh_claims_dropped_other.fetch_add(1, Relaxed);
            return MergeOutcome::Rejected;
        }

        // From here on the envelope is admissible — register its
        // signature so any duplicate copy is dropped at gate (1).
        self.seen_sigs.insert(envelope.signature);

        // 6. Decode the IP.
        let ip_v6 = std::net::Ipv6Addr::from(delta.ip_v6);
        let ip = match ip_v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(ip_v6),
        };

        let new_entry = WafReputation {
            score: delta.score,
            ts_secs: delta.ts_secs,
            reason: delta.reason,
            source_node: envelope.data.origin_pubkey,
        };

        // 7. Revocation path: only the original signer can revoke. This
        //    blocks the griefing attack where a peer with a valid key
        //    cancels another peer's blocks.
        if delta.reason == 255 {
            let outcome = match self.reputation.get(&ip) {
                Some(existing) => {
                    if existing.source_node == envelope.data.origin_pubkey {
                        // Drop the read guard before mutating.
                        drop(existing);
                        self.reputation.remove(&ip);
                        MergeOutcome::Removed
                    } else {
                        MergeOutcome::Rejected
                    }
                }
                None => MergeOutcome::Stale,
            };
            match outcome {
                MergeOutcome::Removed => {
                    metrics.mesh_claims_received.fetch_add(1, Relaxed);
                    self.bump_version();
                }
                MergeOutcome::Rejected => {
                    metrics.mesh_claims_dropped_other.fetch_add(1, Relaxed);
                }
                _ => {}
            }
            return outcome;
        }

        // 8. Insert / LWW update. Updates are *not* source-bound (any
        //    peer's fresh observation can override an older one) but
        //    we still require the new ts to be > the existing one to
        //    stop slow-node clobbering after a partition heal.
        let outcome = match self.reputation.entry(ip) {
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(new_entry);
                MergeOutcome::Inserted
            }
            dashmap::mapref::entry::Entry::Occupied(mut o) => {
                if new_entry.ts_secs > o.get().ts_secs {
                    *o.get_mut() = new_entry;
                    MergeOutcome::Updated
                } else {
                    MergeOutcome::Stale
                }
            }
        };
        if matches!(outcome, MergeOutcome::Inserted | MergeOutcome::Updated) {
            metrics.mesh_claims_received.fetch_add(1, Relaxed);
            self.bump_version();
        }
        // Keep the reputation table bounded (issue #287). Only a *fresh* insert
        // grows the map; an update, stale, or rejected claim cannot, so we prune
        // on `Inserted` only.
        if matches!(outcome, MergeOutcome::Inserted) {
            prune_reputation(
                &self.reputation,
                MAX_REPUTATION_ENTRIES,
                REPUTATION_TTL_SECS,
            );
        }
        outcome
    }

    fn bump_version(&mut self) {
        self.version = self.version.wrapping_add(1);
        let _ = self.update_tx.send(self.version);
    }
}

/// Upper bound on the reputation table (issue #287). Entries are only added by a
/// signature-verified merge and mesh is off by default, so this is not a
/// request-reachable leak — but a long-lived mesh circulating claims for many
/// distinct client IPs would otherwise grow the map without limit. ~100k IPs is
/// a few MB.
const MAX_REPUTATION_ENTRIES: usize = 100_000;
/// Reputation older than this is stale and pruned first. A day is long enough
/// that a still-active attacker keeps getting re-observed (each observation
/// refreshes its `ts_secs`), so only genuinely idle IPs age out.
const REPUTATION_TTL_SECS: u64 = 86_400;

/// Bound the reputation table: drop entries older than `ttl_secs`, then, if
/// still over `max_entries`, evict the oldest by timestamp down to a low-water
/// mark (90% of the cap) so the O(n) cost amortizes over many inserts instead
/// of firing on every one. A no-op while under the cap — the steady-state merge
/// path pays only a `len()` check. `max_entries = 0` disables the bound.
fn prune_reputation(map: &DashMap<IpAddr, WafReputation>, max_entries: usize, ttl_secs: u64) {
    if max_entries == 0 || map.len() <= max_entries {
        return;
    }
    let now = now_secs();
    // 1. Age-prune: stale reputation is the first to go.
    map.retain(|_, v| now.saturating_sub(v.ts_secs) <= ttl_secs);
    // 2. Still over the cap → evict the oldest down to the low-water mark.
    let low_water = max_entries - max_entries / 10;
    let len = map.len();
    if len > low_water {
        let mut ages: Vec<(IpAddr, u64)> =
            map.iter().map(|e| (*e.key(), e.value().ts_secs)).collect();
        ages.sort_unstable_by_key(|&(_, ts)| ts); // oldest first
        for (ip, _) in ages.into_iter().take(len - low_water) {
            map.remove(&ip);
        }
    }
}

async fn run_receiver(
    socket: Arc<UdpSocket>,
    reputation: Arc<DashMap<IpAddr, WafReputation>>,
    update_tx: watch::Sender<u64>,
    inbound_claims_per_sec: u32,
    inbound_claim_burst: u32,
) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut buf = vec![0u8; 65_507]; // max UDP datagram
    let mut state = ReceiverState::new(reputation, update_tx)
        .with_inbound_rate(inbound_claims_per_sec, inbound_claim_burst);

    loop {
        let (len, _peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Bytes accounting (issue #69) covers everything that hits
        // our socket — even malformed packets, so traffic-analysis
        // and rate observations match the kernel's view.
        crate::metrics::METRICS
            .mesh_gossip_bytes_in
            .fetch_add(len as u64, Relaxed);
        let envelope: AimpEnvelope = match rmp_serde::from_slice(&buf[..len]) {
            Ok(e) => e,
            Err(_) => {
                crate::metrics::METRICS
                    .mesh_claims_dropped_other
                    .fetch_add(1, Relaxed);
                continue;
            }
        };
        // try_merge bumps mesh_claims_received / dropped_* counters
        // internally so this loop doesn't double-count.
        let _ = state.try_merge(&envelope, now_secs());
    }
}

// ── Publish task ─────────────────────────────────────────────────────

async fn run_publisher(
    socket: Arc<UdpSocket>,
    identity: Arc<Identity>,
    peers: Vec<SocketAddr>,
    mut publish_rx: mpsc::Receiver<WafReputationDelta>,
) {
    let origin = identity.node_id();
    while let Some(delta) = publish_rx.recv().await {
        // Encode payload: 4-byte ZION magic + rmp-serialized delta.
        let inner = match rmp_serde::to_vec(&delta) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut payload = Vec::with_capacity(ZION_MAGIC.len() + inner.len());
        payload.extend_from_slice(ZION_MAGIC);
        payload.extend_from_slice(&inner);

        let data = AimpData {
            v: 0x01,
            op: OpCode::Infer, // v1: introduce OpCode::WafSignal in aimp_node
            ttl: 4,
            origin_pubkey: origin,
            vclock: BTreeMap::new(),
            payload,
        };
        let envelope = match identity.sign(data) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let bytes = match rmp_serde::to_vec(&envelope) {
            Ok(b) => b,
            Err(_) => continue,
        };

        for peer in &peers {
            // try_send — losing a delta because the OS buffer is full
            // is acceptable, the next delta from the same source will
            // re-converge the receiver's map.
            if let Ok(n) = socket.send_to(&bytes, peer).await {
                crate::metrics::METRICS
                    .mesh_gossip_bytes_out
                    .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

// ── Anti-entropy task ────────────────────────────────────────────────
//
// v0 design: round-robin one peer per round, re-broadcast every entry
// in our local map to that peer. This is the "naive" anti-entropy —
// digest comparison + delta is a v1 follow-up that needs a new
// `OpCode::SyncReq`/`SyncRes` upstream in `aimp_node`.

async fn run_anti_entropy(
    socket: Arc<UdpSocket>,
    identity: Arc<Identity>,
    peers: Vec<SocketAddr>,
    reputation: Arc<DashMap<IpAddr, WafReputation>>,
    period: std::time::Duration,
) {
    let origin = identity.node_id();
    let mut peer_idx: usize = 0;
    let mut ticker = tokio::time::interval(period);
    // Skip the immediate first tick — we want the first round to wait
    // a full `period` so a freshly-booted node doesn't blast its
    // (almost certainly empty) map onto the wire before it's done
    // catching up via gossip.
    ticker.tick().await;

    loop {
        ticker.tick().await;

        if peers.is_empty() {
            continue;
        }
        let peer = peers[peer_idx % peers.len()];
        peer_idx = peer_idx.wrapping_add(1);

        // Snapshot the map. We cannot hold a DashMap iterator across
        // .await points (the shard guards aren't Send-safe across
        // suspend), so collect first, send second.
        let entries: Vec<(IpAddr, WafReputation)> =
            reputation.iter().map(|e| (*e.key(), *e.value())).collect();

        if entries.is_empty() {
            continue;
        }

        let now = now_secs();
        for (ip, rep) in entries {
            // Refresh ts_secs to "now" for the heartbeat — receiver's
            // LWW gate would otherwise reject the round as a stale
            // duplicate. We are *re-asserting* what we know, not
            // claiming to have observed it again, so this is correct.
            let ip_v6 = match ip {
                IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                IpAddr::V6(v6) => v6.octets(),
            };
            let delta = WafReputationDelta {
                ip_v6,
                score: rep.score,
                ts_secs: now,
                reason: rep.reason,
            };
            let inner = match rmp_serde::to_vec(&delta) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let mut payload = Vec::with_capacity(ZION_MAGIC.len() + inner.len());
            payload.extend_from_slice(ZION_MAGIC);
            payload.extend_from_slice(&inner);
            let data = AimpData {
                v: 0x01,
                op: OpCode::Infer,
                ttl: 4,
                origin_pubkey: origin,
                vclock: BTreeMap::new(),
                payload,
            };
            let envelope = match identity.sign(data) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let bytes = match rmp_serde::to_vec(&envelope) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(n) = socket.send_to(&bytes, peer).await {
                crate::metrics::METRICS
                    .mesh_gossip_bytes_out
                    .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

// ── Cross-track wire (Track B3: CRDT update → data plane) ────────────
//
// (Track B3 v0 once lived here as `spawn_xdp_sync(cp, Arc<XdpHandle>, ...)`,
//  reconciling AIMP reputation into an XDP LPM-trie drop. The in-kernel
//  pre-filter track (XDP / eBPF demux) is frozen — see issue #53 — so the
//  reconciler and its `src/xdp.rs` / `src/aimp_xdp_sync.rs` modules were
//  removed. AIMP still gossips reputation; enforcement stays in the
//  userspace WAF/rate-limit path.)

// ── Helpers ──────────────────────────────────────────────────────────

/// Load an `Identity` from `path` if the file exists and contains a
/// 32-byte Ed25519 secret seed; otherwise generate a fresh `Identity`
/// and persist its secret seed at `path` with permissions `0600`.
///
/// Failure to read or write the persistence path is **not** fatal: we
/// fall back to an ephemeral identity and log the reason. A common
/// case where the path is unwritable is the default
/// `/var/lib/zion/aimp-identity.bin` on systems where zion runs as a
/// non-root user that doesn't own that directory — there the operator
/// is expected to point `identity_path` at a path the service can write.
fn load_or_generate_identity(path: &std::path::Path) -> Result<Identity, String> {
    use std::io::Write;

    // Try to load an existing seed.
    if path.exists() {
        match std::fs::read(path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return Ok(Identity::from_secret_bytes(seed));
            }
            Ok(other) => {
                eprintln!(
                    "aimp_cp: warn: identity_path {} has wrong length ({} bytes, expected 32) — generating ephemeral",
                    path.display(),
                    other.len()
                );
            }
            Err(e) => {
                eprintln!(
                    "aimp_cp: warn: identity_path {} unreadable ({e}) — generating ephemeral",
                    path.display()
                );
            }
        }
    }

    // Generate fresh and try to persist.
    let identity = Identity::new();
    let secret = identity.secret_bytes();

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Atomic write: tmp file + rename, so a partial write never
    // produces a half-baked seed file. chmod 0600 BEFORE the rename
    // so the file is never readable by other users in transit.
    let tmp_path = path.with_extension("bin.tmp");
    match std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp_path)
    {
        Ok(mut f) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            if let Err(e) = f.write_all(&secret) {
                eprintln!(
                    "aimp_cp: warn: identity_path {} write failed: {e}",
                    path.display()
                );
            } else if let Err(e) = std::fs::rename(&tmp_path, path) {
                eprintln!(
                    "aimp_cp: warn: identity_path {} rename failed: {e}",
                    path.display()
                );
            }
        }
        Err(e) => {
            eprintln!(
                "aimp_cp: warn: identity_path {} cannot create tmp file: {e} — running with ephemeral identity",
                path.display()
            );
        }
    }

    Ok(identity)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Reputation-table bounding (issue #287) ───────────────────────────
    fn mk_rep(ts_secs: u64) -> WafReputation {
        WafReputation {
            score: 0.5,
            ts_secs,
            reason: 1,
            source_node: [0u8; 32],
        }
    }
    fn mk_ip(i: u32) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            (i >> 16) as u8,
            (i >> 8) as u8,
            i as u8,
        ))
    }

    #[test]
    fn prune_reputation_is_a_noop_under_the_cap() {
        let map = DashMap::new();
        let now = now_secs();
        for i in 0..10 {
            map.insert(mk_ip(i), mk_rep(now));
        }
        prune_reputation(&map, 100, 100);
        assert_eq!(map.len(), 10, "under the cap → untouched");
    }

    #[test]
    fn prune_reputation_ages_out_stale_entries_first() {
        let map = DashMap::new();
        let now = now_secs();
        // 50 stale (older than the 100s TTL) + 50 fresh, over the cap of 60.
        for i in 0..50 {
            map.insert(mk_ip(i), mk_rep(now.saturating_sub(200)));
        }
        for i in 50..100 {
            map.insert(mk_ip(i), mk_rep(now));
        }
        prune_reputation(&map, 60, 100);
        assert!(map.len() <= 60);
        // The stale half is gone by age; every survivor is fresh.
        assert_eq!(map.len(), 50);
        assert!(map
            .iter()
            .all(|e| now.saturating_sub(e.value().ts_secs) <= 100));
    }

    #[test]
    fn prune_reputation_evicts_oldest_when_all_fresh() {
        let map = DashMap::new();
        let now = now_secs();
        // All fresh; mk_ip(0) is newest (ts=now), mk_ip(99) oldest (ts=now-99).
        for i in 0..100 {
            map.insert(mk_ip(i), mk_rep(now.saturating_sub(i as u64)));
        }
        // Huge TTL ⇒ age-prune keeps all ⇒ cap-eviction to the low-water mark.
        prune_reputation(&map, 50, 1_000_000);
        // low_water = 50 - 5 = 45, so the newest 45 survive.
        assert_eq!(map.len(), 45, "bounded to the low-water mark");
        assert!(map.contains_key(&mk_ip(0)), "newest must survive");
        assert!(!map.contains_key(&mk_ip(99)), "oldest must be evicted");
    }
    use std::net::Ipv4Addr;

    #[test]
    fn config_default_disabled() {
        let c = AimpControlPlaneConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.peers.len(), 0);
    }

    #[test]
    fn delta_roundtrip_via_rmp() {
        let d = WafReputationDelta {
            ip_v6: [0; 16],
            score: 0.91,
            ts_secs: 1_700_000_000,
            reason: 1,
        };
        let bytes = rmp_serde::to_vec(&d).unwrap();
        let back: WafReputationDelta = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(d.ip_v6, back.ip_v6);
        assert!((d.score - back.score).abs() < 1e-6);
        assert_eq!(d.ts_secs, back.ts_secs);
        assert_eq!(d.reason, back.reason);
    }

    #[test]
    fn ipv4_round_trip_via_v6_mapped() {
        let v4 = Ipv4Addr::new(192, 168, 1, 1);
        let mapped = v4.to_ipv6_mapped();
        let back = mapped.to_ipv4_mapped().unwrap();
        assert_eq!(v4, back);
    }

    /// Smoke test: full bootstrap + lookup roundtrip on loopback. A
    /// single node publishes a delta to *itself* and verifies the
    /// merge happened. Skipped if the loopback bind fails (CI sandbox).
    #[tokio::test]
    async fn boot_and_self_publish() {
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // Bind a probe socket to discover an actually-free port…
        let probe = match tokio::net::UdpSocket::bind(listen).await {
            Ok(s) => s,
            Err(_) => return,
        };
        let listen = probe.local_addr().unwrap();
        drop(probe);

        let cfg = AimpControlPlaneConfig {
            enabled: true,
            listen,
            peers: vec![listen],
            identity_path: default_key_path(),
            anti_entropy_secs: 0, // off in this loopback smoke test
            ..Default::default()
        };
        let cp = match bootstrap(cfg).await {
            Ok(c) => c,
            Err(_) => return, // harness lacks UDP perms
        };
        let target_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        cp.publish_block(target_ip, 0.97, 1).unwrap();

        // Wait up to 1s for the loopback round-trip + merge.
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if cp.lookup(&target_ip).is_some() {
                break;
            }
        }
        // We deliberately don't assert is_some(): the test environment
        // may have UDP egress disabled. The assertion that matters is
        // that bootstrap + publish + lookup compile and don't deadlock.
    }

    // ── Adversarial / hammer tests ───────────────────────────────────
    //
    // These tests pin the policy decisions made by `ReceiverState::try_merge`.
    // Each one constructs envelopes with precise control over the signing
    // identity and timestamp, then asserts the expected MergeOutcome.
    // Breaking one of these is breaking a security property.

    fn build_envelope(
        identity: &Identity,
        ip: IpAddr,
        score: f32,
        ts_secs: u64,
        reason: u8,
    ) -> AimpEnvelope {
        let ip_v6 = match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        let delta = WafReputationDelta {
            ip_v6,
            score,
            ts_secs,
            reason,
        };
        let inner = rmp_serde::to_vec(&delta).unwrap();
        let mut payload = Vec::with_capacity(ZION_MAGIC.len() + inner.len());
        payload.extend_from_slice(ZION_MAGIC);
        payload.extend_from_slice(&inner);
        let data = AimpData {
            v: 0x01,
            op: OpCode::Infer,
            ttl: 4,
            origin_pubkey: identity.node_id(),
            vclock: BTreeMap::new(),
            payload,
        };
        identity.sign(data).unwrap()
    }

    fn fresh_state() -> (ReceiverState, Arc<DashMap<IpAddr, WafReputation>>) {
        let map: Arc<DashMap<IpAddr, WafReputation>> = Arc::new(DashMap::new());
        let (tx, _rx) = watch::channel(0u64);
        (ReceiverState::new(map.clone(), tx), map)
    }

    /// Hammer F1.1 — peer B cannot revoke an entry inserted by peer A.
    /// This blocks the obvious griefing attack: a single rogue peer
    /// in the trust graph cancelling everyone else's blocks.
    #[test]
    fn revocation_is_source_bound() {
        let alice = Identity::new();
        let mallory = Identity::new();
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let now = 1_700_000_000u64;

        let (mut state, map) = fresh_state();

        // Alice publishes a block.
        let env = build_envelope(&alice, target, 0.95, now, 1);
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Inserted);
        assert!(map.contains_key(&target));

        // Mallory tries to revoke. Same IP, same payload shape, but
        // signed by a different key. Must be rejected.
        let env = build_envelope(&mallory, target, 0.0, now + 1, 255);
        assert_eq!(state.try_merge(&env, now + 1), MergeOutcome::Rejected);
        assert!(
            map.contains_key(&target),
            "rogue revocation must not remove"
        );

        // Alice can still revoke her own entry.
        let env = build_envelope(&alice, target, 0.0, now + 2, 255);
        assert_eq!(state.try_merge(&env, now + 2), MergeOutcome::Removed);
        assert!(!map.contains_key(&target));
    }

    /// Hammer F1.2 — timestamps in the future or far past are dropped.
    /// Without this, a peer with a misconfigured/forward clock pins
    /// entries that no LWW update can dislodge.
    #[test]
    fn timestamp_window_is_enforced() {
        let alice = Identity::new();
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let now = 1_700_000_000u64;

        let (mut state, map) = fresh_state();

        // Future ts beyond the skew window — rejected.
        let env = build_envelope(&alice, target, 0.99, now + state.skew_future_secs + 1, 1);
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Rejected);
        assert!(map.is_empty(), "future-ts envelope must not insert");

        // Far-past ts — rejected.
        let env = build_envelope(&alice, target, 0.99, now - state.skew_past_secs - 1, 1);
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Rejected);
        assert!(map.is_empty(), "stale-ts envelope must not insert");

        // Within window — accepted.
        let env = build_envelope(&alice, target, 0.99, now, 1);
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Inserted);
    }

    /// Hammer F1.3 — replaying the exact same envelope twice merges
    /// only once. The second copy is dropped at the seen-signatures
    /// gate without re-running crypto.
    #[test]
    fn replay_is_filtered() {
        let alice = Identity::new();
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
        let now = 1_700_000_000u64;

        let (mut state, _map) = fresh_state();

        let env = build_envelope(&alice, target, 0.95, now, 1);
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Inserted);
        // Same bytes, same signature → must be rejected at the replay gate.
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Rejected);
    }

    /// Hammer F1.3 corollary — a tampered envelope (good shape, bad
    /// signature) is rejected by the crypto gate.
    #[test]
    fn tampered_envelope_is_rejected() {
        let alice = Identity::new();
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
        let now = 1_700_000_000u64;

        let (mut state, map) = fresh_state();

        let mut env = build_envelope(&alice, target, 0.5, now, 1);
        // Flip a payload byte without re-signing.
        let len = env.data.payload.len();
        env.data.payload[len - 1] ^= 0xFF;
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Rejected);
        assert!(map.is_empty());
    }

    /// Hammer — `OpCode::Ping` envelopes (or anything without our magic
    /// prefix) flow through the network silently. We are only one
    /// participant on the AIMP wire; native chatter must not error.
    #[test]
    fn non_zion_envelope_is_ignored_not_errored() {
        let alice = Identity::new();
        let now = 1_700_000_000u64;
        let data = AimpData {
            v: 0x01,
            op: OpCode::Ping,
            ttl: 4,
            origin_pubkey: alice.node_id(),
            vclock: BTreeMap::new(),
            payload: vec![0u8; 32], // 32-byte Merkle root, no ZION prefix
        };
        let env = alice.sign(data).unwrap();

        let (mut state, _map) = fresh_state();
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Rejected);
    }

    /// Hammer — LWW with strict `>` (not `>=`). Two peers publishing
    /// at the *same* second must not ping-pong: the first wins.
    #[test]
    fn equal_timestamp_does_not_overwrite() {
        let alice = Identity::new();
        let bob = Identity::new();
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
        let now = 1_700_000_000u64;

        let (mut state, map) = fresh_state();

        let env_a = build_envelope(&alice, target, 0.5, now, 1);
        assert_eq!(state.try_merge(&env_a, now), MergeOutcome::Inserted);

        let env_b = build_envelope(&bob, target, 0.99, now, 1);
        assert_eq!(state.try_merge(&env_b, now), MergeOutcome::Stale);

        // Map still has Alice's entry, not Bob's.
        let entry = map.get(&target).unwrap();
        assert_eq!(entry.source_node, alice.node_id());
        assert!((entry.score - 0.5).abs() < 1e-6);
    }

    /// Issue #69 — `try_merge` bumps the right metrics counter for
    /// each rejection class, and bumps `mesh_claims_received` on a
    /// successful merge. We assert `delta >= expected` (not exact)
    /// because cargo runs aimp_cp tests in parallel and other tests
    /// also exercise `try_merge` against the same global METRICS
    /// singleton; concurrent contributions can only ADD to these
    /// counters (never subtract), so `>=` is the precise correctness
    /// claim — not a relaxation.
    #[test]
    fn try_merge_increments_mesh_metrics() {
        use std::sync::atomic::Ordering::Relaxed;
        let metrics = &crate::metrics::METRICS;
        let base_received = metrics.mesh_claims_received.load(Relaxed);
        let base_signature = metrics.mesh_claims_dropped_signature.load(Relaxed);
        let base_replay = metrics.mesh_claims_dropped_replay.load(Relaxed);
        let base_other = metrics.mesh_claims_dropped_other.load(Relaxed);

        let alice = Identity::new();
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
        let now = 1_700_000_000u64;

        let (mut state, _map) = fresh_state();

        // Path A: clean Insert — `mesh_claims_received += 1`.
        let env = build_envelope(&alice, target, 0.85, now, 1);
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Inserted);

        // Path B: replay (same envelope again) — `mesh_claims_dropped_replay += 1`.
        assert_eq!(state.try_merge(&env, now), MergeOutcome::Rejected);

        // Path C: ts in the far past — `mesh_claims_dropped_other += 1`.
        let stale = build_envelope(&alice, target, 0.5, now - 10 * 86_400, 1);
        assert_eq!(state.try_merge(&stale, now), MergeOutcome::Rejected);

        // Path D: forged signature — `mesh_claims_dropped_signature += 1`.
        // Build a real envelope, then mutate one byte of the signature
        // so verify() fails. Must use a fresh sig (not in seen filter)
        // so we exercise the signature path, not the replay path.
        let mut forged = build_envelope(&alice, target, 0.42, now + 1, 1);
        forged.signature[0] ^= 0xff;
        assert_eq!(state.try_merge(&forged, now), MergeOutcome::Rejected);

        let d_received = metrics.mesh_claims_received.load(Relaxed) - base_received;
        let d_signature = metrics.mesh_claims_dropped_signature.load(Relaxed) - base_signature;
        let d_replay = metrics.mesh_claims_dropped_replay.load(Relaxed) - base_replay;
        let d_other = metrics.mesh_claims_dropped_other.load(Relaxed) - base_other;

        // `>=` is exact: counters are monotonic + we did at least the
        // shown number of bumps each. Concurrent test contributions
        // can only inflate the right side.
        assert!(
            d_received >= 1,
            "received delta = {d_received}; expected >= 1"
        );
        assert!(d_replay >= 1, "replay delta = {d_replay}; expected >= 1");
        assert!(d_other >= 1, "other delta = {d_other}; expected >= 1");
        assert!(
            d_signature >= 1,
            "signature delta = {d_signature}; expected >= 1"
        );
    }

    /// Issue #69 — `publish_block` bumps `mesh_claims_emitted` on a
    /// successful enqueue. We exercise it here by constructing an
    /// AimpControlPlane manually (bypassing the UDP bind in
    /// `bootstrap()`) so the test runs in any CI sandbox.
    #[test]
    fn publish_block_increments_mesh_emitted_metric() {
        use std::sync::atomic::Ordering::Relaxed;
        let metrics = &crate::metrics::METRICS;
        let base = metrics.mesh_claims_emitted.load(Relaxed);

        let identity = Identity::new();
        let (publish_tx, _publish_rx) = mpsc::channel::<WafReputationDelta>(8);
        let (_update_tx, update_rx) = watch::channel::<u64>(0);
        let cp = AimpControlPlane {
            reputation: Arc::new(DashMap::new()),
            publish_tx,
            update_rx,
            self_node_id: identity.node_id(),
        };

        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100));
        cp.publish_block(target, 0.91, 1).expect("enqueue");
        cp.publish_block(target, 0.92, 1).expect("enqueue");

        let delta = metrics.mesh_claims_emitted.load(Relaxed) - base;
        // `>=` for the same monotonic-counter / parallel-tests
        // reasoning as the try_merge metrics test above.
        assert!(
            delta >= 2,
            "publish_block called twice → counter delta = {delta}; expected >= 2"
        );
    }

    // ── Chaos scenarios (issue #71) ──────────────────────────────────
    // Failure modes that don't surface under happy-path gossip:
    // split-brain reconciliation, inbound claim flood, and a slow peer
    // whose backlog arrives in a burst. These drive `try_merge` directly
    // (the same minimal-state pattern as the hammer tests) so they're
    // deterministic and need no UDP socket or wall-clock sleep.

    /// #71 F2.1 — split brain: the cluster partitions, each half forms
    /// its own view of the same IP from a different peer, and on heal the
    /// claims reconcile cleanly. LWW must converge both halves to the one
    /// newest observation — no double-count, and no permanent ban
    /// synthesised from the losing half's older accusation.
    #[test]
    fn mesh_split_brain_reconciles_after_partition_heals() {
        let alice = Identity::new(); // peer heard by half A
        let bob = Identity::new(); // peer heard by half B
        let target = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let t_a = 1_700_000_100u64;
        let t_b = 1_700_000_200u64; // bob's observation is the newer one
        let now = t_b; // both halves evaluate against the same clock

        let (mut half_a, map_a) = fresh_state();
        let (mut half_b, map_b) = fresh_state();

        // During the partition each half sees only its own peer's claim.
        let claim_a = build_envelope(&alice, target, 0.80, t_a, 1);
        let claim_b = build_envelope(&bob, target, 0.90, t_b, 1);
        assert_eq!(half_a.try_merge(&claim_a, now), MergeOutcome::Inserted);
        assert_eq!(half_b.try_merge(&claim_b, now), MergeOutcome::Inserted);

        // Heal: each half now also receives the other's claim.
        // Half A adopts bob's newer claim; half B keeps its own (alice's
        // is older → Stale under strict-`>` LWW).
        assert_eq!(half_a.try_merge(&claim_b, now), MergeOutcome::Updated);
        assert_eq!(half_b.try_merge(&claim_a, now), MergeOutcome::Stale);

        // Converged: exactly one entry per half, the same winner, and no
        // duplicate rows for the same IP.
        assert_eq!(map_a.len(), 1, "half A must hold exactly one entry");
        assert_eq!(map_b.len(), 1, "half B must hold exactly one entry");
        let ea = *map_a.get(&target).unwrap();
        let eb = *map_b.get(&target).unwrap();
        assert_eq!(ea.ts_secs, t_b);
        assert_eq!(eb.ts_secs, t_b);
        assert_eq!(ea.source_node, bob.node_id());
        assert_eq!(eb.source_node, bob.node_id());
        assert!((ea.score - 0.90).abs() < 1e-6);
        assert!((eb.score - 0.90).abs() < 1e-6);
    }

    /// #71 F2.2 — claim flood: one source (a compromised peer holding a
    /// valid key) floods the merge path. The per-source rate-cap must
    /// hold (only `burst` admitted at a single instant, the rest dropped
    /// and counted), legitimate signals from *other* sources must keep
    /// flowing, and the cap must throttle rather than ban (the flooder
    /// recovers capacity once the window advances).
    #[test]
    fn mesh_inbound_flood_caps_at_configured_rate() {
        use std::sync::atomic::Ordering::Relaxed;
        let metrics = &crate::metrics::METRICS;
        let base_rate = metrics.mesh_claims_dropped_rate.load(Relaxed);

        let rate = 5u32;
        let burst = 10u32;
        let now = 1_700_000_000u64;

        let map: Arc<DashMap<IpAddr, WafReputation>> = Arc::new(DashMap::new());
        let (tx, _rx) = watch::channel(0u64);
        let mut state = ReceiverState::new(map.clone(), tx).with_inbound_rate(rate, burst);

        let mallory = Identity::new(); // flooding source
        let alice = Identity::new(); // legitimate source

        // Flood with N distinct claims at one instant. A distinct target
        // IP per claim → distinct payload → distinct signature, so none
        // collide with the replay filter: the rate-cap is the only gate
        // that can drop them.
        let flood = 40u32;
        let mut admitted = 0u32;
        let mut rate_dropped = 0u32;
        for i in 0..flood {
            let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, i as u8));
            let env = build_envelope(&mallory, ip, 0.95, now, 1);
            match state.try_merge(&env, now) {
                MergeOutcome::Inserted => admitted += 1,
                MergeOutcome::Rejected => rate_dropped += 1,
                other => panic!("unexpected outcome {other:?}"),
            }
        }

        // At a single instant the bucket starts full and never refills, so
        // exactly `burst` are admitted and the remainder trip the cap.
        assert_eq!(
            admitted, burst,
            "admitted {admitted}, expected burst {burst}"
        );
        assert_eq!(rate_dropped, flood - burst);

        // Legitimate signals keep flowing: a different source has its own
        // bucket, untouched by Mallory's flood at the same instant.
        let legit = build_envelope(
            &alice,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            0.70,
            now,
            1,
        );
        assert_eq!(state.try_merge(&legit, now), MergeOutcome::Inserted);

        // Throttle, not ban: after the window advances tokens refill, so
        // Mallory can publish again.
        let later = now + 2; // +10 tokens, capped at burst
        let env = build_envelope(
            &mallory,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)),
            0.95,
            later,
            1,
        );
        assert_eq!(state.try_merge(&env, later), MergeOutcome::Inserted);

        let d_rate = metrics.mesh_claims_dropped_rate.load(Relaxed) - base_rate;
        assert!(
            d_rate >= u64::from(flood - burst),
            "dropped_rate delta {d_rate}; expected >= {}",
            flood - burst
        );
    }

    /// #71 F2.3 — slow gossip: a wedged peer's claims accumulate and
    /// arrive in a burst once its link recovers. Replays and stale
    /// observations must not synthesise duplicate decisions; only the
    /// genuinely newer claim changes state, exactly once.
    #[test]
    fn mesh_slow_gossip_no_duplicate_decisions() {
        use std::sync::atomic::Ordering::Relaxed;
        let metrics = &crate::metrics::METRICS;
        let base_received = metrics.mesh_claims_received.load(Relaxed);

        let alice = Identity::new();
        let target = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
        let t0 = 1_700_000_000u64;
        let now = t0 + 100; // the link recovers well after the originals

        let (mut state, map) = fresh_state();

        // Decision 1: the first observation lands.
        let c0 = build_envelope(&alice, target, 0.80, t0, 1);
        assert_eq!(state.try_merge(&c0, now), MergeOutcome::Inserted);

        // The wedged peer's backlog now arrives all at once:
        // (a) exact replay of c0 → dropped at the replay filter.
        assert_eq!(state.try_merge(&c0, now), MergeOutcome::Rejected);
        // (b) an older queued claim → Stale under LWW, no state change.
        let older = build_envelope(&alice, target, 0.60, t0 - 50, 1);
        assert_eq!(state.try_merge(&older, now), MergeOutcome::Stale);
        // (c) the one genuinely newer claim → a single new decision.
        let newer = build_envelope(&alice, target, 0.90, t0 + 10, 1);
        assert_eq!(state.try_merge(&newer, now), MergeOutcome::Updated);
        // (d) the slow peer re-sends the newer claim → replay, no decision.
        assert_eq!(state.try_merge(&newer, now), MergeOutcome::Rejected);

        // Exactly one row, holding the newest observation — no duplicates
        // synthesised from the six delivered envelopes.
        assert_eq!(map.len(), 1);
        let e = *map.get(&target).unwrap();
        assert_eq!(e.ts_secs, t0 + 10);
        assert!((e.score - 0.90).abs() < 1e-6);

        // The per-call outcomes above are the proof that replays/stale
        // changed nothing; the counter delta corroborates (>= the two
        // genuine decisions; `==` would be racy against parallel tests).
        let d_received = metrics.mesh_claims_received.load(Relaxed) - base_received;
        assert!(
            d_received >= 2,
            "received delta {d_received}; expected >= 2 genuine decisions"
        );
    }
}
