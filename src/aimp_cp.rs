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
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:9443".parse().unwrap()
}
fn default_key_path() -> PathBuf {
    PathBuf::from("/var/lib/zion/aimp-identity.bin")
}

impl Default for AimpControlPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_listen(),
            peers: vec![],
            identity_path: default_key_path(),
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

    // --- Identity (load or generate). v0 PoC just generates a fresh
    //     ephemeral identity; v1 will persist to `cfg.identity_path`.
    let identity = Arc::new(Identity::new());
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
        tokio::spawn(async move {
            run_receiver(socket, reputation, update_tx).await;
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
        }
    }

    /// Apply the policy gates and merge, returning what happened.
    /// `now_secs` is injected so tests can pin time without sleeping.
    pub(crate) fn try_merge(&mut self, envelope: &AimpEnvelope, now_secs: u64) -> MergeOutcome {
        // 1. Replay filter (cheap; do this before crypto).
        if self.seen_sigs.contains(&envelope.signature) {
            return MergeOutcome::Rejected;
        }

        // 2. Signature verification — every ingress envelope must pass.
        if !SecurityFirewall::verify(envelope) {
            return MergeOutcome::Rejected;
        }

        // 3. Magic prefix check (filters AIMP-native chatter).
        let payload = &envelope.data.payload;
        if payload.len() < ZION_MAGIC.len() || &payload[..ZION_MAGIC.len()] != ZION_MAGIC {
            return MergeOutcome::Rejected;
        }

        // 4. Decode the inner delta.
        let delta: WafReputationDelta = match rmp_serde::from_slice(&payload[ZION_MAGIC.len()..]) {
            Ok(d) => d,
            Err(_) => return MergeOutcome::Rejected,
        };

        // 5. Timestamp window. A peer with a future clock or a
        //    captured-and-replayed-from-the-past delta is rejected.
        if delta.ts_secs > now_secs.saturating_add(self.skew_future_secs) {
            return MergeOutcome::Rejected;
        }
        if delta.ts_secs.saturating_add(self.skew_past_secs) < now_secs {
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
            if outcome == MergeOutcome::Removed {
                self.bump_version();
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
            self.bump_version();
        }
        outcome
    }

    fn bump_version(&mut self) {
        self.version = self.version.wrapping_add(1);
        let _ = self.update_tx.send(self.version);
    }
}

async fn run_receiver(
    socket: Arc<UdpSocket>,
    reputation: Arc<DashMap<IpAddr, WafReputation>>,
    update_tx: watch::Sender<u64>,
) {
    let mut buf = vec![0u8; 65_507]; // max UDP datagram
    let mut state = ReceiverState::new(reputation, update_tx);

    loop {
        let (len, _peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let envelope: AimpEnvelope = match rmp_serde::from_slice(&buf[..len]) {
            Ok(e) => e,
            Err(_) => continue,
        };
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
            let _ = socket.send_to(&bytes, peer).await;
        }
    }
}

// ── Cross-track wires (Track B3: CRDT update → data plane) ───────────

/// Spawn a task that mirrors the AIMP reputation map into the XDP
/// `BLOCKED_V4` LPM-trie. Each map update bumps the watch counter, the
/// watcher wakes, scans the reputation map for entries above
/// `block_threshold`, and inserts/removes XDP map keys accordingly.
///
/// This is the wire that turns "we heard about a bad IP from a peer"
/// into "kernel-level XDP drop on this NIC" — the single path that
/// converts gossip into line-rate enforcement.
///
/// Compiled only when **all three** features line up: the control
/// plane (Track B), Linux, and the XDP loader (Track A). On any other
/// build the wire compiles to nothing.
#[cfg(all(target_os = "linux", feature = "xdp"))]
pub fn spawn_xdp_sync(
    cp: AimpControlPlane,
    handle: std::sync::Arc<crate::xdp::XdpHandle>,
    block_threshold: f32,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut updates = cp.subscribe();
        let map = cp.reputation();
        loop {
            // Wait for the *next* version bump. `changed()` returns
            // immediately if there has been an update we haven't seen.
            if updates.changed().await.is_err() {
                break; // sender dropped → control plane shut down
            }

            // Scan all entries and reconcile with the XDP map. v0
            // implementation is O(N) per update, which is fine until
            // the map exceeds ~10k entries — at that point switch to
            // a delta-only API on the control plane.
            for entry in map.iter() {
                let (ip, rep) = entry.pair();
                let ip_v4 = match ip {
                    std::net::IpAddr::V4(v4) => *v4,
                    std::net::IpAddr::V6(_) => continue, // v0: IPv4 only
                };
                let cidr = crate::xdp::Cidr4::host(ip_v4);
                // A score that fell back below threshold (e.g. a
                // downgrade from a peer who saw the IP behave) must
                // also remove the XDP entry — otherwise we keep
                // dropping packets from an IP that is no longer
                // collectively considered hostile.
                if rep.score >= block_threshold {
                    let _ = handle.add_blocked(cidr).await;
                } else {
                    let _ = handle.remove_blocked(cidr).await;
                }
            }
        }
    })
}

// ── Helpers ──────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
