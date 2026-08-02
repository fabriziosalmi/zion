// SPDX-License-Identifier: Apache-2.0
//! Audit log — HMAC-SHA256-chained, JSON-line events for compliance.
//!
//! Goals (in priority order):
//!   1. **Tamper evidence.** Every event carries `prev_hash`, the HMAC of
//!      the previous event. A reader who knows the secret key can verify
//!      the entire chain in O(n); a single missing or modified line breaks
//!      verification at the offending position.
//!   2. **Non-blocking emission.** The hot path (TLS handshake, dispatch,
//!      WAF gate) hands events to a bounded `mpsc` and returns immediately.
//!      A dedicated writer task drains the queue, signs, and writes. If
//!      the queue is full (writer is slow / disk is wedged), the event is
//!      *dropped* and `zion_audit_events_dropped_total` is bumped — never
//!      blocking the request path is the design choice. This is documented.
//!   3. **PII redaction.** Header values and query parameters listed in
//!      [`RedactConfig`](crate::audit::RedactConfig) are replaced with
//!      `<redacted:N>` (N = original byte length, useful for downstream
//!      sizing analysis) before signing.
//!      Redaction happens at construction time, not at write time, so the
//!      chain hash is computed over the already-redacted record.
//!
//! Wire format: one JSON object per line (NDJSON / JSON Lines), keys are
//! lowercase, timestamps are RFC 3339 / ISO 8601 with microsecond precision,
//! `hmac` is hex-encoded SHA-256 (64 chars), `prev_hash` is the same on
//! every record except the first (where it is the hex-encoded
//! HMAC-SHA256(key, "ZION-AUDIT-GENESIS-V1")).

use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

use crate::observability;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Config — surfaced into ZionConfig::{audit,redact}.
// ─────────────────────────────────────────────────────────────────────────────

/// `[audit]` block in zion.toml.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Enable the writer task. Disabled by default — operator must opt in.
    pub enabled: bool,
    /// Filesystem path for the JSON-Lines audit log. The parent directory
    /// must already exist; we don't `mkdir -p` since this code can run as
    /// a non-root user with no DAC capability.
    pub path: Option<String>,
    /// Name of the env var that holds the HMAC key. We deliberately don't
    /// accept the key as a literal in zion.toml — config files end up in
    /// version control too easily.
    #[serde(default = "default_key_env")]
    pub key_env: String,
    /// Bounded queue depth. Events beyond this are dropped (and counted).
    /// Pick a number large enough to absorb a fsync stall.
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,
    /// Rotate the active segment once it reaches this many megabytes. `None`
    /// (or `0`) disables rotation — the log grows unbounded, the pre-rotation
    /// behavior. Default 100 MB. The HMAC chain re-anchors at genesis in the
    /// fresh segment (a `chain_rotate` marker records the boundary), so every
    /// segment verifies independently — the same tamper-evidence model already
    /// used at process restart.
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: Option<u64>,
    /// How many rotated segments to keep on disk; the oldest are pruned first.
    /// `0` keeps them all (operator manages retention out-of-band). Default 10,
    /// so the on-disk ceiling is `max_size_mb * (max_files + 1)`.
    #[serde(default = "default_max_files")]
    pub max_files: usize,
}

fn default_key_env() -> String {
    "ZION_AUDIT_HMAC_KEY".to_string()
}

fn default_queue_depth() -> usize {
    4096
}

fn default_max_size_mb() -> Option<u64> {
    Some(100)
}

fn default_max_files() -> usize {
    10
}

/// `[redact]` block. Lists are case-insensitive. Empty = no redaction.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RedactConfig {
    /// HTTP header names whose value should be replaced with `<redacted:N>`.
    /// Compared lowercase per RFC 9110 §5.1 (header names are case-insensitive).
    pub headers: Vec<String>,
    /// Query-parameter names whose value should be redacted.
    pub query_params: Vec<String>,
}

impl RedactConfig {
    /// Build a fast-lookup compiled set. Called once at config-load time.
    pub fn compile(&self) -> CompiledRedaction {
        CompiledRedaction {
            headers: self
                .headers
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            query_params: self
                .query_params
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }
}

/// Compiled, case-folded redaction lists. Cheap to clone (`Vec<String>`).
#[derive(Clone, Debug, Default)]
pub struct CompiledRedaction {
    headers: Vec<String>,
    query_params: Vec<String>,
}

impl CompiledRedaction {
    /// Test whether the given (lowercased) header name should be redacted.
    /// Currently consumed by the unit tests and reserved for the access-log
    /// integration point; kept on the public surface so callers can ship
    /// their own log layer without forking this module.
    #[allow(dead_code)]
    pub fn redacts_header(&self, lowercased_name: &str) -> bool {
        self.headers.iter().any(|h| h == lowercased_name)
    }

    /// Test whether the given (lowercased) query-param name should be redacted.
    pub fn redacts_query_param(&self, lowercased_name: &str) -> bool {
        self.query_params.iter().any(|p| p == lowercased_name)
    }

    /// Apply redaction to a header value. Returns `Cow::Borrowed(orig)` when
    /// no redaction is needed, `Cow::Owned(...)` otherwise. Callers can
    /// pass the result straight into `serde_json::Value::String`.
    /// Same status as `redacts_header` — public for downstream loggers.
    #[allow(dead_code)]
    pub fn redact_header_value<'a>(
        &self,
        name_lower: &str,
        value: &'a str,
    ) -> std::borrow::Cow<'a, str> {
        if self.redacts_header(name_lower) {
            std::borrow::Cow::Owned(format!("<redacted:{}>", value.len()))
        } else {
            std::borrow::Cow::Borrowed(value)
        }
    }

    /// Apply redaction to every value of a percent-encoded `query=…&q2=…`
    /// string. Keys are matched case-insensitively. The output preserves
    /// key order. Returns `None` if the input had no query string.
    pub fn redact_query_string(&self, query: &str) -> String {
        let mut out = String::with_capacity(query.len());
        for (i, pair) in query.split('&').enumerate() {
            if i > 0 {
                out.push('&');
            }
            match pair.split_once('=') {
                Some((k, v)) => {
                    let k_lower = k.to_ascii_lowercase();
                    out.push_str(k);
                    out.push('=');
                    if self.redacts_query_param(&k_lower) {
                        // Preserve length signal as <redacted:N>.
                        out.push_str(&format!("<redacted:{}>", v.len()));
                    } else {
                        out.push_str(v);
                    }
                }
                None => out.push_str(pair),
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Event taxonomy. Keep narrow on purpose — every variant must be
//    actionable for an auditor.
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical audit-event kind names. Using string constants (not an
/// enum) keeps `AuditEvent.kind` zero-cost (`&'static str`) and lets
/// callsites read like the on-disk format. Auditors grep on these
/// values; treat them like a wire format and add new ones additively.
///
/// `#[allow(dead_code)]` at module level: callsites today still pass
/// the kind name as a string literal (`kind: "auth_failure"`); these
/// constants are the reference list for new callsites. Migrating the
/// existing literals to these constants is a follow-up — the value of
/// landing the canonical surface now is that the new mesh / quorum /
/// peer-state callsites added over the v0.4 mesh slice can reference
/// `audit::kind::MESH_*` instead of inventing parallel literals.
#[allow(dead_code)]
pub mod kind {
    /// Successful authentication (`--features auth`).
    pub const AUTH_SUCCESS: &str = "auth_success";
    /// Failed authentication.
    pub const AUTH_FAILURE: &str = "auth_failure";
    /// `zion.toml` reload (success or rejection — see `detail`).
    pub const CONFIG_RELOAD: &str = "config_reload";
    /// WAF / rate-limit / mTLS gate denied a request.
    pub const REQUEST_BLOCKED: &str = "request_blocked";
    /// Internal endpoint (`/metrics`, `/_zion/*`) accessed.
    pub const ADMIN_ACCESS: &str = "admin_access";
    /// Worker thread panicked; panic hook captured the trace.
    pub const PANIC: &str = "panic";
    /// Request completed — emitted alongside the access log when
    /// `[access_log]` opts into headers / mTLS fingerprint (#60).
    /// Carries `status`, `latency_us`, the redacted-header JSON
    /// blob, and the mTLS fingerprint in `detail`.
    pub const REQUEST_COMPLETED: &str = "request_completed";
    /// Mesh claim published to the gossip mesh (#69 / #70).
    pub const MESH_PUBLISH: &str = "mesh_publish";
    /// Mesh claim received from a peer and merged into local state.
    pub const MESH_RECEIVE: &str = "mesh_receive";
    /// Reserved for future mesh-side events. Defined here as the
    /// canonical strings so callsites added in follow-up PRs reference
    /// `audit::kind::MESH_PEER_JOINED` instead of hand-typing literals.
    #[allow(dead_code)] // wired by the mesh peer-state tracker (#68 follow-up)
    pub const MESH_PEER_JOINED: &str = "mesh_peer_joined";
    #[allow(dead_code)] // wired by the mesh peer-state tracker (#68 follow-up)
    pub const MESH_PEER_DROPPED: &str = "mesh_peer_dropped";
    #[allow(dead_code)] // wired by the mesh quorum aggregator (#66/#67 follow-up)
    pub const MESH_QUORUM_DECISION: &str = "mesh_quorum_decision";
}

/// One audit event before signing. Fields are lowercase to match wire format.
#[derive(Serialize, Clone, Debug)]
pub struct AuditEvent {
    /// Monotonic event sequence within this process. Resets on restart.
    pub seq: u64,
    /// RFC 3339 / ISO 8601 timestamp.
    pub ts: String,
    /// Event type — see [`kind`] for the canonical name set.
    pub kind: &'static str,
    /// Optional 32-char hex trace ID linking to the originating request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Optional remote IP (already redacted if config dictates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Optional method/path. Path query string is redacted via [`CompiledRedaction`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Free-form fields supplied by the call site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A signed audit record — the on-disk wire format. `hmac` is computed over
/// the canonical JSON of [`AuditEvent`] concatenated with `prev_hash`.
#[derive(Serialize, Clone, Debug)]
pub struct SignedAuditEvent {
    #[serde(flatten)]
    pub event: AuditEvent,
    /// Hex-encoded HMAC-SHA256 of the previous SignedAuditEvent's `hmac`.
    /// On the first record this is the genesis tag (see module docstring).
    pub prev_hash: String,
    /// Hex-encoded HMAC-SHA256 of canonical(`event` || `prev_hash`).
    pub hmac: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Signing — pure function, easy to unit-test.
// ─────────────────────────────────────────────────────────────────────────────

const GENESIS_TAG: &[u8] = b"ZION-AUDIT-GENESIS-V1";

/// Compute the HMAC-SHA256 hex digest of an [`AuditEvent`] given the chain's
/// previous hash. Pure, deterministic, used both at write time and by
/// external verifiers.
pub fn compute_hmac(key: &hmac::Key, event_json: &str, prev_hash_hex: &str) -> String {
    // Concatenate canonical event JSON + prev_hash bytes, sign once.
    // Domain separation: event JSON ends with `}`, then `|`, then prev_hash.
    // The literal `|` cannot appear inside any well-formed top-level JSON
    // object, so the boundary is unambiguous.
    let mut tag_input = Vec::with_capacity(event_json.len() + prev_hash_hex.len() + 1);
    tag_input.extend_from_slice(event_json.as_bytes());
    tag_input.push(b'|');
    tag_input.extend_from_slice(prev_hash_hex.as_bytes());
    let tag = hmac::sign(key, &tag_input);
    hex_encode(tag.as_ref())
}

/// Compute the genesis hash: `HMAC(key, "ZION-AUDIT-GENESIS-V1")`. The first
/// signed event in the log uses this as its `prev_hash`.
pub fn genesis_hash(key: &hmac::Key) -> String {
    let tag = hmac::sign(key, GENESIS_TAG);
    hex_encode(tag.as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; bytes.len() * 2];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = LUT[(b >> 4) as usize];
        out[i * 2 + 1] = LUT[(b & 0x0F) as usize];
    }
    // SAFETY: every byte we wrote is in the ASCII subset of UTF-8.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Sign an event in the chain. Returns the signed record AND the new
/// `prev_hash` to feed into the next event.
pub fn sign_event(
    key: &hmac::Key,
    event: AuditEvent,
    prev_hash: String,
) -> Result<(SignedAuditEvent, String), serde_json::Error> {
    let event_json = serde_json::to_string(&event)?;
    let mac = compute_hmac(key, &event_json, &prev_hash);
    let signed = SignedAuditEvent {
        event,
        prev_hash,
        hmac: mac.clone(),
    };
    Ok((signed, mac))
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Async writer — bounded mpsc, dedicated task.
// ─────────────────────────────────────────────────────────────────────────────

/// Handle that the rest of the codebase uses to push audit events. Cheap to
/// clone (it's a `tokio::sync::mpsc::Sender` underneath). When the writer
/// is disabled ([`AuditConfig::enabled`] = false at config-load time) the
/// handle is `None` and `emit()` is a no-op.
#[derive(Clone)]
pub struct AuditHandle {
    inner: Option<tokio::sync::mpsc::Sender<AuditEvent>>,
}

impl AuditHandle {
    /// Create a no-op handle. Used when audit is disabled or the writer
    /// failed to start (the latter logs a warning).
    pub fn noop() -> Self {
        Self { inner: None }
    }

    /// Push one event. Non-blocking — drops the event if the queue is full
    /// and bumps `zion_audit_events_dropped_total`. Returns `true` if the
    /// event was queued (and `false` for both "dropped" and "no-op handle").
    pub fn emit(&self, event: AuditEvent) -> bool {
        let Some(tx) = self.inner.as_ref() else {
            return false;
        };
        match tx.try_send(event) {
            Ok(()) => {
                observability::AUDIT_EVENTS_TOTAL.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                observability::AUDIT_EVENTS_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

/// Spawn the audit writer. Returns a handle the rest of the system clones
/// into `AppState`. If `cfg.enabled` is `false` or the key is missing /
/// path is missing / file open fails, returns a no-op handle and logs a
/// warning — we never want an audit-config error to block boot.
pub fn spawn_writer(cfg: &AuditConfig) -> AuditHandle {
    if !cfg.enabled {
        return AuditHandle::noop();
    }

    let path = match cfg.path.as_deref() {
        Some(p) => p.to_string(),
        None => {
            crate::logging::warn(
                "audit",
                "audit.enabled=true but audit.path not set — disabling audit log",
            );
            return AuditHandle::noop();
        }
    };

    let key_bytes = match std::env::var(&cfg.key_env) {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => {
            crate::logging::warn(
                "audit",
                &format!(
                    "audit.enabled=true but env var {} is empty/unset — disabling audit log",
                    cfg.key_env
                ),
            );
            return AuditHandle::noop();
        }
    };

    // RFC 2104 recommends the key be at least the hash output length (32B
    // for SHA-256). Shorter keys are accepted but reduce the security
    // ceiling — surface a warning so an operator can fix it.
    if key_bytes.len() < 32 {
        crate::logging::warn(
            "audit",
            &format!(
                "audit HMAC key is {} bytes; recommended minimum is 32 (HMAC-SHA256 block-size). Continuing.",
                key_bytes.len()
            ),
        );
    }

    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let (tx, rx) = tokio::sync::mpsc::channel::<AuditEvent>(cfg.queue_depth);

    // `max_size_mb = None` or `0` disables rotation (unbounded); otherwise the
    // active segment rotates once it crosses the byte cap.
    let max_size_bytes = cfg
        .max_size_mb
        .filter(|&mb| mb > 0)
        .map(|mb| mb.saturating_mul(1024 * 1024));
    tokio::spawn(writer_loop(path, key, rx, max_size_bytes, cfg.max_files));

    AuditHandle { inner: Some(tx) }
}

async fn writer_loop(
    path: String,
    key: hmac::Key,
    mut rx: tokio::sync::mpsc::Receiver<AuditEvent>,
    max_size_bytes: Option<u64>,
    max_files: usize,
) {
    use tokio::io::AsyncWriteExt;

    // Open the initial segment and anchor the chain. Mirrors the process-restart
    // model: a fresh chain from genesis + a boundary marker (we never continue
    // from an on-disk tail — that would mean trusting an unverified value).
    let Some((mut file, mut prev_hash, mut bytes_written)) = open_and_anchor(
        &path,
        &key,
        "chain_init",
        "audit chain initialized at process start",
    )
    .await
    else {
        return; // fatal open error already logged
    };

    let mut seq: u64 = 1;
    // Tracks whether flush is currently failing, so we log the degraded↔healthy
    // transition once instead of per-event.
    let mut flush_degraded = false;
    // Once rotation becomes impossible (rename keeps failing), stop attempting
    // it so the writer degrades to unbounded-with-a-warning instead of spinning
    // (re-anchor → still over cap → rename fails → repeat).
    let mut rotation_disabled = max_size_bytes.is_none();

    while let Some(mut event) = rx.recv().await {
        event.seq = seq;
        if event.ts.is_empty() {
            event.ts = now_iso8601();
        }
        match sign_event(&key, event, prev_hash.clone()) {
            Ok((signed, new_prev)) => {
                if let Ok(mut line) = serde_json::to_string(&signed) {
                    line.push('\n'); // single all-or-nothing record write
                    if file.write_all(line.as_bytes()).await.is_err() {
                        // Terminal: the buffer can't even accept the record
                        // (disk full / fd revoked). Stop rather than spin.
                        crate::logging::error(
                            "audit",
                            "audit log write failed — buffer cannot accept data (disk full / fd revoked), exiting writer",
                        );
                        break;
                    }
                    prev_hash = new_prev;
                    seq += 1;
                    bytes_written += line.len() as u64;
                    // Flush each event — durability over throughput. A flush
                    // failure (transient ENOSPC, slow network FS) does NOT kill
                    // the writer: the record stays buffered and a later flush
                    // retries it, so audit self-heals once the disk recovers.
                    // Log the degraded↔healthy transition once, not per event.
                    match file.flush().await {
                        Ok(()) => {
                            if flush_degraded {
                                crate::logging::warn(
                                    "audit",
                                    "audit log flush recovered — durability restored",
                                );
                                flush_degraded = false;
                            }
                        }
                        Err(e) => {
                            if !flush_degraded {
                                crate::logging::error(
                                    "audit",
                                    &format!("audit log flush failing ({e}) — records buffered, not yet durable; retrying (writer stays alive)"),
                                );
                                flush_degraded = true;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                crate::logging::error("audit", &format!("audit event serialize failed: {e}"));
                continue;
            }
        }

        // Size-based rotation (RFC-agnostic disk hygiene, issue #288). Once the
        // active segment crosses the cap, seal it and re-anchor into a fresh
        // one. A rotation failure degrades to unbounded (logged once) rather
        // than killing the writer or spinning on a rename that keeps failing.
        if !rotation_disabled {
            if let Some(max) = max_size_bytes {
                if bytes_written >= max {
                    let _ = file.flush().await;
                    let _ = file.shutdown().await;
                    match rotate_paths(&path, max_files).await {
                        Ok(rotated_to) => match open_and_anchor(
                            &path,
                            &key,
                            "chain_rotate",
                            &format!("audit chain re-anchored after size rotation → {rotated_to}"),
                        )
                        .await
                        {
                            Some((f, ph, bw)) => {
                                file = f;
                                prev_hash = ph;
                                bytes_written = bw;
                                seq = 1;
                                crate::logging::info(
                                    "audit",
                                    &format!("audit log rotated → {rotated_to}"),
                                );
                            }
                            None => {
                                crate::logging::error(
                                    "audit",
                                    "cannot reopen audit log after rotation — exiting writer",
                                );
                                return;
                            }
                        },
                        Err(e) => {
                            crate::logging::warn(
                                "audit",
                                &format!("audit log rotation failed ({e}) — continuing unbounded on the current segment; check the directory's permissions/disk"),
                            );
                            // The original file is still at `path` (rename
                            // failed); reopen it so events keep flowing.
                            match open_and_anchor(
                                &path,
                                &key,
                                "chain_init",
                                "audit chain re-anchored (rotation failed; resuming on the current segment)",
                            )
                            .await
                            {
                                Some((f, ph, bw)) => {
                                    file = f;
                                    prev_hash = ph;
                                    bytes_written = bw;
                                    seq = 1;
                                }
                                None => return,
                            }
                            rotation_disabled = true;
                        }
                    }
                }
            }
        }
    }
    if file.flush().await.is_err() {
        crate::logging::warn("audit", "final audit log flush failed on writer shutdown");
    }
}

/// Open (create + append) the segment at `path` and write a re-anchor marker so
/// verifiers see the boundary — the same fresh-chain-from-genesis model used at
/// process restart. Returns `(writer, chain_head_hash, current_segment_bytes)`,
/// or `None` on a fatal open error (already logged). If the marker itself can't
/// be written, the writer is still returned with the chain head at genesis
/// (matching the pre-rotation degraded behavior).
async fn open_and_anchor(
    path: &str,
    key: &hmac::Key,
    kind: &'static str,
    context: &str,
) -> Option<(tokio::io::BufWriter<tokio::fs::File>, String, u64)> {
    use tokio::io::AsyncWriteExt;

    let file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            crate::logging::error(
                "audit",
                &format!("cannot open audit log {path}: {e} — events will be dropped"),
            );
            return None;
        }
    };
    // A pre-existing file (a restart onto an old segment) already carries bytes;
    // count them so rotation still fires on schedule instead of never.
    let existing = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let mut file = tokio::io::BufWriter::new(file);

    let genesis = genesis_hash(key);
    let init = AuditEvent {
        seq: 0,
        ts: now_iso8601(),
        kind,
        trace_id: None,
        remote_ip: None,
        method: None,
        path: None,
        detail: Some(format!("{context}; genesis={}", &genesis[..16])),
    };
    let mut head = genesis.clone();
    let mut bytes = existing;
    if let Ok((signed, new_prev)) = sign_event(key, init, genesis) {
        if let Ok(mut line) = serde_json::to_string(&signed) {
            line.push('\n'); // one all-or-nothing record write (no orphaned line)
            if file.write_all(line.as_bytes()).await.is_ok() && file.flush().await.is_ok() {
                head = new_prev;
                bytes += line.len() as u64;
            } else {
                crate::logging::error(
                    "audit",
                    "audit chain-anchor write/flush failed — the on-disk log may be unreliable",
                );
            }
        }
    }
    Some((file, head, bytes))
}

/// Seal the active segment: rename `path` → `path.<epoch_nanos>` (with a numeric
/// suffix on the astronomically-unlikely collision) and prune the oldest rotated
/// segments beyond `max_files`. The caller must have flushed + closed `path`.
async fn rotate_paths(path: &str, max_files: usize) -> std::io::Result<String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut rotated = format!("{path}.{stamp}");
    let mut n: u32 = 0;
    while tokio::fs::try_exists(&rotated).await.unwrap_or(false) {
        n += 1;
        rotated = format!("{path}.{stamp}.{n}");
    }
    tokio::fs::rename(path, &rotated).await?;
    prune_old_segments(path, max_files).await;
    Ok(rotated)
}

/// Delete the oldest rotated segments so at most `max_files` remain (`0` keeps
/// them all). A rotated segment is any sibling named `<basename>.<suffix>`;
/// ordering is by modification time so it is robust to the suffix format. Prune
/// failures are non-fatal — retention is best-effort, never a reason to drop an
/// audit event.
async fn prune_old_segments(path: &str, max_files: usize) {
    if max_files == 0 {
        return;
    }
    let p = std::path::Path::new(path);
    let (dir, base) = match (p.parent(), p.file_name().and_then(|n| n.to_str())) {
        (Some(d), Some(b)) => (d.to_path_buf(), b.to_string()),
        _ => return,
    };
    let prefix = format!("{base}.");
    let mut rd = match tokio::fs::read_dir(&dir).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut segments: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // A rotated segment is `<base>.<suffix>`; the active `<base>` has no
        // trailing dot and is excluded by the prefix test.
        if name.starts_with(&prefix) {
            let mtime = entry
                .metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            segments.push((mtime, entry.path()));
        }
    }
    if segments.len() <= max_files {
        return;
    }
    segments.sort_by_key(|(t, _)| *t); // oldest first
    let remove_n = segments.len() - max_files;
    for (_, seg) in segments.into_iter().take(remove_n) {
        let _ = tokio::fs::remove_file(&seg).await;
    }
}

fn now_iso8601() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let micros = d.subsec_micros();
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d_val = doy - (153 * mp + 2) / 5 + 1;
    let m_val = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_val = if m_val <= 2 { y + 1 } else { y };
    format!("{y_val:04}-{m_val:02}-{d_val:02}T{hours:02}:{minutes:02}:{seconds:02}.{micros:06}Z")
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Tests.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, b"this-is-a-32-byte-test-secret!ab")
    }

    #[test]
    fn genesis_hash_is_64_hex_chars() {
        let g = genesis_hash(&test_key());
        assert_eq!(g.len(), 64);
        assert!(g.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn genesis_hash_is_deterministic_for_same_key() {
        assert_eq!(genesis_hash(&test_key()), genesis_hash(&test_key()));
    }

    #[test]
    fn genesis_hash_differs_for_different_keys() {
        let k1 = test_key();
        let k2 = hmac::Key::new(hmac::HMAC_SHA256, b"different-32-byte-test-secret!12");
        assert_ne!(genesis_hash(&k1), genesis_hash(&k2));
    }

    fn make_event(seq: u64, kind: &'static str) -> AuditEvent {
        AuditEvent {
            seq,
            ts: "2026-05-05T08:00:00.000000Z".into(),
            kind,
            trace_id: None,
            remote_ip: None,
            method: None,
            path: None,
            detail: Some(format!("test event {seq}")),
        }
    }

    #[test]
    fn chain_three_events_each_links_to_previous() {
        let key = test_key();
        let mut prev = genesis_hash(&key);
        let mut signed = Vec::new();
        for i in 1..=3 {
            let (s, new_prev) = sign_event(&key, make_event(i, "test"), prev.clone()).unwrap();
            assert_eq!(s.prev_hash, prev);
            prev = new_prev;
            signed.push(s);
        }
        // Each next event's prev_hash equals the previous event's hmac.
        assert_eq!(signed[1].prev_hash, signed[0].hmac);
        assert_eq!(signed[2].prev_hash, signed[1].hmac);
    }

    #[test]
    fn tampering_an_event_breaks_the_next_hmac() {
        let key = test_key();
        let prev = genesis_hash(&key);
        let (mut s1, p1) = sign_event(&key, make_event(1, "test"), prev).unwrap();
        let (s2, _) = sign_event(&key, make_event(2, "test"), p1).unwrap();

        // Mutate s1's detail and recompute its hmac honestly. Now s2's
        // prev_hash no longer matches s1.hmac, even though s2 itself is
        // internally consistent. A verifier walks the chain top-down and
        // catches this on s2.
        s1.event.detail = Some("TAMPERED".into());
        let new_e1_json = serde_json::to_string(&s1.event).unwrap();
        s1.hmac = compute_hmac(&key, &new_e1_json, &s1.prev_hash);

        assert_ne!(s2.prev_hash, s1.hmac, "tamper must break the link");
    }

    #[test]
    fn redact_header_value_preserves_unmatched() {
        let r = RedactConfig {
            headers: vec!["authorization".into()],
            query_params: vec![],
        }
        .compile();
        assert_eq!(
            r.redact_header_value("user-agent", "Mozilla/5.0"),
            "Mozilla/5.0"
        );
    }

    #[test]
    fn redact_header_value_replaces_matched_with_length_token() {
        let r = RedactConfig {
            headers: vec!["authorization".into(), "cookie".into()],
            query_params: vec![],
        }
        .compile();
        assert_eq!(
            r.redact_header_value("authorization", "Bearer abc123xyz"),
            "<redacted:16>"
        );
        assert_eq!(
            r.redact_header_value("cookie", "session=deadbeef"),
            "<redacted:16>"
        );
    }

    #[test]
    fn redact_header_lookup_is_case_insensitive() {
        let r = RedactConfig {
            headers: vec!["AUTHORIZATION".into()],
            query_params: vec![],
        }
        .compile();
        assert_eq!(
            r.redact_header_value("authorization", "secret"),
            "<redacted:6>"
        );
    }

    #[test]
    fn redact_query_string_only_redacts_named_params() {
        let r = RedactConfig {
            headers: vec![],
            query_params: vec!["token".into(), "api_key".into()],
        }
        .compile();
        let out = r.redact_query_string("foo=bar&token=secret123&api_key=verylongkey");
        assert_eq!(out, "foo=bar&token=<redacted:9>&api_key=<redacted:11>");
    }

    #[test]
    fn redact_query_string_preserves_order_and_handles_no_value_pairs() {
        let r = RedactConfig {
            headers: vec![],
            query_params: vec!["b".into()],
        }
        .compile();
        // "x" pair has no '=' — must be passed through unchanged.
        let out = r.redact_query_string("x&a=1&b=secret&c=3");
        assert_eq!(out, "x&a=1&b=<redacted:6>&c=3");
    }

    #[test]
    fn audit_handle_noop_swallows_emit() {
        let h = AuditHandle::noop();
        assert!(!h.emit(make_event(1, "test")));
    }

    #[tokio::test]
    async fn writer_emits_chain_init_then_caller_event() {
        let dir = tempdir();
        let path = dir.join("audit.log");
        std::env::set_var("ZION_TEST_AUDIT_KEY", "this-is-a-32-byte-test-secret!ab");
        let cfg = AuditConfig {
            enabled: true,
            path: Some(path.to_string_lossy().into_owned()),
            key_env: "ZION_TEST_AUDIT_KEY".into(),
            queue_depth: 16,
            ..Default::default()
        };
        let h = spawn_writer(&cfg);
        assert!(h.emit(AuditEvent {
            seq: 0, // will be overwritten by writer
            ts: String::new(),
            kind: "auth_success",
            trace_id: Some("0af7651916cd43dd8448eb211c80319c".into()),
            remote_ip: Some("10.0.0.5".into()),
            method: None,
            path: None,
            detail: Some("smoke test".into()),
        }));

        // Drop the sender by dropping the handle so the writer task exits
        // cleanly after the channel closes.
        drop(h);

        // Tiny wait — writer flushes after each event.
        for _ in 0..50 {
            if let Ok(s) = std::fs::read_to_string(&path) {
                if s.lines().count() >= 2 {
                    let lines: Vec<&str> = s.lines().collect();
                    assert!(lines[0].contains(r#""kind":"chain_init""#));
                    assert!(lines[1].contains(r#""kind":"auth_success""#));
                    // The second event's prev_hash must equal the first event's hmac.
                    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
                    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
                    assert_eq!(
                        second["prev_hash"].as_str().unwrap(),
                        first["hmac"].as_str().unwrap(),
                        "chain link must be preserved"
                    );
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("writer did not emit two lines within 1s");
    }

    // ── Rotation (issue #288) ────────────────────────────────────────────
    // Drive `writer_loop` directly with a tiny *byte* cap (spawn_writer's
    // MB→bytes conversion is bypassed) so rotation fires in a handful of
    // events — deterministic and fast.

    async fn run_writer(
        dir: &std::path::Path,
        max_bytes: Option<u64>,
        max_files: usize,
        n_events: usize,
    ) -> std::path::PathBuf {
        let path = dir.join("audit.log");
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"this-is-a-32-byte-test-secret!ab");
        let (tx, rx) = tokio::sync::mpsc::channel::<AuditEvent>(256);
        let jh = tokio::spawn(writer_loop(
            path.to_string_lossy().into_owned(),
            key,
            rx,
            max_bytes,
            max_files,
        ));
        for i in 0..n_events {
            tx.send(AuditEvent {
                seq: 0,
                ts: String::new(),
                kind: "auth_success",
                trace_id: None,
                remote_ip: Some("10.0.0.5".into()),
                method: None,
                path: None,
                detail: Some(format!(
                    "event-{i}-with-padding-so-the-line-crosses-the-tiny-cap"
                )),
            })
            .await
            .unwrap();
        }
        drop(tx); // close the channel → writer drains, final-flushes, and exits
        jh.await.unwrap();
        path
    }

    /// Rotated siblings only (`audit.log.<suffix>`); the active `audit.log` has
    /// no trailing dot and is excluded.
    fn rotated_segments(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit.log."))
                    .unwrap_or(false)
            })
            .collect()
    }

    fn json_lines(p: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn rotation_seals_the_active_segment_at_the_byte_cap() {
        let dir = tempdir();
        let path = run_writer(&dir, Some(600), 10, 40).await;
        assert!(
            !rotated_segments(&dir).is_empty(),
            "crossing the cap 40 times must produce rotated segments"
        );
        // The active segment stays bounded (cap + at most one over-cap event),
        // not unbounded.
        let active = std::fs::metadata(&path).unwrap().len();
        assert!(
            active < 600 + 512,
            "active segment is {active} bytes — should hover near the 600B cap"
        );
    }

    #[tokio::test]
    async fn rotation_itself_loses_no_events() {
        let dir = tempdir();
        // max_files=0 → keep every segment, so this isolates rotation from
        // pruning: crossing a segment boundary must never drop an event.
        // (Pruning deliberately deletes old segments — covered separately.)
        let path = run_writer(&dir, Some(500), 0, 50).await;
        let mut files = rotated_segments(&dir);
        files.push(path);
        let total: usize = files
            .iter()
            .map(|f| {
                std::fs::read_to_string(f)
                    .unwrap()
                    .lines()
                    .filter(|l| l.contains(r#""kind":"auth_success""#))
                    .count()
            })
            .sum();
        assert_eq!(
            total, 50,
            "every event must survive rotation across segments"
        );
    }

    #[tokio::test]
    async fn rotation_prunes_beyond_max_files() {
        let dir = tempdir();
        // cap=300B, keep only 2 rotated segments; 60 events → many rotations.
        let _ = run_writer(&dir, Some(300), 2, 60).await;
        let rotated = rotated_segments(&dir);
        assert!(
            !rotated.is_empty() && rotated.len() <= 2,
            "max_files=2 must cap retained segments; got {}",
            rotated.len()
        );
    }

    #[tokio::test]
    async fn each_segment_reanchors_and_links_internally() {
        let dir = tempdir();
        let path = run_writer(&dir, Some(500), 10, 40).await;
        let mut files = rotated_segments(&dir);
        files.push(path);
        for f in &files {
            let lines = json_lines(f);
            assert!(!lines.is_empty(), "no empty segments");
            // Every segment opens with a re-anchor marker.
            let k0 = lines[0]["kind"].as_str().unwrap();
            assert!(
                k0 == "chain_init" || k0 == "chain_rotate",
                "segment {f:?} must open with a re-anchor marker, got {k0}"
            );
            // The chain links within the segment: each prev_hash == the prior hmac.
            for w in lines.windows(2) {
                assert_eq!(
                    w[1]["prev_hash"].as_str().unwrap(),
                    w[0]["hmac"].as_str().unwrap(),
                    "chain must link line-to-line within a segment"
                );
            }
        }
    }

    #[tokio::test]
    async fn no_rotation_when_the_cap_is_disabled() {
        let dir = tempdir();
        let path = run_writer(&dir, None, 10, 50).await;
        assert!(
            rotated_segments(&dir).is_empty(),
            "max_size=None must never rotate"
        );
        // chain_init + 50 events, all in one segment.
        assert_eq!(json_lines(&path).len(), 51);
    }

    fn tempdir() -> std::path::PathBuf {
        // A process-wide counter makes this collision-proof across the parallel
        // `#[tokio::test]`s — nanos alone can repeat when two tests start within
        // the clock's resolution, and a shared dir cross-contaminates line counts.
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "zion-audit-test-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property-based tests: redaction must be idempotent, must preserve the
// pair count, and must never expose the secret value when the key matches.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Idempotence: redacting an already-redacted query string twice
        // produces the same result as redacting it once. (The redactor
        // replaces values, not keys; a second pass re-finds the keys but
        // the values now spell `<redacted:N>` where the *new* N is the
        // length of the literal `<redacted:K>` token from the prior pass.
        // The property we want is structural-stability: pair count and
        // key set are preserved across passes.)
        #[test]
        fn redact_query_string_preserves_pair_count(
            keys in proptest::collection::vec("[a-z]{1,8}", 0..8),
            redact_set in proptest::collection::vec("[a-z]{1,8}", 0..4),
        ) {
            let r = RedactConfig {
                headers: vec![],
                query_params: redact_set,
            }
            .compile();
            let original = keys
                .iter()
                .enumerate()
                .map(|(i, k)| format!("{k}=value{i}"))
                .collect::<Vec<_>>()
                .join("&");
            let pairs_in = original.split('&').filter(|s| !s.is_empty()).count();
            let redacted = r.redact_query_string(&original);
            let pairs_out = redacted.split('&').filter(|s| !s.is_empty()).count();
            prop_assert_eq!(pairs_in, pairs_out);
        }

        // The redactor must never panic on arbitrary input — it sees client
        // query strings, which are attacker-controlled.
        #[test]
        fn redact_query_string_never_panics(q in ".*") {
            let r = RedactConfig {
                headers: vec![],
                query_params: vec!["secret".into()],
            }
            .compile();
            let _ = r.redact_query_string(&q);
        }

        // For any key in the redact list, the redacted output must NOT
        // contain the secret value as a substring.
        #[test]
        fn redact_drops_secret_values(
            secret in "[a-zA-Z0-9]{16,64}",
        ) {
            let r = RedactConfig {
                headers: vec![],
                query_params: vec!["token".into()],
            }
            .compile();
            let q = format!("foo=bar&token={secret}&baz=qux");
            let out = r.redact_query_string(&q);
            prop_assert!(!out.contains(&*secret), "secret leaked: {out}");
            prop_assert!(out.contains("foo=bar"), "non-redacted pair preserved");
            prop_assert!(out.contains("baz=qux"), "non-redacted pair preserved");
        }

        // Issue #60 acceptance — the access-log path packs configured
        // headers into a JSON object via `redact_header_value` before
        // emission. Property: for any header in the redact list and
        // any value, the rendered JSON never contains the value as a
        // substring. The dispatcher composes this exact JSON via
        // `serde_json::to_string` over a `BTreeMap<&str, String>`, so
        // testing the underlying redaction + serialisation pair is
        // testing the load-bearing assumption.
        #[test]
        fn redacted_header_json_never_contains_secret_value(
            secret in "[a-zA-Z0-9]{16,128}",
            cookie in "[a-zA-Z0-9=]{8,64}",
        ) {
            let r = RedactConfig {
                headers: vec!["authorization".into(), "cookie".into()],
                query_params: vec![],
            }
            .compile();
            let mut pairs: std::collections::BTreeMap<&str, String> = Default::default();
            // Redacted entries.
            pairs.insert(
                "authorization",
                r.redact_header_value("authorization", &format!("Bearer {secret}"))
                    .into_owned(),
            );
            pairs.insert(
                "cookie",
                r.redact_header_value("cookie", &cookie)
                    .into_owned(),
            );
            // Non-redacted entry should pass through unchanged.
            pairs.insert(
                "user-agent",
                r.redact_header_value("user-agent", "Mozilla/5.0")
                    .into_owned(),
            );
            let json = serde_json::to_string(&pairs).expect("BTreeMap<&str, String> serialises");
            prop_assert!(!json.contains(&*secret), "Bearer secret leaked in JSON: {json}");
            prop_assert!(!json.contains(&*cookie), "cookie value leaked in JSON: {json}");
            // Non-redacted header value survives.
            prop_assert!(
                json.contains("Mozilla/5.0"),
                "non-redacted user-agent should pass through; got {json}"
            );
            // Redacted token shape.
            prop_assert!(
                json.contains("<redacted:"),
                "redacted token marker missing: {json}"
            );
        }

        // HMAC chain integrity: signing the same event twice with the same
        // key + prev_hash yields the same hmac. Determinism is the load-
        // bearing assumption every external verifier relies on.
        #[test]
        fn hmac_signing_is_deterministic(
            seq in 0u64..=u64::MAX,
            detail in "[ -~]{0,64}",
        ) {
            let key = hmac::Key::new(hmac::HMAC_SHA256, b"this-is-a-32-byte-test-secret!ab");
            let prev = genesis_hash(&key);
            let event = AuditEvent {
                seq,
                ts: "2026-05-05T08:00:00.000000Z".into(),
                kind: "test",
                trace_id: None,
                remote_ip: None,
                method: None,
                path: None,
                detail: Some(detail),
            };
            let (s1, _) = sign_event(&key, event.clone(), prev.clone()).unwrap();
            let (s2, _) = sign_event(&key, event, prev).unwrap();
            prop_assert_eq!(s1.hmac, s2.hmac);
        }
    }
}
