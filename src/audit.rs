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
    /// so the on-disk ceiling is `max_size_mb * (max_files + 1)`. Only the
    /// writer's own segments (`<log>.<nanoseconds>`) count and are deleted; a
    /// file you keep next to the log (`audit.log.verified`, `audit.log.1.gz`)
    /// is never touched. A delete that fails is logged and counted in
    /// `zion_audit_prune_failures_total`.
    #[serde(default = "default_max_files")]
    pub max_files: usize,
    /// How often (milliseconds) the active segment is `fsync`ed. Each record is
    /// flushed to the OS page cache as it is written, which survives `kill -9`
    /// but not a power loss or kernel crash; this bounds how much a power loss
    /// can take: at most the records of the last interval. `0` disables the
    /// periodic sync (the pre-fix behaviour: page cache only). Default 1000. A
    /// segment is always synced before it is sealed at rotation, and the
    /// directory is synced after the rename, regardless of this setting.
    #[serde(default = "default_sync_interval_ms")]
    pub sync_interval_ms: u64,
    /// Label for the HMAC key, written into every `chain_init`/`chain_rotate`
    /// marker (`key_id=...`) so a verifier knows which key signed a chain. Change
    /// it whenever the key changes. Default: a short fingerprint derived from the
    /// key (it reveals nothing about the key itself). 1-64 chars of
    /// `[A-Za-z0-9._-]`.
    pub key_id: Option<String>,
    /// Env var holding the *previous* HMAC key during a rotation. It is never used
    /// to sign; it lets the writer check the tail of a segment written under the
    /// old key (so `prev_head` stays verified across the rotation) and gives the
    /// operator one place to keep the outgoing key while old segments are
    /// verified. Optional.
    pub previous_key_env: Option<String>,
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

fn default_sync_interval_ms() -> u64 {
    1000
}

/// How a client IP address is written to the access log and the audit trail
/// (`[redact] ip`). The default writes it as is.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpPrivacy {
    /// The address as is.
    #[default]
    Full,
    /// The network only: `203.0.113.0/24` (IPv4) or `2001:db8:1::/48` (IPv6). Not reversible, and
    /// not correlatable below the network.
    Truncate,
    /// A keyed, irreversible token (`ip:` + 16 hex of HMAC-SHA256 under `ip_hmac_key`). The same
    /// address always gives the same token, so a client can still be followed across the logs
    /// without being identifiable from them; without the key the token cannot be tied back to an
    /// address.
    Hmac,
}

/// `[redact]` block. Lists are case-insensitive. Empty = no redaction.
#[derive(Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RedactConfig {
    /// HTTP header names whose value should be replaced with `<redacted:N>`.
    /// Compared lowercase per RFC 9110 §5.1 (header names are case-insensitive).
    pub headers: Vec<String>,
    /// Query-parameter names whose value should be redacted.
    pub query_params: Vec<String>,
    /// How client IPs are written to the access log, the audit trail and connection-error logs
    /// (default `full`; see [`IpPrivacy`]). Applied at start-up.
    pub ip: IpPrivacy,
    /// Secret for `ip = "hmac"` (at least 16 bytes). Deprecated in favour of
    /// `ip_hmac_key_env`: a literal ends up wherever `zion.toml` goes (version control,
    /// config management, backups), and with the key every logged token can be reversed by
    /// enumerating the IPv4 space.
    pub ip_hmac_key: Option<String>,
    /// Name of the environment variable holding the secret for `ip = "hmac"`. Preferred over
    /// the literal `ip_hmac_key`; set one or the other.
    pub ip_hmac_key_env: Option<String>,
}

impl std::fmt::Debug for RedactConfig {
    // by hand: the HMAC key must never reach a debug print
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactConfig")
            .field("headers", &self.headers)
            .field("query_params", &self.query_params)
            .field("ip", &self.ip)
            .field("ip_hmac_key", &self.ip_hmac_key.as_ref().map(|_| "<set>"))
            .field("ip_hmac_key_env", &self.ip_hmac_key_env)
            .finish()
    }
}

/// Shortest accepted `ip_hmac_key`.
pub const MIN_IP_HMAC_KEY_BYTES: usize = 16;

impl RedactConfig {
    /// Problems that make this block unusable, for config validation.
    pub fn errors(&self) -> Vec<String> {
        let mut e = Vec::new();
        if self.ip_hmac_key.is_some() && self.ip_hmac_key_env.is_some() {
            e.push(
                "redact.ip_hmac_key and redact.ip_hmac_key_env are both set: keep \
                 ip_hmac_key_env and remove the literal"
                    .to_string(),
            );
            return e;
        }
        let configured = self.ip_hmac_key.is_some() || self.ip_hmac_key_env.is_some();
        match (self.ip, self.resolve_ip_hmac_key()) {
            (IpPrivacy::Full | IpPrivacy::Truncate, _) if configured => e.push(
                "redact.ip_hmac_key / ip_hmac_key_env is only used with redact.ip = \"hmac\""
                    .to_string(),
            ),
            (IpPrivacy::Hmac, Err(problem)) => e.push(problem),
            (IpPrivacy::Hmac, Ok(None)) => e.push(
                "redact.ip = \"hmac\" needs redact.ip_hmac_key_env (or redact.ip_hmac_key)"
                    .to_string(),
            ),
            (IpPrivacy::Hmac, Ok(Some(k))) if k.len() < MIN_IP_HMAC_KEY_BYTES => {
                let which = if self.ip_hmac_key_env.is_some() {
                    "the value of redact.ip_hmac_key_env"
                } else {
                    "redact.ip_hmac_key"
                };
                e.push(format!(
                    "{which} must be at least {MIN_IP_HMAC_KEY_BYTES} bytes"
                ));
            }
            _ => {}
        }
        e
    }

    /// The key for `ip = "hmac"`: from the environment variable `ip_hmac_key_env` names, else
    /// the literal. `Err` when the variable is named but unset or empty (the message names
    /// the variable, never a value).
    fn resolve_ip_hmac_key(&self) -> Result<Option<String>, String> {
        match &self.ip_hmac_key_env {
            Some(var) => match std::env::var(var) {
                Ok(v) if !v.is_empty() => Ok(Some(v)),
                _ => Err(format!(
                    "redact.ip_hmac_key_env names {var}, which is not set (or empty)"
                )),
            },
            None => Ok(self.ip_hmac_key.clone()),
        }
    }
}

impl RedactConfig {
    /// Build a fast-lookup compiled set. Called once at config-load time.
    pub fn compile(&self) -> CompiledRedaction {
        CompiledRedaction {
            ip: self.ip,
            ip_key: self
                .resolve_ip_hmac_key()
                .ok()
                .flatten()
                .filter(|k| k.len() >= MIN_IP_HMAC_KEY_BYTES)
                .map(|k| hmac::Key::new(hmac::HMAC_SHA256, k.as_bytes())),
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
    ip: IpPrivacy,
    ip_key: Option<hmac::Key>,
}

/// A client address as it is to be logged (see [`CompiledRedaction::ip_label`]).
pub enum IpLabel {
    /// Written as is (no allocation).
    Full(std::net::IpAddr),
    Text(String),
}

impl std::fmt::Display for IpLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(ip) => ip.fmt(f),
            Self::Text(s) => f.write_str(s),
        }
    }
}

/// `203.0.113.0/24` / `2001:db8:1::/48`. An IPv4-mapped IPv6 address counts as IPv4.
fn truncate_ip(ip: std::net::IpAddr) -> String {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

impl CompiledRedaction {
    /// How `ip` is to be written to a log or an audit record under `[redact] ip`. `hmac` with no
    /// usable key (validation refuses that) degrades to `truncate`, never to the raw address.
    pub fn ip_label(&self, ip: std::net::IpAddr) -> IpLabel {
        match (self.ip, &self.ip_key) {
            (IpPrivacy::Full, _) => IpLabel::Full(ip),
            (IpPrivacy::Hmac, Some(key)) => {
                let tag = match ip.to_canonical() {
                    std::net::IpAddr::V4(v4) => hmac::sign(key, &v4.octets()),
                    std::net::IpAddr::V6(v6) => hmac::sign(key, &v6.octets()),
                };
                let mut s = String::with_capacity(19);
                s.push_str("ip:");
                for b in &tag.as_ref()[..8] {
                    s.push_str(&format!("{b:02x}"));
                }
                IpLabel::Text(s)
            }
            _ => IpLabel::Text(truncate_ip(ip)),
        }
    }

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

    /// A handle whose events can be read back, for tests of what the pipeline records.
    #[cfg(test)]
    pub fn capture() -> (Self, tokio::sync::mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        (Self { inner: Some(tx) }, rx)
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
            // Queue full: back-pressure. The writer is alive and will catch up.
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                observability::AUDIT_EVENTS_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
                false
            }
            // Channel closed: the writer has exited (disk full, fd revoked, or
            // shutdown). Every later event is lost, which is a different failure
            // from back-pressure and must not look like one. The drop is still
            // counted; `zion_audit_writer_up == 0` is the explicit signal, and
            // we log once so it is not only inferable from a rising counter.
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                observability::AUDIT_EVENTS_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
                if !WRITER_DEAD_LOGGED.swap(true, Ordering::Relaxed) {
                    crate::logging::error(
                        "audit",
                        "audit writer is not running — every audit event is being dropped (see zion_audit_writer_up)",
                    );
                }
                false
            }
        }
    }
}

/// Logged once when the writer is found dead; see [`AuditHandle::emit`].
static WRITER_DEAD_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Smallest accepted HMAC key: the SHA-256 output length (RFC 2104 §3). A shorter
/// key is guessable, and with it an attacker who can write the log can forge a
/// valid chain.
const MIN_KEY_BYTES: usize = 32;

/// Owner of the running writer task. Keep it for the life of the process and call
/// [`AuditWriter::shutdown`] on the way out: the queue can hold thousands of
/// events, and without an explicit stop the runtime is dropped and the task
/// aborted before it drains them.
pub struct AuditWriter {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl AuditWriter {
    /// Stop accepting events, let the writer drain everything already queued,
    /// flush and fsync, then wait for it to exit — at most `timeout`. Returns
    /// `true` if it finished in time.
    pub async fn shutdown(mut self, timeout: std::time::Duration) -> bool {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        tokio::time::timeout(timeout, &mut self.join).await.is_ok()
    }
}

/// Load an HMAC key from `env_name`. `Ok(None)` if the variable is unset or
/// empty; the bytes are wiped from our copy on drop.
fn load_key_bytes(env_name: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    match std::env::var(env_name) {
        Ok(s) if !s.is_empty() => Some(zeroize::Zeroizing::new(s.into_bytes())),
        _ => None,
    }
}

/// Default `key_id`: a short fingerprint derived from the key. It is an HMAC of a
/// fixed label under the key, so it identifies the key without revealing it.
fn derive_key_id(key: &hmac::Key) -> String {
    let tag = hmac::sign(key, b"ZION-AUDIT-KEY-ID-V1");
    hex_encode(&tag.as_ref()[..8])
}

/// Spawn the audit writer. Returns the handle the rest of the system clones into
/// `AppState`, and the [`AuditWriter`] to shut down on exit. `(noop, None)` when
/// `cfg.enabled` is `false`.
///
/// When audit IS enabled, a missing path, a missing/empty key, or a key shorter
/// than 32 bytes is an `Err`: the operator asked for a tamper-evident trail, and
/// booting without one because of a typo in `key_env` or a missing secret mount
/// would silently remove it. The caller refuses to start.
pub fn spawn_writer(cfg: &AuditConfig) -> Result<(AuditHandle, Option<AuditWriter>), String> {
    if !cfg.enabled {
        return Ok((AuditHandle::noop(), None));
    }

    let path = cfg
        .path
        .clone()
        .ok_or("[audit] enabled = true but audit.path is not set")?;

    let key_bytes = load_key_bytes(&cfg.key_env).ok_or_else(|| {
        format!(
            "[audit] enabled = true but env var {} is empty or unset — refusing to start without the audit HMAC key",
            cfg.key_env
        )
    })?;
    if key_bytes.len() < MIN_KEY_BYTES {
        return Err(format!(
            "[audit] HMAC key in {} is {} bytes; the minimum is {MIN_KEY_BYTES} (HMAC-SHA256 output size)",
            cfg.key_env,
            key_bytes.len()
        ));
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);

    let key_id = match cfg.key_id.as_deref() {
        Some(id) => {
            let ok = !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
            if !ok {
                return Err(format!(
                    "[audit] key_id {id:?} must be 1-64 characters of [A-Za-z0-9._-]"
                ));
            }
            id.to_string()
        }
        None => derive_key_id(&key),
    };

    // Optional previous key (rotation overlap). Absent/short is a warning, not an
    // error: the current key is what signs, and `prev_head` simply reads
    // `unverified` across the rotation.
    let previous_key = cfg.previous_key_env.as_deref().and_then(|env| {
        match load_key_bytes(env) {
            Some(b) if b.len() >= MIN_KEY_BYTES => Some(hmac::Key::new(hmac::HMAC_SHA256, &b)),
            Some(b) => {
                crate::logging::warn(
                    "audit",
                    &format!("audit previous key in {env} is {} bytes (< {MIN_KEY_BYTES}) — ignoring it", b.len()),
                );
                None
            }
            None => {
                crate::logging::warn(
                    "audit",
                    &format!("audit previous_key_env {env} is empty/unset — the previous chain cannot be checked across the key rotation"),
                );
                None
            }
        }
    });

    let (tx, rx) = tokio::sync::mpsc::channel::<AuditEvent>(cfg.queue_depth);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    // `max_size_mb = None` or `0` disables rotation (unbounded); otherwise the
    // active segment rotates once it crosses the byte cap.
    let opts = WriterOpts {
        max_size_bytes: cfg
            .max_size_mb
            .filter(|&mb| mb > 0)
            .map(|mb| mb.saturating_mul(1024 * 1024)),
        max_files: cfg.max_files,
        sync_interval: (cfg.sync_interval_ms > 0)
            .then(|| std::time::Duration::from_millis(cfg.sync_interval_ms)),
        key_id,
        previous_key,
    };
    observability::AUDIT_ENABLED.store(1, Ordering::Relaxed);
    let join = tokio::spawn(writer_loop(path, key, rx, stop_rx, opts));

    Ok((
        AuditHandle { inner: Some(tx) },
        Some(AuditWriter {
            stop: Some(stop_tx),
            join,
        }),
    ))
}

/// Everything the writer needs besides the path, key and channels.
struct WriterOpts {
    max_size_bytes: Option<u64>,
    max_files: usize,
    sync_interval: Option<std::time::Duration>,
    key_id: String,
    previous_key: Option<hmac::Key>,
}

/// Marks the writer as down on every exit path, including a panic.
struct WriterUpGuard;
impl WriterUpGuard {
    fn up() -> Self {
        observability::AUDIT_WRITER_UP.store(1, Ordering::Relaxed);
        Self
    }
}
impl Drop for WriterUpGuard {
    fn drop(&mut self) {
        observability::AUDIT_WRITER_UP.store(0, Ordering::Relaxed);
    }
}

fn note_write_failure() {
    observability::AUDIT_WRITE_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
}

fn note_write_ok() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    observability::AUDIT_LAST_WRITE_TIMESTAMP_SECONDS.store(now, Ordering::Relaxed);
}

async fn writer_loop(
    path: String,
    key: hmac::Key,
    mut rx: tokio::sync::mpsc::Receiver<AuditEvent>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    opts: WriterOpts,
) {
    use tokio::io::AsyncWriteExt;

    let WriterOpts {
        max_size_bytes,
        max_files,
        sync_interval,
        key_id,
        previous_key,
    } = opts;

    // Open the initial segment and anchor the chain. Mirrors the process-restart
    // model: a fresh chain from genesis + a boundary marker. The marker records
    // the verified head of any chain already on disk (`prev_head=`), so a
    // verifier can check continuity without the writer trusting the tail.
    let Some((mut file, mut prev_hash, mut bytes_written)) = open_and_anchor(
        &path,
        &key,
        previous_key.as_ref(),
        &key_id,
        "chain_init",
        "audit chain initialized at process start",
    )
    .await
    else {
        note_write_failure();
        return; // fatal open error already logged
    };
    // From here until this task ends the writer counts as up (also on panic).
    let _up = WriterUpGuard::up();

    let mut seq: u64 = 1;
    // Tracks whether flush is currently failing, so we log the degraded↔healthy
    // transition once instead of per-event.
    let mut flush_degraded = false;
    // Once rotation becomes impossible (rename keeps failing), stop attempting
    // it so the writer degrades instead of spinning (re-anchor → still over cap
    // → rename fails → repeat).
    let mut rotation_disabled = max_size_bytes.is_none();
    // Distinct from `rotation_disabled`: true only when rotation was CONFIGURED
    // but FAILED at runtime. In that state we cap the segment by shedding
    // (drop + count) events that would push it past `max_size_bytes`, rather
    // than growing the file without bound — a rotation the operator asked for
    // silently becoming an unbounded disk-fill is worse than a counted drop.
    // (When rotation is off by config, `max_size_bytes` is None and this stays
    // false, so an opt-out deployment keeps its intended unbounded behaviour.)
    let mut rotation_broken = false;
    let mut shed_logged = false;
    // Durability (ZION-DATA-01): `dirty` = records flushed to the OS page cache
    // but not yet fsynced; `last_sync` anchors the interval. A power loss can
    // then take at most `sync_interval` of records instead of an unbounded tail.
    let mut dirty = false;
    let mut last_sync = std::time::Instant::now();
    let mut sync_degraded = false;

    // Set once `AuditWriter::shutdown` fires: the queue is closed to new events
    // but everything already in it is still written before the task exits.
    let mut stopping = false;

    enum Wake {
        Event(Option<AuditEvent>),
        SyncDue,
        Stop,
    }

    loop {
        if let Some(iv) = sync_interval {
            if dirty && last_sync.elapsed() >= iv {
                sync_active(&mut file, &mut sync_degraded).await;
                dirty = false;
                last_sync = std::time::Instant::now();
            }
        }
        // While records are unsynced, wake at the sync deadline even if no event
        // arrives, so an idle log still reaches stable storage.
        let wait = match (dirty, sync_interval) {
            (true, Some(iv)) => Some(iv.saturating_sub(last_sync.elapsed())),
            _ => None,
        };
        let wake = tokio::select! {
            biased;
            // A dropped sender counts as a stop too.
            _ = &mut stop, if !stopping => Wake::Stop,
            w = async {
                match wait {
                    Some(w) => match tokio::time::timeout(w, rx.recv()).await {
                        Ok(ev) => Wake::Event(ev),
                        Err(_) => Wake::SyncDue,
                    },
                    None => Wake::Event(rx.recv().await),
                }
            } => w,
        };
        let mut event = match wake {
            Wake::Stop => {
                rx.close(); // no new events; queued ones still drain via recv()
                stopping = true;
                continue;
            }
            Wake::SyncDue => continue,  // the check above syncs
            Wake::Event(None) => break, // closed and drained
            Wake::Event(Some(e)) => e,
        };
        // Shed when a configured rotation has broken and the segment is already
        // at/over its cap: drop the event (counted) instead of appending and
        // growing the file without bound. Self-heals only on restart — the
        // failure is logged prominently below.
        if rotation_broken {
            if let Some(max) = max_size_bytes {
                if bytes_written >= max {
                    observability::AUDIT_EVENTS_DROPPED_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if !shed_logged {
                        crate::logging::error(
                            "audit",
                            "audit log rotation is broken and the segment is at its size cap — shedding (dropping + counting) further events to avoid an unbounded disk-fill; fix the directory permissions/disk and restart",
                        );
                        shed_logged = true;
                    }
                    continue;
                }
            }
        }
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
                        note_write_failure();
                        crate::logging::error(
                            "audit",
                            "audit log write failed — buffer cannot accept data (disk full / fd revoked), exiting writer",
                        );
                        break;
                    }
                    prev_hash = new_prev;
                    seq += 1;
                    bytes_written += line.len() as u64;
                    // Flush each event to the OS page cache. That survives a
                    // process kill -9 (the kernel keeps the bytes) but not a
                    // power loss or kernel crash, so the periodic `sync_active`
                    // above bounds the exposure to `sync_interval` (and rotation
                    // always syncs before sealing). A flush failure (transient
                    // ENOSPC, slow network FS) does NOT kill the writer: the
                    // record stays buffered and a later flush retries it, so
                    // audit self-heals once the disk recovers. Log the
                    // degraded↔healthy transition once.
                    match file.flush().await {
                        Ok(()) => {
                            dirty = true;
                            note_write_ok();
                            if flush_degraded {
                                crate::logging::warn(
                                    "audit",
                                    "audit log flush recovered — durability restored",
                                );
                                flush_degraded = false;
                            }
                        }
                        Err(e) => {
                            note_write_failure();
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
                    // Flush the outgoing segment before sealing it. Unlike the
                    // steady-state flush (which keeps records buffered and
                    // retries), we are about to rename this file away, so a
                    // failed flush here means buffered records are lost with the
                    // old segment — surface it instead of discarding the error.
                    if let Err(e) = file.flush().await {
                        crate::logging::warn(
                            "audit",
                            &format!("audit log flush before rotation failed ({e}) — buffered records in the outgoing segment may be lost"),
                        );
                    }
                    // The outgoing segment is about to be renamed away for good,
                    // so make it durable first — independent of `sync_interval`.
                    if let Err(e) = file.get_ref().sync_data().await {
                        crate::logging::warn(
                            "audit",
                            &format!("audit log fsync before rotation failed ({e}) — the sealed segment may not survive a power loss"),
                        );
                    }
                    dirty = false;
                    last_sync = std::time::Instant::now();
                    let _ = file.shutdown().await; // best-effort close of the outgoing fd
                    match rotate_paths(&path, max_files).await {
                        Ok(rotated_to) => match open_and_anchor(
                            &path,
                            &key,
                            previous_key.as_ref(),
                            &key_id,
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
                                previous_key.as_ref(),
                                &key_id,
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
                            rotation_broken = true;
                        }
                    }
                }
            }
        }
    }
    if file.flush().await.is_err() {
        crate::logging::warn("audit", "final audit log flush failed on writer shutdown");
    } else if dirty {
        sync_active(&mut file, &mut sync_degraded).await;
    }
}

/// Flush and `fsync` the active segment so its records reach stable storage.
/// Best-effort: a failure is logged once per degraded stretch and the writer
/// keeps going (the records stay in the page cache, as before this existed).
async fn sync_active(file: &mut tokio::io::BufWriter<tokio::fs::File>, degraded: &mut bool) {
    use tokio::io::AsyncWriteExt;
    let res = match file.flush().await {
        Ok(()) => file.get_ref().sync_data().await,
        Err(e) => Err(e),
    };
    match res {
        Ok(()) => {
            if *degraded {
                crate::logging::warn("audit", "audit log fsync recovered — durability restored");
                *degraded = false;
            }
        }
        Err(e) => {
            note_write_failure();
            if !*degraded {
                crate::logging::error(
                    "audit",
                    &format!("audit log fsync failing ({e}) — records are in the page cache but not durable against power loss"),
                );
                *degraded = true;
            }
        }
    }
}

/// Best-effort `fsync` of `path`'s parent directory so a `rename` into it
/// survives power loss. A filesystem that refuses to sync a directory handle must
/// not fail an otherwise-successful rotation.
async fn fsync_parent_dir(path: &str) {
    let dir = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    if let Ok(f) = tokio::fs::File::open(dir).await {
        let _ = f.sync_all().await;
    }
}

/// What the tail of an existing segment says about the chain written before this
/// open (ZION-DATA-04).
#[derive(Debug, PartialEq, Eq)]
enum PrevHead {
    /// New or empty segment: nothing precedes this anchor.
    Empty,
    /// The last record is well-formed and its HMAC verifies under our key.
    Verified {
        hmac: String,
        seq: u64,
        /// True when it verified under the previous (rotated-out) key.
        previous_key: bool,
    },
    /// The segment has content but its last line is not a valid signed record:
    /// a torn write, tampering, or a different HMAC key.
    Unverified,
}

/// How much of the segment's end is read to find its last record. Records are a
/// few hundred bytes; a line that does not fit is treated as unverifiable.
const TAIL_WINDOW: u64 = 64 * 1024;

/// Judge the last record in `tail` (the final bytes of a segment). Pure, so it is
/// unit-tested without a filesystem. `at_file_start` says whether `tail` begins at
/// byte 0 — if not, a first line without a preceding newline may be cut off.
fn verify_tail(
    key: &hmac::Key,
    prev_key: Option<&hmac::Key>,
    tail: &[u8],
    at_file_start: bool,
) -> PrevHead {
    match verify_tail_with(key, tail, at_file_start) {
        PrevHead::Unverified => match prev_key {
            Some(pk) => match verify_tail_with(pk, tail, at_file_start) {
                PrevHead::Verified { hmac, seq, .. } => PrevHead::Verified {
                    hmac,
                    seq,
                    previous_key: true,
                },
                other => other,
            },
            None => PrevHead::Unverified,
        },
        other => other,
    }
}

fn verify_tail_with(key: &hmac::Key, tail: &[u8], at_file_start: bool) -> PrevHead {
    if tail.is_empty() {
        return PrevHead::Empty;
    }
    // Every record is written as one line ending in `\n`; a tail that does not end
    // in one was cut mid-write.
    if tail.last() != Some(&b'\n') {
        return PrevHead::Unverified;
    }
    let Ok(text) = std::str::from_utf8(tail) else {
        return PrevHead::Unverified;
    };
    let body = text.trim_end_matches('\n');
    let (line, complete) = match body.rfind('\n') {
        Some(i) => (&body[i + 1..], true),
        None => (body, at_file_start), // no newline before it: complete only from byte 0
    };
    if !complete || line.is_empty() {
        return PrevHead::Unverified;
    }
    // Records serialize as `{<event fields>,"prev_hash":"..","hmac":".."}`, so the
    // signed canonical JSON is everything before `,"prev_hash"` plus a `}`.
    let Some(split) = line.rfind(",\"prev_hash\":\"") else {
        return PrevHead::Unverified;
    };
    let event_json = format!("{}}}", &line[..split]);
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return PrevHead::Unverified;
    };
    let (Some(prev), Some(mac), Some(seq)) = (
        v["prev_hash"].as_str(),
        v["hmac"].as_str(),
        v["seq"].as_u64(),
    ) else {
        return PrevHead::Unverified;
    };
    let expected = compute_hmac(key, &event_json, prev);
    if aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_bytes(), mac.as_bytes())
        .is_ok()
    {
        PrevHead::Verified {
            hmac: mac.to_string(),
            seq,
            previous_key: false,
        }
    } else {
        PrevHead::Unverified
    }
}

/// Read the last [`TAIL_WINDOW`] bytes of `file` and judge them. The bool is
/// true when the segment ends mid-line (no trailing `\n`), so the caller can
/// terminate that fragment before appending the next record to it.
async fn read_prev_head(
    file: &mut tokio::fs::File,
    len: u64,
    key: &hmac::Key,
    prev_key: Option<&hmac::Key>,
) -> (PrevHead, bool) {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if len == 0 {
        return (PrevHead::Empty, false);
    }
    let start = len.saturating_sub(TAIL_WINDOW);
    let mut buf = vec![0u8; (len - start) as usize];
    if file.seek(std::io::SeekFrom::Start(start)).await.is_err()
        || file.read_exact(&mut buf).await.is_err()
    {
        return (PrevHead::Unverified, false);
    }
    let torn = buf.last() != Some(&b'\n');
    (verify_tail(key, prev_key, &buf, start == 0), torn)
}

/// Open (create + append) the segment at `path` and write a re-anchor marker so
/// verifiers see the boundary. The new chain still starts at genesis (each
/// segment verifies independently, ADR-0017), but the signed marker records the
/// verified head of whatever chain already sits at the end of the file
/// (`prev_head=<hmac>; prev_seq=<n>`, or `none` / `unverified`). A verifier can
/// therefore check that the previous chain ends where the marker says it does,
/// which makes a truncated or removed tail detectable across restarts — without
/// this writer ever *continuing* a chain from an unverified value. Returns
/// `(writer, chain_head_hash, current_segment_bytes)`, or `None` on a fatal open
/// error (already logged). If the marker itself can't be written, the writer is
/// still returned with the chain head at genesis (the pre-rotation degraded
/// behaviour).
async fn open_and_anchor(
    path: &str,
    key: &hmac::Key,
    prev_key: Option<&hmac::Key>,
    key_id: &str,
    kind: &'static str,
    context: &str,
) -> Option<(tokio::io::BufWriter<tokio::fs::File>, String, u64)> {
    use tokio::io::AsyncWriteExt;

    let mut file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true) // to inspect the existing tail; writes still append
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
    let (prev, torn_tail) = read_prev_head(&mut file, existing, key, prev_key).await;
    let prev_note = match &prev {
        PrevHead::Empty => "prev_head=none".to_string(),
        PrevHead::Verified {
            hmac,
            seq,
            previous_key: false,
        } => format!("prev_head={hmac}; prev_seq={seq}"),
        // Signed under the outgoing key: still verified, and a verifier is told which key to use.
        PrevHead::Verified {
            hmac,
            seq,
            previous_key: true,
        } => format!("prev_head={hmac}; prev_seq={seq}; prev_key=previous"),
        PrevHead::Unverified => {
            crate::logging::warn(
                "audit",
                &format!("audit log {path}: the last record is not a valid signed record (torn write, tampering, or a different HMAC key) — anchoring a fresh chain and recording prev_head=unverified"),
            );
            "prev_head=unverified".to_string()
        }
    };
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
        detail: Some(format!(
            "{context}; genesis={}; key_id={key_id}; {prev_note}",
            &genesis[..16]
        )),
    };
    let mut head = genesis.clone();
    let mut bytes = existing;
    if let Ok((signed, new_prev)) = sign_event(key, init, genesis) {
        if let Ok(mut line) = serde_json::to_string(&signed) {
            line.push('\n'); // one all-or-nothing record write (no orphaned line)
            if torn_tail {
                // The previous run died mid-record. Terminate that fragment so the
                // marker starts on its own line and stays parseable.
                line.insert(0, '\n');
            }
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
    // Make the rename itself durable, not just the file's contents.
    fsync_parent_dir(path).await;
    prune_old_segments(path, max_files).await;
    Ok(rotated)
}

/// True when `name` is a segment this writer produced from `base`: `<base>.<nanos>`
/// or, after a same-instant collision, `<base>.<nanos>.<n>` (see `rotate_paths`).
/// Anything else next to the log (`audit.log.verified`, `audit.log.1.gz`, an
/// operator's export) is not ours to count or delete.
fn is_own_segment(base: &str, name: &str) -> bool {
    let Some(suffix) = name
        .strip_prefix(base)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match suffix.split_once('.') {
        None => digits(suffix),
        Some((stamp, n)) => digits(stamp) && digits(n),
    }
}

/// Delete the oldest rotated segments so at most `max_files` remain (`0` keeps
/// them all). Only the writer's own segments count (`is_own_segment`); ordering
/// is by modification time. A failed delete never stops the writer (retention is
/// best-effort, never a reason to drop an audit event) but it is not silent: it is
/// logged and counted, because a retention bound that stops holding ends with a
/// full disk.
async fn prune_old_segments(path: &str, max_files: usize) {
    if max_files == 0 {
        return;
    }
    let p = std::path::Path::new(path);
    let (dir, base) = match (p.parent(), p.file_name().and_then(|n| n.to_str())) {
        (Some(d), Some(b)) => (d.to_path_buf(), b.to_string()),
        _ => return,
    };
    let mut rd = match tokio::fs::read_dir(&dir).await {
        Ok(r) => r,
        Err(e) => {
            prune_failed(&dir, &e);
            return;
        }
    };
    let mut segments: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name();
        if !is_own_segment(&base, &name.to_string_lossy()) {
            continue;
        }
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        segments.push((
            meta.modified().unwrap_or(std::time::UNIX_EPOCH),
            entry.path(),
        ));
    }
    if segments.len() <= max_files {
        return;
    }
    segments.sort_by_key(|(t, _)| *t); // oldest first
    let remove_n = segments.len() - max_files;
    for (_, seg) in segments.into_iter().take(remove_n) {
        if let Err(e) = tokio::fs::remove_file(&seg).await {
            prune_failed(&seg, &e);
        }
    }
}

fn prune_failed(what: &std::path::Path, e: &std::io::Error) {
    observability::AUDIT_PRUNE_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
    crate::logging::warn(
        "audit",
        &format!(
            "cannot prune rotated audit segment {}: {e} — [audit] max_files is not being enforced and segments will accumulate",
            what.display()
        ),
    );
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
// 4b. Offline verification — `zion audit verify`.
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of verifying one audit segment.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifyReport {
    /// Signed records checked.
    pub records: u64,
    /// Chains found: one per `chain_init` / `chain_rotate` marker (process start,
    /// rotation), each re-anchored at genesis.
    pub chains: u64,
    /// The final line had no newline: a write cut short (crash, `kill -9`) or an
    /// end-truncation. It is not counted in `records`.
    pub torn_tail: bool,
}

/// Verify a whole segment: every record's HMAC, and that each record's `prev_hash`
/// is the previous record's HMAC. A chain starts at a `chain_init` /
/// `chain_rotate` marker whose `prev_hash` is the genesis tag; the marker may be
/// signed by any of `keys` (a rotation switches key at a marker). Returns the
/// 1-based line number and reason of the first record that does not verify.
///
/// This detects a modified, reordered or deleted record in the MIDDLE of a chain.
/// It cannot detect removal of the END of a chain (nothing after it commits to it);
/// that is what the `prev_head=` value in the next marker is for.
pub fn verify_log(text: &str, keys: &[hmac::Key]) -> Result<VerifyReport, (usize, String)> {
    let torn_tail = !text.is_empty() && !text.ends_with('\n');
    let complete = if torn_tail {
        text.rfind('\n').map_or("", |i| &text[..=i])
    } else {
        text
    };
    let mut report = VerifyReport {
        records: 0,
        chains: 0,
        torn_tail,
    };
    // (key index, hmac of the previous record) of the chain being walked.
    let mut chain: Option<(usize, String)> = None;
    for (i, line) in complete.lines().enumerate() {
        let n = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        let bad = |why: &str| (n, why.to_string());
        let v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| bad(&format!("not valid JSON: {e}")))?;
        let (Some(prev), Some(mac), Some(kind)) = (
            v["prev_hash"].as_str(),
            v["hmac"].as_str(),
            v["kind"].as_str(),
        ) else {
            return Err(bad("missing kind / prev_hash / hmac"));
        };
        let split = line
            .rfind(",\"prev_hash\":\"")
            .ok_or_else(|| bad("no prev_hash field"))?;
        let event_json = format!("{}}}", &line[..split]);
        let is_marker = kind == "chain_init" || kind == "chain_rotate";
        let key_idx = if is_marker {
            // a new chain: must start at genesis under one of the known keys
            let found = keys.iter().position(|k| prev == genesis_hash(k));
            let Some(idx) = found else {
                return Err(bad(
                    "chain marker does not start at genesis under any supplied key \
                     (wrong key, or the file was edited)",
                ));
            };
            report.chains += 1;
            idx
        } else {
            let Some((idx, ref head)) = chain else {
                return Err(bad("record before any chain_init / chain_rotate marker"));
            };
            if prev != head {
                return Err(bad(
                    "prev_hash does not match the previous record (a record was removed, \
                     reordered or altered)",
                ));
            }
            idx
        };
        let expected = compute_hmac(&keys[key_idx], &event_json, prev);
        if aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_bytes(), mac.as_bytes())
            .is_err()
        {
            return Err(bad(
                "HMAC mismatch (record altered, or signed by another key)",
            ));
        }
        chain = Some((key_idx, mac.to_string()));
        report.records += 1;
    }
    Ok(report)
}

const VERIFY_USAGE: &str =
    "usage: zion audit verify [--key-env VAR] [--previous-key-env VAR] <segment>...\n\
  Verifies the HMAC chain of one or more audit segments (each verifies independently).\n\
  --key-env           env var holding the HMAC key (default ZION_AUDIT_HMAC_KEY)\n\
  --previous-key-env  env var holding an outgoing key, for segments that predate a rotation\n\
  exit: 0 all verified, 1 a segment failed, 2 usage / key error";

/// `zion audit verify …`: returns the process exit code.
pub fn run_cli(args: &[String]) -> i32 {
    if args.first().map(String::as_str) != Some("verify") {
        eprintln!("{VERIFY_USAGE}");
        return 2;
    }
    let mut key_env = "ZION_AUDIT_HMAC_KEY".to_string();
    let mut prev_env: Option<String> = None;
    let mut files: Vec<&String> = Vec::new();
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key-env" => match it.next() {
                Some(v) => key_env = v.clone(),
                None => {
                    eprintln!("{VERIFY_USAGE}");
                    return 2;
                }
            },
            "--previous-key-env" => match it.next() {
                Some(v) => prev_env = Some(v.clone()),
                None => {
                    eprintln!("{VERIFY_USAGE}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("{VERIFY_USAGE}");
                return 0;
            }
            _ => files.push(a),
        }
    }
    if files.is_empty() {
        eprintln!("{VERIFY_USAGE}");
        return 2;
    }
    let mut keys = Vec::new();
    for name in std::iter::once(&key_env).chain(prev_env.as_ref()) {
        match load_key_bytes(name) {
            Some(b) if b.len() >= MIN_KEY_BYTES => keys.push(hmac::Key::new(hmac::HMAC_SHA256, &b)),
            Some(b) => {
                eprintln!("zion audit verify: the key in {name} is {} bytes; the minimum is {MIN_KEY_BYTES}", b.len());
                return 2;
            }
            None => {
                eprintln!("zion audit verify: {name} is unset or empty");
                return 2;
            }
        }
    }
    let mut failed = false;
    for f in files {
        let text = match std::fs::read(f) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                eprintln!("FAIL {f}: cannot read: {e}");
                failed = true;
                continue;
            }
        };
        match verify_log(&text, &keys) {
            Ok(r) => {
                let torn = if r.torn_tail {
                    " (last line has no newline: torn write or truncated end, not counted)"
                } else {
                    ""
                };
                println!(
                    "ok   {f}: {} records, {} chain(s){torn}",
                    r.records, r.chains
                );
            }
            Err((line, why)) => {
                eprintln!("FAIL {f}: line {line}: {why}");
                failed = true;
            }
        }
    }
    i32::from(failed)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Tests.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // ── [redact] ip ────────────────────────────────────────────────────────

    fn redact(ip: IpPrivacy, key: Option<&str>) -> CompiledRedaction {
        RedactConfig {
            ip,
            ip_hmac_key: key.map(str::to_string),
            ..Default::default()
        }
        .compile()
    }
    const KEY: &str = "0123456789abcdef0123456789abcdef";

    /// `ip_hmac_key_env` (ZION-SEC-02): the key comes from the environment, so `zion.toml`
    /// can go to version control without it.
    #[test]
    fn the_hmac_key_can_come_from_the_environment() {
        const VAR: &str = "ZION_TEST_IP_HMAC_KEY_5f21";
        let from_env = |ip| RedactConfig {
            ip,
            ip_hmac_key_env: Some(VAR.to_string()),
            ..Default::default()
        };
        // Named but not set: refused, naming the variable.
        std::env::remove_var(VAR);
        let e = from_env(IpPrivacy::Hmac).errors().join("\n");
        assert!(e.contains(VAR) && e.contains("not set"), "{e}");
        // Too short: refused without showing the value.
        std::env::set_var(VAR, "short-key");
        let e = from_env(IpPrivacy::Hmac).errors().join("\n");
        assert!(
            e.contains("at least 16 bytes") && !e.contains("short-key"),
            "{e}"
        );
        // Set: used, and it gives the token the same key gives as a literal.
        std::env::set_var(VAR, KEY);
        let cfg = from_env(IpPrivacy::Hmac);
        assert!(cfg.errors().is_empty(), "{:?}", cfg.errors());
        let ip = "203.0.113.9".parse().unwrap();
        let token = cfg.compile().ip_label(ip).to_string();
        assert!(token.starts_with("ip:"), "{token}");
        assert_eq!(
            token,
            redact(IpPrivacy::Hmac, Some(KEY)).ip_label(ip).to_string()
        );
        // Both forms at once: one must go.
        let both = RedactConfig {
            ip: IpPrivacy::Hmac,
            ip_hmac_key: Some(KEY.to_string()),
            ip_hmac_key_env: Some(VAR.to_string()),
            ..Default::default()
        };
        assert!(both.errors().join("\n").contains("both set"));
        // A key with nothing to use it.
        let e = from_env(IpPrivacy::Full).errors().join("\n");
        assert!(e.contains("only used with redact.ip = \"hmac\""), "{e}");
        std::env::remove_var(VAR);
        // The debug print names the variable and never a key.
        let shown = format!(
            "{:?}",
            RedactConfig {
                ip: IpPrivacy::Hmac,
                ip_hmac_key: Some(KEY.to_string()),
                ..Default::default()
            }
        );
        assert!(!shown.contains(KEY), "{shown}");
    }

    #[test]
    fn ip_full_is_the_default_and_writes_the_address_as_is() {
        let r = CompiledRedaction::default();
        assert_eq!(
            r.ip_label("203.0.113.9".parse().unwrap()).to_string(),
            "203.0.113.9"
        );
        assert_eq!(
            r.ip_label("2001:db8::1".parse().unwrap()).to_string(),
            "2001:db8::1"
        );
    }

    #[test]
    fn ip_truncate_keeps_only_the_network() {
        let r = redact(IpPrivacy::Truncate, None);
        let t = |s: &str| r.ip_label(s.parse().unwrap()).to_string();
        assert_eq!(t("203.0.113.9"), "203.0.113.0/24");
        assert_eq!(
            t("203.0.113.200"),
            "203.0.113.0/24",
            "same network, same label"
        );
        assert_eq!(t("2001:db8:1:2:3:4:5:6"), "2001:db8:1::/48");
        assert_eq!(
            t("::ffff:203.0.113.9"),
            "203.0.113.0/24",
            "an IPv4-mapped address is IPv4"
        );
        assert!(!t("203.0.113.9").contains(".9"));
    }

    #[test]
    fn ip_hmac_is_stable_keyed_and_not_the_address() {
        let r = redact(IpPrivacy::Hmac, Some(KEY));
        let t = |s: &str| r.ip_label(s.parse().unwrap()).to_string();
        let a = t("203.0.113.9");
        assert!(a.starts_with("ip:") && a.len() == 3 + 16, "{a}");
        assert!(a[3..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(a, t("203.0.113.9"), "the same client gives the same token");
        assert_ne!(a, t("203.0.113.10"), "another client gives another one");
        assert_eq!(
            a,
            t("::ffff:203.0.113.9"),
            "v4 and its mapped form are one client"
        );
        assert!(
            !a.contains("203"),
            "the address does not appear in its token"
        );
        let other = redact(IpPrivacy::Hmac, Some("fedcba9876543210fedcba9876543210"));
        assert_ne!(
            a,
            other.ip_label("203.0.113.9".parse().unwrap()).to_string(),
            "key-dependent"
        );
    }

    #[test]
    fn ip_hmac_without_a_usable_key_never_falls_back_to_the_raw_address() {
        for key in [None, Some("short")] {
            let r = redact(IpPrivacy::Hmac, key);
            let t = r.ip_label("203.0.113.9".parse().unwrap()).to_string();
            assert_eq!(t, "203.0.113.0/24", "degrades to truncate, not to full");
        }
    }

    #[test]
    fn redact_ip_config_is_validated_and_the_key_never_reaches_a_debug_print() {
        let ok = |ip, key: Option<&str>| {
            RedactConfig {
                ip,
                ip_hmac_key: key.map(str::to_string),
                ..Default::default()
            }
            .errors()
        };
        assert!(ok(IpPrivacy::Full, None).is_empty());
        assert!(ok(IpPrivacy::Truncate, None).is_empty());
        assert!(ok(IpPrivacy::Hmac, Some(KEY)).is_empty());
        assert!(ok(IpPrivacy::Hmac, None)[0].contains("needs redact.ip_hmac_key"));
        assert!(ok(IpPrivacy::Hmac, Some("short"))[0].contains("at least 16 bytes"));
        assert!(ok(IpPrivacy::Truncate, Some(KEY))[0].contains("only used with"));
        let dbg = format!(
            "{:?}",
            RedactConfig {
                ip: IpPrivacy::Hmac,
                ip_hmac_key: Some(KEY.into()),
                ..Default::default()
            }
        );
        assert!(!dbg.contains(KEY) && dbg.contains("<set>"), "{dbg}");
        let parsed: RedactConfig = toml::from_str("ip = \"truncate\"").unwrap();
        assert_eq!(parsed.ip, IpPrivacy::Truncate);
        assert!(toml::from_str::<RedactConfig>("ip = \"md5\"").is_err());
    }

    // ── zion audit verify ─────────────────────────────────────────────────────
    fn vkey(b: u8) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &[b; 32])
    }

    /// Build a signed segment: marker + `n` events, chain anchored at genesis.
    fn segment(key: &hmac::Key, marker: &'static str, n: usize) -> String {
        let mut prev = genesis_hash(key);
        let mut out = String::new();
        for i in 0..=n {
            let kind: &'static str = if i == 0 { marker } else { "request_blocked" };
            let ev = AuditEvent {
                seq: i as u64,
                ts: "2026-09-30T00:00:00.000000Z".into(),
                kind,
                trace_id: None,
                remote_ip: None,
                method: None,
                path: None,
                detail: Some(format!("event {i}")),
            };
            let (signed, next) = sign_event(key, ev, prev).unwrap();
            out.push_str(&serde_json::to_string(&signed).unwrap());
            out.push('\n');
            prev = next;
        }
        out
    }

    #[test]
    fn verify_accepts_an_untouched_multi_chain_segment() {
        let k = vkey(1);
        let text = format!(
            "{}{}",
            segment(&k, "chain_init", 5),
            segment(&k, "chain_init", 3)
        );
        let r = verify_log(&text, &[k]).unwrap();
        assert_eq!((r.records, r.chains, r.torn_tail), (10, 2, false));
    }

    #[test]
    fn verify_rejects_an_edited_a_removed_and_a_reordered_record() {
        let k = vkey(1);
        let text = segment(&k, "chain_init", 6);
        let lines: Vec<&str> = text.lines().collect();
        let join = |v: &[&str]| v.join("\n") + "\n";
        // edited content
        let mut edited = lines.clone();
        let changed = edited[3].replace("event 3", "event X");
        edited[3] = &changed;
        assert_eq!(verify_log(&join(&edited), &[vkey(1)]).unwrap_err().0, 4);
        // removed record
        let mut removed = lines.clone();
        removed.remove(3);
        assert_eq!(verify_log(&join(&removed), &[vkey(1)]).unwrap_err().0, 4);
        // reordered
        let mut swapped = lines.clone();
        swapped.swap(2, 3);
        assert_eq!(verify_log(&join(&swapped), &[vkey(1)]).unwrap_err().0, 3);
    }

    #[test]
    fn verify_rejects_the_wrong_key_and_headless_records() {
        let text = segment(&vkey(1), "chain_init", 2);
        assert_eq!(verify_log(&text, &[vkey(2)]).unwrap_err().0, 1);
        let headless: String = text.lines().skip(1).map(|l| format!("{l}\n")).collect();
        let (n, why) = verify_log(&headless, &[vkey(1)]).unwrap_err();
        assert_eq!(n, 1);
        assert!(why.contains("before any"), "{why}");
    }

    #[test]
    fn verify_follows_a_key_rotation_and_flags_a_torn_tail() {
        let (old, new) = (vkey(1), vkey(2));
        let text = format!(
            "{}{}",
            segment(&old, "chain_init", 2),
            segment(&new, "chain_rotate", 2)
        );
        assert_eq!(verify_log(&text, &[vkey(2), vkey(1)]).unwrap().chains, 2);
        // a tail cut mid-record is reported, not treated as forgery of the rest
        let cut = &text[..text.len() - 20];
        let r = verify_log(cut, &[vkey(2), vkey(1)]).unwrap();
        assert!(r.torn_tail);
        assert_eq!(r.records, 5);
    }

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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
    async fn verifier_accepts_what_the_real_writer_wrote_across_a_restart() {
        let dir = tempdir();
        let path = dir.join("audit.log");
        std::env::set_var(
            "ZION_TEST_AUDIT_KEY_VERIFY",
            "this-is-a-32-byte-test-secret!ab",
        );
        let cfg = AuditConfig {
            enabled: true,
            path: Some(path.to_string_lossy().into_owned()),
            key_env: "ZION_TEST_AUDIT_KEY_VERIFY".into(),
            queue_depth: 64,
            ..Default::default()
        };
        for run in 0..2 {
            let (h, w) = spawn_writer(&cfg).expect("writer starts");
            for i in 0..20 {
                assert!(h.emit(AuditEvent {
                    seq: 0,
                    ts: String::new(),
                    kind: "request_blocked",
                    trace_id: None,
                    remote_ip: Some("10.0.0.5".into()),
                    method: Some("GET".into()),
                    path: Some(format!("/run{run}/{i}")),
                    detail: Some("waf".into()),
                }));
            }
            drop(h);
            assert!(
                w.expect("writer")
                    .shutdown(std::time::Duration::from_secs(5))
                    .await
            );
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"this-is-a-32-byte-test-secret!ab");
        let r = verify_log(&text, &[key]).expect("the writer's own output must verify");
        assert_eq!((r.records, r.chains), (42, 2), "2 markers + 40 events");
        // flipping one byte of one record is caught, on the right line
        let tampered = text.replacen("/run1/7", "/run1/8", 1);
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"this-is-a-32-byte-test-secret!ab");
        let (line, _) = verify_log(&tampered, &[key]).unwrap_err();
        assert_eq!(
            line,
            1 + 20 + 1 + 7 + 1,
            "marker, run 0, marker, then run-1 event 7 (line 30)"
        );
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
        let (h, _writer) = spawn_writer(&cfg).expect("writer starts");
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

    // ── Boot policy, key identity, shutdown (ZION-SEC-01/02/04, CONC-01/02) ─

    fn spawn_err(cfg: &AuditConfig) -> String {
        match spawn_writer(cfg) {
            Ok(_) => panic!("spawn_writer was expected to refuse this config"),
            Err(e) => e,
        }
    }

    fn cfg_for(path: &std::path::Path, key_env: &str) -> AuditConfig {
        AuditConfig {
            enabled: true,
            path: Some(path.to_string_lossy().into_owned()),
            key_env: key_env.into(),
            queue_depth: 512,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn enabled_audit_refuses_to_start_without_a_valid_key() {
        let dir = tempdir();
        let path = dir.join("audit.log");

        // disabled: nothing to do, not an error
        let (h, w) = spawn_writer(&AuditConfig::default()).expect("disabled is fine");
        assert!(w.is_none() && !h.emit(make_event(1, "x")));

        // no path
        let mut c = cfg_for(&path, "ZION_TEST_SEC01_A");
        c.path = None;
        assert!(spawn_err(&c).contains("audit.path"));

        // key env unset -> error naming the variable (the typo-in-key_env case)
        std::env::remove_var("ZION_TEST_SEC01_MISSING");
        let e = spawn_err(&cfg_for(&path, "ZION_TEST_SEC01_MISSING"));
        assert!(
            e.contains("ZION_TEST_SEC01_MISSING") && e.contains("refusing to start"),
            "{e}"
        );

        // empty key -> same
        std::env::set_var("ZION_TEST_SEC01_EMPTY", "");
        assert!(spawn_writer(&cfg_for(&path, "ZION_TEST_SEC01_EMPTY")).is_err());

        // 31 bytes is too short, 32 is accepted
        std::env::set_var("ZION_TEST_SEC04_SHORT", "x".repeat(31));
        let e = spawn_err(&cfg_for(&path, "ZION_TEST_SEC04_SHORT"));
        assert!(e.contains("31 bytes") && e.contains("minimum is 32"), "{e}");
        std::env::set_var("ZION_TEST_SEC04_OK", "x".repeat(32));
        let (_h, w) =
            spawn_writer(&cfg_for(&path, "ZION_TEST_SEC04_OK")).expect("32 bytes is fine");
        assert!(w.unwrap().shutdown(std::time::Duration::from_secs(5)).await);

        // key_id must be a simple label
        std::env::set_var("ZION_TEST_SEC02_KEY", "k".repeat(40));
        for bad in ["", "has space", "semi;colon", &"a".repeat(65)] {
            let mut c = cfg_for(&path, "ZION_TEST_SEC02_KEY");
            c.key_id = Some(bad.to_string());
            assert!(spawn_err(&c).contains("key_id"), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn marker_names_the_signing_key() {
        std::env::set_var("ZION_TEST_SEC02_MARK", "m".repeat(40));
        // configured label
        let dir = tempdir();
        let path = dir.join("audit.log");
        let mut c = cfg_for(&path, "ZION_TEST_SEC02_MARK");
        c.key_id = Some("2026-10".into());
        let (_h, w) = spawn_writer(&c).unwrap();
        assert!(w.unwrap().shutdown(std::time::Duration::from_secs(5)).await);
        assert!(
            marker_details(&path)[0].contains("key_id=2026-10;"),
            "{:?}",
            marker_details(&path)
        );

        // default: a 16-hex fingerprint that does not contain the key
        let dir = tempdir();
        let path = dir.join("audit.log");
        let (_h, w) = spawn_writer(&cfg_for(&path, "ZION_TEST_SEC02_MARK")).unwrap();
        assert!(w.unwrap().shutdown(std::time::Duration::from_secs(5)).await);
        let d = marker_details(&path).remove(0);
        let id = d
            .split("key_id=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!d.contains(&"m".repeat(40)));
    }

    #[test]
    fn previous_key_keeps_the_tail_verifiable_across_a_rotation() {
        let old = test_key();
        let new = hmac::Key::new(hmac::HMAC_SHA256, b"rotated-in-32-byte-secret-key-xxx");
        let (line, mac) = signed_line(&old, 3, &genesis_hash(&old));
        // Without the outgoing key the old chain cannot be checked...
        assert_eq!(
            verify_tail(&new, None, line.as_bytes(), true),
            PrevHead::Unverified
        );
        // ...with it, the head is verified and flagged as signed by the previous key.
        assert_eq!(
            verify_tail(&new, Some(&old), line.as_bytes(), true),
            PrevHead::Verified {
                hmac: mac,
                seq: 3,
                previous_key: true
            }
        );
    }

    #[tokio::test]
    async fn shutdown_drains_every_queued_event_before_exiting() {
        std::env::set_var("ZION_TEST_CONC01_KEY", "d".repeat(40));
        let dir = tempdir();
        let path = dir.join("audit.log");
        let (h, w) = spawn_writer(&cfg_for(&path, "ZION_TEST_CONC01_KEY")).unwrap();
        for i in 0..300 {
            let mut e = make_event(0, "auth_success");
            e.detail = Some(format!("queued-{i}"));
            assert!(h.emit(e));
        }
        // Stop straight away: the queue is not empty yet. Everything in it must
        // still reach the file, and the writer must exit within the timeout.
        assert!(
            w.unwrap()
                .shutdown(std::time::Duration::from_secs(10))
                .await
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1 + 300, "chain_init + all 300 events");
        assert!(
            text.contains("queued-299"),
            "the newest event must not be lost"
        );
    }

    #[tokio::test]
    async fn a_dead_writer_is_told_apart_from_a_full_queue() {
        std::env::set_var("ZION_TEST_CONC02_KEY", "e".repeat(40));
        let dir = tempdir();
        let path = dir.join("audit.log");
        let (h, w) = spawn_writer(&cfg_for(&path, "ZION_TEST_CONC02_KEY")).unwrap();
        assert!(w.unwrap().shutdown(std::time::Duration::from_secs(5)).await);
        let before = observability::AUDIT_EVENTS_DROPPED_TOTAL.load(Ordering::Relaxed);
        // The channel is closed now: emit fails and is still counted as dropped.
        assert!(!h.emit(make_event(1, "auth_success")));
        assert!(observability::AUDIT_EVENTS_DROPPED_TOTAL.load(Ordering::Relaxed) > before);
        // (the writer-down gauge itself is process-global, so it is asserted in
        // the metrics render test, not here where tests run in parallel)
    }

    // ── Chain continuity across restarts (ZION-DATA-04) ─────────────────

    fn signed_line(key: &hmac::Key, seq: u64, prev: &str) -> (String, String) {
        let (signed, mac) =
            sign_event(key, make_event(seq, "auth_success"), prev.to_string()).expect("sign");
        let mut line = serde_json::to_string(&signed).unwrap();
        line.push('\n');
        (line, mac)
    }

    #[test]
    fn verify_tail_accepts_a_valid_last_record() {
        let key = test_key();
        let genesis = genesis_hash(&key);
        let (l1, h1) = signed_line(&key, 1, &genesis);
        let (l2, h2) = signed_line(&key, 2, &h1);
        let both = format!("{l1}{l2}");
        assert_eq!(
            verify_tail(&key, None, both.as_bytes(), true),
            PrevHead::Verified {
                hmac: h2,
                seq: 2,
                previous_key: false
            }
        );
    }

    #[test]
    fn verify_tail_flags_torn_wrong_key_and_garbage() {
        let key = test_key();
        let (l1, _) = signed_line(&key, 1, &genesis_hash(&key));
        assert_eq!(verify_tail(&key, None, b"", true), PrevHead::Empty);
        // cut mid-record: no trailing newline
        assert_eq!(
            verify_tail(&key, None, l1.trim_end().as_bytes(), true),
            PrevHead::Unverified
        );
        // valid shape, different HMAC key
        let other = hmac::Key::new(hmac::HMAC_SHA256, b"another-32-byte-secret-key-xxxxxx");
        assert_eq!(
            verify_tail(&other, None, l1.as_bytes(), true),
            PrevHead::Unverified
        );
        // not JSON at all
        assert_eq!(
            verify_tail(&key, None, b"hello world\n", true),
            PrevHead::Unverified
        );
        // tampered field breaks the MAC
        let forged = l1.replace("auth_success", "auth_failure");
        assert_eq!(
            verify_tail(&key, None, forged.as_bytes(), true),
            PrevHead::Unverified
        );
        // a lone line that may have been cut off at the window start is not trusted
        assert_eq!(
            verify_tail(&key, None, l1.as_bytes(), false),
            PrevHead::Unverified
        );
    }

    fn marker_details(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["kind"] == "chain_init")
            .map(|v| v["detail"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn restart_marker_records_the_previous_chain_head() {
        let dir = tempdir();
        let path = run_writer(&dir, None, 0, 3).await;
        let last: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .last()
                .unwrap(),
        )
        .unwrap();
        // Second process start onto the same segment.
        let path = run_writer(&dir, None, 0, 1).await;
        let m = marker_details(&path);
        assert_eq!(m.len(), 2, "one chain_init per process start");
        assert!(m[0].contains("prev_head=none"), "fresh file: {}", m[0]);
        let want = format!("prev_head={}; prev_seq=3", last["hmac"].as_str().unwrap());
        assert!(
            m[1].contains(&want),
            "marker must carry the old head: {}",
            m[1]
        );
    }

    #[tokio::test]
    async fn torn_tail_is_flagged_and_does_not_corrupt_the_marker() {
        let dir = tempdir();
        let path = run_writer(&dir, None, 0, 2).await;
        // Simulate a crash mid-record: a fragment with no trailing newline.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(br#"{"seq":9,"ts":"2026-01-01T00:00:0"#)
                .unwrap();
        }
        let path = run_writer(&dir, None, 0, 1).await;
        let m = marker_details(&path);
        assert_eq!(
            m.len(),
            2,
            "the marker after the torn tail must still parse"
        );
        assert!(m[1].contains("prev_head=unverified"), "{}", m[1]);
        // and the fragment sits on its own line, not glued to the marker
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text
            .lines()
            .any(|l| l.starts_with(r#"{"seq":9,"ts":"2026-01-01T00:00:0"#)
                && !l.contains("chain_init")));
    }

    // ── Durability (ZION-DATA-01) ─────────────────────────────────────────

    #[test]
    fn sync_interval_defaults_to_one_second_and_can_be_disabled() {
        let d: AuditConfig = toml::from_str("enabled = true").unwrap();
        assert_eq!(d.sync_interval_ms, 1000);
        let off: AuditConfig = toml::from_str("enabled = true\nsync_interval_ms = 0").unwrap();
        assert_eq!(off.sync_interval_ms, 0);
    }

    #[tokio::test]
    async fn periodic_sync_keeps_the_writer_alive_across_idle_gaps() {
        // Exercises the idle-deadline branch: events, a gap longer than the sync
        // interval (the writer must wake on its own and fsync), then more events.
        // fsync itself is not observable from here; what is checked is that the
        // timed path neither loses records nor hangs the writer.
        let dir = tempdir();
        let path = dir.join("audit.log");
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"this-is-a-32-byte-test-secret!ab");
        let (tx, rx) = tokio::sync::mpsc::channel::<AuditEvent>(64);
        let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let jh = tokio::spawn(writer_loop(
            path.to_string_lossy().into_owned(),
            key,
            rx,
            stop_rx,
            test_opts(None, 0, Some(std::time::Duration::from_millis(20))),
        ));
        for round in 0..3 {
            for i in 0..3 {
                let mut e = make_event(0, "auth_success");
                e.detail = Some(format!("r{round}-e{i}"));
                tx.send(e).await.unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        }
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), jh)
            .await
            .expect("writer must exit after the channel closes")
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.lines().count(),
            1 + 9,
            "chain_init + 9 events, none lost"
        );
    }

    #[tokio::test]
    async fn rotation_syncs_the_directory_and_keeps_every_event() {
        // The seal path now fsyncs the outgoing segment and the directory; it must
        // still lose nothing and leave a parseable active segment.
        let dir = tempdir();
        let path = run_writer(&dir, Some(600), 5, 12).await;
        assert!(
            !rotated_segments(&dir).is_empty(),
            "rotation must have fired"
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .all(|l| serde_json::from_str::<serde_json::Value>(l).is_ok()));
    }

    // ── Rotation (issue #288) ────────────────────────────────────────────
    // Drive `writer_loop` directly with a tiny *byte* cap (spawn_writer's
    // MB→bytes conversion is bypassed) so rotation fires in a handful of
    // events — deterministic and fast.

    fn test_opts(
        max_size_bytes: Option<u64>,
        max_files: usize,
        sync_interval: Option<std::time::Duration>,
    ) -> WriterOpts {
        WriterOpts {
            max_size_bytes,
            max_files,
            sync_interval,
            key_id: "test-key".into(),
            previous_key: None,
        }
    }

    async fn run_writer(
        dir: &std::path::Path,
        max_bytes: Option<u64>,
        max_files: usize,
        n_events: usize,
    ) -> std::path::PathBuf {
        let path = dir.join("audit.log");
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"this-is-a-32-byte-test-secret!ab");
        let (tx, rx) = tokio::sync::mpsc::channel::<AuditEvent>(256);
        let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let jh = tokio::spawn(writer_loop(
            path.to_string_lossy().into_owned(),
            key,
            rx,
            stop_rx,
            test_opts(max_bytes, max_files, None),
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

    #[test]
    fn only_the_writers_own_names_are_segments() {
        // What `rotate_paths` produces.
        assert!(is_own_segment("audit.log", "audit.log.1790000000000000000"));
        assert!(is_own_segment(
            "audit.log",
            "audit.log.1790000000000000000.3"
        ));
        // What an operator leaves next to it: not ours, never counted or deleted.
        for foreign in [
            "audit.log",
            "audit.log.",
            "audit.log.verified",
            "audit.log.1.gz",
            "audit.log.1790000000000000000.gz",
            "audit.log.1790000000000000000.",
            "audit.log.1790000000000000000.x",
            "audit.log.1790000000000000000.3.4",
            "audit.log.bak.1790000000000000000",
            "audit.logx.1790000000000000000",
            "other.log.1790000000000000000",
        ] {
            assert!(!is_own_segment("audit.log", foreign), "{foreign}");
        }
    }

    #[tokio::test]
    async fn pruning_never_touches_files_the_writer_did_not_create() {
        let dir = tempdir();
        let log = dir.join("audit.log");
        let mut ours = Vec::new();
        for i in 0..5u64 {
            let f = dir.join(format!("audit.log.{}", 1_790_000_000_000_000_000u64 + i));
            std::fs::write(&f, b"x").unwrap();
            // Older stamp = older mtime, so the order is the one the writer would see.
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000 + i);
            std::fs::File::options()
                .write(true)
                .open(&f)
                .unwrap()
                .set_modified(t)
                .unwrap();
            ours.push(f);
        }
        let foreign: Vec<_> = ["audit.log.verified", "audit.log.1.gz"]
            .iter()
            .map(|n| {
                let f = dir.join(n);
                std::fs::write(&f, b"evidence").unwrap();
                // Older than every segment of ours: the first thing a mtime-ordered prune would take.
                let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(10);
                std::fs::File::options()
                    .write(true)
                    .open(&f)
                    .unwrap()
                    .set_modified(t)
                    .unwrap();
                f
            })
            .collect();

        // A directory with a segment's name is not a segment either (and cannot be unlinked).
        let lookalike = dir.join("audit.log.1790000000000000099");
        std::fs::create_dir(&lookalike).unwrap();

        prune_old_segments(log.to_str().unwrap(), 2).await;

        assert!(lookalike.is_dir());
        for f in &foreign {
            assert!(
                f.exists(),
                "{f:?} is not a segment of the writer and must survive"
            );
        }
        let left: Vec<_> = ours.iter().filter(|f| f.exists()).collect();
        assert_eq!(
            left,
            vec![&ours[3], &ours[4]],
            "the two newest of ours stay"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_prune_is_counted_and_does_not_stop_the_writer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let log = dir.join("audit.log");
        for i in 0..3u64 {
            std::fs::write(
                dir.join(format!("audit.log.{}", 1_790_000_000_000_000_000u64 + i)),
                b"x",
            )
            .unwrap();
        }
        // A read-only directory refuses unlink, unless we are root (then there is no failure to provoke).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let probe = dir.join("probe");
        let can_write = std::fs::write(&probe, b"x").is_ok();
        if can_write {
            std::fs::remove_file(&probe).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipped: running with rights that ignore directory permissions");
            return;
        }
        let before = observability::AUDIT_PRUNE_FAILURES_TOTAL.load(Ordering::Relaxed);
        prune_old_segments(log.to_str().unwrap(), 1).await;
        let after = observability::AUDIT_PRUNE_FAILURES_TOTAL.load(Ordering::Relaxed);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            after - before,
            2,
            "two segments over the bound, two failed deletes, both counted"
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
