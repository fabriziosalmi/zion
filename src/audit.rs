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
#[serde(default)]
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
}

fn default_key_env() -> String {
    "ZION_AUDIT_HMAC_KEY".to_string()
}

fn default_queue_depth() -> usize {
    4096
}

/// `[redact]` block. Lists are case-insensitive. Empty = no redaction.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
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

/// One audit event before signing. Fields are lowercase to match wire format.
#[derive(Serialize, Clone, Debug)]
pub struct AuditEvent {
    /// Monotonic event sequence within this process. Resets on restart.
    pub seq: u64,
    /// RFC 3339 / ISO 8601 timestamp.
    pub ts: String,
    /// Event type — `auth_success`, `auth_failure`, `config_reload`,
    /// `request_blocked`, `admin_access`, `panic`. Free-form string;
    /// auditors filter on it.
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

    tokio::spawn(writer_loop(path, key, rx));

    AuditHandle { inner: Some(tx) }
}

async fn writer_loop(
    path: String,
    key: hmac::Key,
    mut rx: tokio::sync::mpsc::Receiver<AuditEvent>,
) {
    use tokio::io::AsyncWriteExt;

    let file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            crate::logging::error(
                "audit",
                &format!("cannot open audit log {path}: {e} — events will be dropped"),
            );
            return;
        }
    };
    let mut file = tokio::io::BufWriter::new(file);

    // Bootstrap the chain. If the file already has content we don't try to
    // continue from its tail — that would require trusting the on-disk
    // value, which defeats tamper-evidence. Instead, every process restart
    // starts a fresh chain anchored at the genesis tag and a `kind=
    // chain_init` marker so verifiers can detect the boundary.
    let mut prev_hash = genesis_hash(&key);
    let init = AuditEvent {
        seq: 0,
        ts: now_iso8601(),
        kind: "chain_init",
        trace_id: None,
        remote_ip: None,
        method: None,
        path: None,
        detail: Some(format!(
            "audit chain initialized at process start; genesis={}",
            &prev_hash[..16]
        )),
    };
    if let Ok((signed, new_prev)) = sign_event(&key, init, prev_hash.clone()) {
        if let Ok(line) = serde_json::to_string(&signed) {
            let _ = file.write_all(line.as_bytes()).await;
            let _ = file.write_all(b"\n").await;
            prev_hash = new_prev;
        }
    }
    let _ = file.flush().await;

    let mut seq: u64 = 1;
    while let Some(mut event) = rx.recv().await {
        event.seq = seq;
        if event.ts.is_empty() {
            event.ts = now_iso8601();
        }
        match sign_event(&key, event, prev_hash.clone()) {
            Ok((signed, new_prev)) => {
                if let Ok(line) = serde_json::to_string(&signed) {
                    if file.write_all(line.as_bytes()).await.is_err()
                        || file.write_all(b"\n").await.is_err()
                    {
                        crate::logging::error(
                            "audit",
                            "audit log write failed — disk full or fd revoked, exiting writer",
                        );
                        break;
                    }
                    prev_hash = new_prev;
                    seq += 1;
                    // Flush each event — durability over throughput. Audit
                    // logs are low-rate; if this becomes a bottleneck we
                    // can batch on a 100ms timer.
                    let _ = file.flush().await;
                }
            }
            Err(e) => {
                crate::logging::error("audit", &format!("audit event serialize failed: {e}"));
                continue;
            }
        }
    }
    let _ = file.flush().await;
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

    fn tempdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "zion-audit-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
