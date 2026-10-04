// SPDX-License-Identifier: Apache-2.0
//! Configuration loading, validation, and router construction.
//!
//! Parses `zion.toml` into typed structs (`ZionConfig`), validates the
//! result (every WAF/auth/cache profile referenced by a route must
//! exist; CIDRs parse; xff_mode is a known string), and builds the
//! `matchit::Router<Arc<ResolvedRoute>>` consumed by `dispatch.rs`.
//!
//! `build_router` is the single fallible entry point; everything that
//! turns static TOML into runtime state flows through it.

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

// ============================================================================
// TOP-LEVEL CONFIG
// ============================================================================

/// The config-schema version THIS binary understands. Bump it (and document
/// the migration) whenever a breaking config change lands. A config may declare
/// `schema_version` to opt into the version handshake below.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// The version a file with NO `schema_version` is taken to be. Pinned to `1` — the
/// schema every config written before the handshake existed used — and never
/// "whatever is current": when schema 2 lands, an unversioned file must still be
/// read as schema 1 (and migrated), not silently reinterpreted as 2.
pub const LEGACY_SCHEMA_VERSION: u32 = 1;

fn legacy_schema_version() -> u32 {
    LEGACY_SCHEMA_VERSION
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ZionConfig {
    /// Schema version the file targets. **Absent means [`LEGACY_SCHEMA_VERSION`]
    /// (1)**, not "compatible with anything": the file is read with the schema-1
    /// reader and brought up to the current shape by `upgrade_schema`. A value
    /// NEWER than this binary's `CURRENT_SCHEMA_VERSION` gets targeted upgrade
    /// guidance (see `check_schema_version`); `0` is rejected.
    #[serde(default = "legacy_schema_version")]
    pub schema_version: u32,
    pub server: ServerConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub upstream: HashMap<String, UpstreamConfig>,
    #[serde(default)]
    pub waf_profile: HashMap<String, WafProfile>,
    #[serde(default)]
    pub cache_profile: HashMap<String, CacheProfile>,
    pub route: Vec<RouteConfig>,
    /// Named auth profiles for JWT/OIDC validation (feature: auth).
    #[serde(default)]
    pub auth_profile: HashMap<String, crate::auth::AuthProfileConfig>,

    /// Sovereign Edge Intelligence config (feature: geo-ita / geo-eu).
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    #[serde(default)]
    pub sovereign: crate::sovereign::SovereignConfig,

    /// HMAC-chained audit log (Track B). When `enabled = true` Zion writes
    /// one signed JSON event per security-relevant action to the configured
    /// path. Every event carries a `prev_hash` field so any tamper breaks
    /// the chain at the next verification.
    #[serde(default)]
    pub audit: crate::audit::AuditConfig,

    /// PII redaction policy applied to access logs and audit events
    /// (Track B). Empty = no redaction (default — back-compat).
    #[serde(default)]
    pub redact: crate::audit::RedactConfig,

    /// Access-log emission policy (issue #60). Controls which request
    /// headers are included in the structured `tracing::info!(target:
    /// "access", ...)` event and whether the mTLS fingerprint is
    /// surfaced as a separate field. Empty list = no headers logged
    /// (default — back-compat with v0.2.x).
    #[serde(default)]
    pub access_log: AccessLogConfig,

    /// AIMP control-plane / mesh config (feature: sovereign-aimp).
    /// Optional — absent block = mesh disabled.
    #[cfg(feature = "sovereign-aimp")]
    #[serde(default)]
    pub sovereign_aimp: AimpConfig,

    // Legacy compat: flat upstreams map (just URLs)
    #[serde(default)]
    pub upstreams: HashMap<String, String>,

    /// Admin API (#26). Absent block ⇒ no admin listener spawned (zero
    /// overhead, zero attack surface). When present, a dedicated loopback
    /// listener serves runtime config inspection / push.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
}

/// `[admin]` block — the runtime admin API listener (#26). Loopback +
/// internal-ip-gated by default; production turns on mTLS (Phase 4).
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Listen address. Default `127.0.0.1:9180` (loopback only).
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    /// Auth mode: `"internal-ip"` (default — same gate as `/_zion/snapshot.json`)
    /// or `"mtls"` (opt-in, Phase 4). Unknown values are rejected at validation.
    #[serde(default = "default_admin_auth")]
    pub auth: String,
    /// Global request rate limit (req/s) for the admin listener — defense in
    /// depth that bounds the expensive reload path against loops / abuse. Must
    /// be > 0. Default 10.
    #[serde(default = "default_admin_rate_limit")]
    pub rate_limit_rps: u32,
    /// Name of an environment variable holding a bearer token (>= 32 bytes) that
    /// every MUTATING admin call (`POST /admin/config`, `/admin/reload`,
    /// `/admin/revoke`) must present as `Authorization: Bearer <token>`, on top of
    /// the `auth` mode. Reads (`GET /admin/config`) stay under `auth` alone, so a
    /// monitoring client can hold read access without being able to change the
    /// config. Unset (default): a peer that passes `auth` may write.
    #[serde(default)]
    pub write_token_env: Option<String>,
    /// Write a config accepted by `POST /admin/config` back to `zion.toml`
    /// (atomically, keeping the file's mode) so a restart does not revert it.
    /// Default `false`: a push is live-only until the next reload or restart.
    #[serde(default)]
    pub persist_push: bool,
    /// The CA that signs ADMIN client certificates (`auth = "mtls"`). Required in that
    /// mode and separate from `tls.client_ca_path` on purpose: a certificate issued for
    /// data-plane client authentication must not also open the admin API.
    #[serde(default)]
    pub client_ca_path: Option<String>,
    /// Certificate revocation list(s) for ADMIN client certificates (`auth = "mtls"`): a
    /// PEM file with one or more CRLs, or one DER CRL. A certificate it lists is refused at
    /// the handshake. Re-read when the file changes. See `[tls] client_crl_path`.
    #[serde(default)]
    pub client_crl_path: Option<String>,
}

fn default_admin_listen() -> String {
    "127.0.0.1:9180".to_string()
}
fn default_admin_auth() -> String {
    "internal-ip".to_string()
}
fn default_admin_rate_limit() -> u32 {
    10
}

/// `[sovereign_aimp]` block — gossip control plane.
///
/// TOML takes precedence: a `ZION_AIMP_*` env var only fills a field that is
/// UNSET (empty) in this block — it does NOT override a value present in the
/// TOML (see the wiring in `main.rs`). Env vars are the legacy path and keep
/// existing deployments working; operators are encouraged to migrate to TOML
/// for review/diffability. (If you need an env var to win, clear the TOML key.)
#[cfg(feature = "sovereign-aimp")]
#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AimpConfig {
    /// Master switch. False or absent block = mesh disabled.
    #[serde(default)]
    pub enabled: bool,
    /// UDP socket to bind for gossip ingress. Example: "0.0.0.0:7777".
    #[serde(default)]
    pub listen: String,
    /// Static peer list for v0 (no mDNS). Comma-separated host:port pairs.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Path to the persisted Ed25519 secret. If absent or unreadable,
    /// a fresh keypair is generated and written on first boot.
    #[serde(default)]
    pub identity_path: String,
    /// Score threshold above which an AIMP→XDP reconciler would install
    /// an LPM-trie drop. Range \[0,1\]. Default 0.95 = only escalate to
    /// kernel-level drop on high-confidence threats.
    ///
    /// Reserved: the XDP reconciler is not shipped (the in-kernel
    /// pre-filter track is frozen — see issue #53). The field is kept so
    /// the TOML schema stays stable if that work is ever picked up.
    #[allow(dead_code)]
    #[serde(default = "default_aimp_xdp_threshold")]
    pub xdp_block_threshold: f32,
    /// Period in seconds between anti-entropy SyncReq rounds. 0 disables.
    #[serde(default = "default_aimp_anti_entropy_secs")]
    pub anti_entropy_secs: u64,
    /// Per-source inbound claim rate-cap (issue #71). 0 = disabled
    /// (default). When set, a flooding peer is capped to this many
    /// claims/sec; other sources are unaffected (own token bucket).
    #[serde(default)]
    pub inbound_claims_per_sec: u32,
    /// Burst headroom (in claims) for the inbound rate-cap. Only used
    /// when `inbound_claims_per_sec > 0`. Default 256.
    #[serde(default = "default_aimp_inbound_claim_burst")]
    pub inbound_claim_burst: u32,
    /// Node ids (Ed25519 public keys, 64 hex characters, as each node prints at boot)
    /// whose claims are accepted. Required when the mesh is enabled: a valid signature
    /// alone only proves the sender holds some key.
    #[serde(default)]
    pub trusted_keys: Vec<String>,
}

#[cfg(feature = "sovereign-aimp")]
fn default_aimp_xdp_threshold() -> f32 {
    0.95
}

#[cfg(feature = "sovereign-aimp")]
fn default_aimp_anti_entropy_secs() -> u64 {
    60
}

#[cfg(feature = "sovereign-aimp")]
fn default_aimp_inbound_claim_burst() -> u32 {
    256
}

// ============================================================================
// SERVER
// ============================================================================

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen_http: String,
    pub listen_https: String,
    /// Max requests per IP per window. 0 = unlimited (default).
    #[serde(default)]
    pub rate_limit_rps: u32,
    /// Refuse a config in which any route is neither protected nor declared open.
    /// With `true`, every `[[route]]` must set `auth_profile`, or `public = true`
    /// (deliberately unauthenticated), or `internal_only = true`. Default `false`
    /// (routes without `auth_profile` are served unauthenticated, as before).
    #[serde(default)]
    pub require_route_auth: bool,
    /// Rate limit window in seconds. Default: 1.
    #[serde(default = "default_rate_window")]
    pub rate_limit_window_secs: u64,
    /// Max distinct client IPs the per-IP rate limiter tracks. Default 100 000.
    /// At the cap, stale entries are evicted; if every entry is live the new IP is
    /// DENIED (fail-closed), so size this above the number of distinct clients you
    /// expect inside one window. Each entry costs roughly 40 bytes.
    #[serde(default = "default_rate_map_entries")]
    pub rate_limit_max_tracked_ips: usize,
    /// Max *concurrent* connections from a single source IP.
    ///
    /// Tri-state (CVE-2026-49975 multi-connection hardening):
    ///   * omitted → **AUTO**: ~1/8 of the platform connection ceiling
    ///     (`compute_conn_limit`), so one peer cannot monopolize admission or
    ///     drive a multi-connection HTTP/2 Bomb. Scales with box size, so it
    ///     won't pinch CGNAT / large-NAT clients on big nodes.
    ///   * `0` → explicitly **DISABLED** (one source may hold any number of
    ///     slots, up to the global ceiling).
    ///   * `N` → explicit per-IP cap.
    ///
    /// Complements `rate_limit_rps` (request frequency); this caps the held
    /// sockets a slow/backed flood actually drains. The tri-state is resolved
    /// to a concrete cap in `ResolvedAppConfig::try_build` and read live at
    /// accept, so a hot-reload retunes it without dropping live connections.
    #[serde(default)]
    pub max_connections_per_ip: Option<u32>,
    /// Seconds of silence before the kernel starts TCP keepalive probes on client
    /// connections (then every 10 s, dead after 3 unanswered). Frees the file
    /// descriptor and connection slot of a peer that vanished without a FIN (power
    /// loss, a NAT that dropped its mapping) in this + 30 s. Default 60; `0` = off.
    /// Retuned live on reload for new connections. The upstream pool and WebSocket
    /// dials use the 60 s default.
    #[serde(default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
    /// `TCP_USER_TIMEOUT` on client connections (Linux only; seconds; default `0` = the kernel's
    /// own limit of about 15 minutes of retransmissions). Data sent to a client that stays
    /// unacknowledged, **or stays unsent because the client's receive window is zero**, for this
    /// long drops the connection. It frees the descriptor, connection slot and buffers of a client
    /// that vanished *while a response was in flight* (keepalive only probes idle connections),
    /// but it also drops a client that stops reading for longer than this (a paused player with a
    /// full buffer, a very slow reader), hence opt-in: pick a value comfortably above the longest
    /// pause you accept (for example `300`). Retuned live on reload for new connections.
    #[serde(default = "default_tcp_user_timeout_secs")]
    pub tcp_user_timeout_secs: u64,
    /// Log format: "text" (default) or "json".
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// How long (seconds) the last good DNS answer for an upstream host may be served when a
    /// fresh lookup fails, times out or returns nothing (default 3600; `0` = never serve a
    /// stale answer). A fresh lookup is always tried first. Applied on reload.
    #[serde(default = "default_dns_stale_secs")]
    pub dns_stale_secs: u64,
    /// Deadline (ms) for one upstream DNS lookup before the last good answer is used instead
    /// (default 2000; `0` = wait as long as the system resolver does). Applied on reload.
    #[serde(default = "default_dns_timeout_ms")]
    pub dns_timeout_ms: u64,
    /// Log lines that can wait for stderr (default 8192). Logging never blocks a request: when
    /// the sink is slower than the log rate the newest lines are dropped and counted in
    /// `zion_log_lines_dropped_total`. `0` writes synchronously (a stalled stderr then stalls
    /// the request that logged). Read at start-up; changing it needs a restart.
    #[serde(default = "default_log_queue_lines")]
    pub log_queue_lines: usize,
    /// Trusted proxy CIDR ranges. When the TCP peer IP matches one of these,
    /// the real client IP is extracted from X-Forwarded-For (rightmost untrusted hop).
    /// Example: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Peers allowed to use the internal-only endpoints (`/metrics`,
    /// `/_zion/snapshot.json`, `/_zion/cache/purge`) and routes marked
    /// `internal_only`, as CIDRs (bare IPs allowed). Empty (default) keeps the
    /// built-in rule: any loopback / private-range / link-local / ULA peer. That
    /// rule is a network-position test, so behind a private-range load balancer,
    /// Kubernetes SNAT or a Docker bridge every client looks internal; set this (and
    /// `trusted_proxies`) to name exactly which hosts are. Example: `["127.0.0.1/32",
    /// "10.20.0.0/24"]`.
    #[serde(default)]
    pub internal_networks: Vec<String>,
    /// X-Forwarded-For policy applied to outbound requests to upstreams.
    ///
    /// * `"append"` (default): preserve any inbound XFF chain and append
    ///   the resolved client IP. Compatible with deployments where Zion
    ///   sits behind a sanitising edge (CDN/ALB).
    /// * `"rewrite"`: drop inbound XFF and emit a single trusted entry —
    ///   the resolved client IP. Recommended when Zion is the front edge.
    /// * `"drop"`: strip inbound XFF; emit nothing. Use when upstreams
    ///   must not learn the client IP at all.
    ///
    /// Invalid values fall back to `"append"` with a startup warning.
    #[serde(default = "default_xff_mode")]
    pub xff_mode: String,
}

fn default_xff_mode() -> String {
    "append".to_string()
}

fn default_tcp_user_timeout_secs() -> u64 {
    crate::net::DEFAULT_TCP_USER_TIMEOUT_SECS
}

fn default_tcp_keepalive_secs() -> u64 {
    crate::net::DEFAULT_TCP_KEEPALIVE_SECS
}

fn default_dns_stale_secs() -> u64 {
    crate::dns::DEFAULT_STALE_SECS
}

fn default_dns_timeout_ms() -> u64 {
    crate::dns::DEFAULT_TIMEOUT_MS
}

fn default_log_queue_lines() -> usize {
    8192
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_rate_window() -> u64 {
    1
}

fn default_rate_map_entries() -> usize {
    crate::security::MAX_RATE_MAP_ENTRIES
}

// ============================================================================
// CORS
// ============================================================================

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Allowed origins. Empty = CORS disabled (default).
    /// Use `["*"]` for any origin, or `["https://app.example.com"]`.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Additional allowed headers beyond the CORS safelisted ones.
    #[serde(default = "default_cors_headers")]
    pub allowed_headers: Vec<String>,
    /// Max age for pre-flight cache (seconds). Default: 86400 (24h).
    #[serde(default = "default_cors_max_age")]
    pub max_age: u64,
}

fn default_cors_headers() -> Vec<String> {
    vec![
        "Content-Type".to_string(),
        "Authorization".to_string(),
        "X-Requested-With".to_string(),
    ]
}

fn default_cors_max_age() -> u64 {
    86400
}

// ============================================================================
// ACCESS LOG (issue #60)
// ============================================================================

/// Access-log emission policy. Controls which request headers are
/// included in the structured `tracing::info!(target: "access", ...)`
/// event in [`crate::dispatch`].
///
/// Defaults: empty header list, mTLS fingerprint included when present.
/// The mTLS fingerprint is a SHA-256 hash and is **never redacted** —
/// it's already an opaque identifier suitable for upstream correlation.
///
/// All other configured headers pass through
/// [`crate::audit::CompiledRedaction::redact_header_value`] before
/// emission, using the same `[redact.headers]` policy that protects
/// the audit log. If a header name appears in `[redact.headers]`,
/// every value of that header is replaced by `<redacted:N>` where
/// `N` is the byte length of the original value.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
    /// Emit the per-request access-log event (default `true`). It costs throughput (one
    /// formatted line per request); `false` turns it off without touching `RUST_LOG`.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Header names to include in the access-log event. Lowercased
    /// at deserialise time so case-insensitive matching against
    /// `req.headers().get(name)` is cheap. Default: empty.
    #[serde(default, deserialize_with = "deserialize_lowercased_headers")]
    pub include_headers: Vec<String>,

    /// When `true` (default), the mTLS leaf-cert SHA-256 fingerprint
    /// (already injected by the listener as `X-Client-Cert-Fingerprint`)
    /// is emitted on a dedicated `mtls_fp` field. The hash is opaque,
    /// so no redaction is applied. Set `false` to omit even when
    /// mTLS is configured.
    #[serde(default = "default_mtls_fingerprint")]
    pub mtls_fingerprint: bool,
}

fn default_mtls_fingerprint() -> bool {
    true
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_headers: Vec::new(),
            mtls_fingerprint: default_mtls_fingerprint(),
        }
    }
}

/// Lowercase every entry on parse so the dispatch hot path can do
/// `eq_ignore_ascii_case`-free comparisons against `HeaderName::as_str()`.
fn deserialize_lowercased_headers<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    Ok(raw.into_iter().map(|s| s.to_ascii_lowercase()).collect())
}

// ============================================================================
// TLS (abstracted: min version, ALPN, cipher control)
// ============================================================================

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Default cert (used when no SNI match, or single-FQDN mode)
    pub cert_path: String,
    pub key_path: String,
    #[serde(default = "default_true")]
    pub hot_reload: bool,
    #[serde(default = "default_tls_min_version")]
    pub min_version: String, // "1.2" or "1.3"
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>, // ["h2", "http/1.1"]
    /// Optional SNI-based cert mappings. If empty, single-cert mode (zero overhead).
    #[serde(default)]
    pub sni: Vec<SniCert>,
    /// ACME auto-renewal. If set, Zion auto-renews certificates via Let's Encrypt.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// Path to CA bundle for verifying client certificates (mTLS downstream).
    #[serde(default)]
    pub client_ca_path: Option<String>,
    /// Certificate revocation list(s) for client certificates: a PEM file with one or more
    /// CRLs, or one DER CRL, issued by the CA(s) in `client_ca_path`. A client certificate it
    /// lists is refused at the handshake; so is one whose issuer has no CRL in the file (an
    /// unknown revocation status is not accepted). Only the client's own certificate is
    /// checked, not the intermediates. The file is re-read when it changes (with
    /// `hot_reload`), so revoking a certificate needs no restart. The CRL's `nextUpdate` is
    /// not enforced: an out-of-date list keeps being applied rather than locking every client
    /// out.
    #[serde(default)]
    pub client_crl_path: Option<String>,
    /// Client auth mode: "none" (default), "optional", "required".
    #[serde(default = "default_client_auth")]
    pub client_auth: String,
    /// JA4 TLS client fingerprinting (`--features tls-fingerprint`, issue #27).
    /// Absent or `mode = "off"` → zero overhead, no ClientHello peek.
    #[serde(default)]
    pub fingerprint: Option<FingerprintConfig>,
}

/// JA4 TLS client-fingerprinting config (`[tls.fingerprint]`). Always parsed so
/// a typo is a clear error on any build; only *acted upon* under the
/// `tls-fingerprint` feature (a feature-off `mode != off` is warned — see
/// `warn_feature_config_gaps`). `allowed` is only read under the feature, hence
/// the targeted allow (mirrors `AcmeConfig`).
#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct FingerprintConfig {
    /// `off` (default) | `shadow` | `allowlist`.
    /// - `off`: no fingerprinting; zero overhead.
    /// - `shadow`: compute JA4, count known/unknown, log — but never block.
    /// - `allowlist`: additionally enforce — a fingerprint not in `allowed` is
    ///   handled per `on_unknown`, an unfingerprintable ClientHello per
    ///   `on_unfingerprintable` (a `drop` closes the socket before the handshake).
    #[serde(default)]
    pub mode: FingerprintMode,
    /// Known-good fingerprints. In `shadow` they label a connection known vs
    /// unknown for the metrics; in `allowlist` they are the enforced allowlist.
    #[serde(default)]
    pub allowed: Vec<AllowedFingerprint>,
    /// `allowlist` mode: what to do with a fingerprint not in `allowed`.
    /// Default `log_only` — observe without blocking. `drop` closes the socket
    /// before the TLS handshake.
    #[serde(default)]
    pub on_unknown: OnUnknown,
    /// `allowlist` mode: what to do with a connection whose ClientHello can't be
    /// fingerprinted (peek timed out, record larger than the buffer, not TLS).
    /// Default `allow` — availability first; `drop` fails closed for the strict.
    #[serde(default)]
    pub on_unfingerprintable: OnUnfingerprintable,
    /// `allowlist` + `on_unknown = "drop"`: once an unknown fingerprint is
    /// rejected it goes on a ban set for this many seconds, and repeat
    /// connections with the same JA4 are rejected on a fast path — one map
    /// lookup, a debug-level log instead of a warn per connection, counted in
    /// `zion_tls_fp_banned_hits`. Under a flood of one fingerprint this is
    /// what keeps the log readable. `0` disables the ban set (every rejection
    /// logs individually). Default 600 (10 minutes). Bans survive config
    /// reloads but never outlive the process.
    #[serde(default = "default_ban_ttl_secs")]
    pub ban_ttl_secs: u64,
}

fn default_ban_ttl_secs() -> u64 {
    600
}

/// Upper bound accepted for `ban_ttl_secs` (1 year). Anything larger is an
/// operator error (see the validator) — and, unvalidated, would overflow
/// `Instant + Duration` on the first ban insert.
#[allow(dead_code)] // read only by the `tls-fingerprint`-gated validator block
pub const MAX_BAN_TTL_SECS: u64 = 31_536_000;

// Manual impl (not derived) so `FingerprintConfig::default()` and a TOML block
// that omits `ban_ttl_secs` agree on 600 — a derived Default would say 0
// (bans disabled) while serde says 600.
impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            mode: FingerprintMode::default(),
            allowed: Vec::new(),
            on_unknown: OnUnknown::default(),
            on_unfingerprintable: OnUnfingerprintable::default(),
            ban_ttl_secs: default_ban_ttl_secs(),
        }
    }
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintMode {
    #[default]
    Off,
    Shadow,
    Allowlist,
}

#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnUnknown {
    /// Log + count the unknown fingerprint; let the connection proceed.
    #[default]
    LogOnly,
    /// Close the socket before the TLS handshake.
    Drop,
}

#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnUnfingerprintable {
    /// Let the connection proceed into the handshake (availability first).
    #[default]
    Allow,
    /// Close the socket before the TLS handshake.
    Drop,
}

#[allow(dead_code)] // fields read only under `--features tls-fingerprint`
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AllowedFingerprint {
    /// Human label for metrics/logs (e.g. `chrome-131`, `corp-agent`).
    pub name: String,
    /// The JA4 string, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub ja4: String,
    /// Cap on NEW TLS connections per second for this fingerprint —
    /// connections, not HTTP requests: the gate runs before the handshake,
    /// where requests don't exist yet. Over-cap connections are dropped
    /// pre-handshake in `allowlist` mode and only counted
    /// (`zion_tls_fp_rate_limited`) in `shadow`. `0` (default) = no limit,
    /// consistent with `[server] rate_limit_rps`.
    #[serde(default)]
    pub rate_limit_cps: u32,
    /// Routes this fingerprint may request — same pattern syntax and matching
    /// semantics as `[[route]] path` (matchit; a catch-all also covers its
    /// bare prefix, `/x` and `/x/` are the same). Empty (default) = no
    /// restriction. A request outside the list gets **403** in `allowlist`
    /// mode — request-level policy is HTTP-level: the handshake already
    /// happened, and on HTTP/2 dropping the connection would kill unrelated
    /// in-flight requests — and is only counted
    /// (`zion_tls_fp_route_denied`) in `shadow`. Patterns are validated at
    /// boot; an invalid one refuses the config.
    ///
    /// Scope: the list is a positive grant over the WHOLE request surface,
    /// built-in endpoints included — a restricted scraper needs `/metrics`
    /// on its list (the endpoint's own internal-IP gate still applies).
    /// Exceptions: `/healthz` and `/readyz` are exempt BY DESIGN — the gate
    /// itself allows them (`route_gate`), so the property holds on every
    /// protocol: on :443 HTTP/1.1-2 they are answered on the listener fast
    /// path before dispatch, while HTTP/3 bridges into dispatch directly.
    #[serde(default)]
    pub allowed_routes: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SniCert {
    pub server_name: String,
    pub cert_path: String,
    pub key_path: String,
}

/// Always deserialized so users get a clear "unknown ACME field" error
/// even on builds without `--features acme`. The fields below are only
/// READ by acme.rs, which is feature-gated; hence the targeted allow.
#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    /// Contact email for Let's Encrypt (required).
    pub email: String,
    /// Domains to get certificates for.
    pub domains: Vec<String>,
    /// ACME directory URL. Default: Let's Encrypt production.
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    /// Days before expiry to trigger renewal. Default: 30.
    #[serde(default = "default_acme_renew_days")]
    pub renew_before_days: u64,
    /// Where to store ACME account key + certs. Default: `/var/lib/zion/acme`
    /// (a runtime-writable state dir — NOT `/etc`, which is read-only under the
    /// hardened systemd unit and the distroless container).
    #[serde(default = "default_acme_state_dir")]
    pub state_dir: String,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
fn default_acme_renew_days() -> u64 {
    30
}
fn default_acme_state_dir() -> String {
    // /var/lib/zion (not /etc): this dir is written at RUNTIME (account.json +
    // issued certs) by the non-root process; /etc is root-owned config. Matches
    // what the container pre-creates as nonroot-writable and what init emits.
    "/var/lib/zion/acme".to_string()
}

fn default_true() -> bool {
    true
}
fn default_tls_min_version() -> String {
    "1.3".to_string()
}
fn default_alpn() -> Vec<String> {
    vec!["h2".to_string(), "http/1.1".to_string()]
}

// ============================================================================
// UPSTREAM (abstracted: url, timeouts, keepalive, TLS to backend)
// ============================================================================

/// The `[upstream.<name>]` table exactly as written: a single `url`, a `urls`
/// list, or (accepted for compatibility) both. Only ever an input to
/// [`UpstreamConfig`], which normalizes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpstream {
    url: Option<String>,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default = "default_connect_timeout")]
    connect_timeout_ms: u64,
    #[serde(default)]
    request_timeout_ms: Option<u64>,
    #[serde(default = "default_keepalive")]
    keepalive: usize,
    #[serde(default)]
    tls: bool,
    #[serde(default)]
    client_cert_path: Option<String>,
    #[serde(default)]
    client_key_path: Option<String>,
    #[serde(default)]
    circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default)]
    load_balancing: LoadBalancing,
    #[serde(default)]
    outlier_detection: Option<OutlierDetectionConfig>,
    #[serde(default)]
    max_in_flight: Option<u32>,
    #[serde(default)]
    preserve_host: bool,
    #[serde(default)]
    health_host: Option<String>,
}

/// How a pool of several endpoints assigns a request to a member.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancing {
    /// Power of two choices on in-flight requests × peak-EWMA latency measured on real traffic.
    #[default]
    P2c,
    /// The member with the lowest active-probe latency (the behaviour before 0.9.4).
    LowestLatency,
}

impl From<LoadBalancing> for crate::pool::Algorithm {
    fn from(l: LoadBalancing) -> Self {
        match l {
            LoadBalancing::P2c => crate::pool::Algorithm::P2c,
            LoadBalancing::LowestLatency => crate::pool::Algorithm::LowestLatency,
        }
    }
}

/// `[upstream.<name>] outlier_detection = { ... }`: eject a pool member whose own failure rate
/// is high while the rest of the pool is fine. See `pool.rs`. Pools of two or more endpoints only.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutlierDetectionConfig {
    /// Eject a member when at least this percentage (1..=100) of its requests in the window
    /// failed (a 502, 503 or 504, or a transport error). Default 50.
    #[serde(default = "default_cb_error_rate")]
    pub error_rate_pct: u32,
    /// ...and it saw at least this many requests in it (>= 1). Default 20.
    #[serde(default = "default_cb_min_requests")]
    pub min_requests: u32,
    /// Sliding window in seconds (1..=60). Default 10.
    #[serde(default = "default_cb_window")]
    pub window_secs: u32,
    /// Base ejection time in seconds (1..=3600); consecutive ejections of the same member last
    /// longer (up to 10x). Default 30.
    #[serde(default = "default_cb_open")]
    pub eject_secs: u32,
    /// At most this percentage of the pool (1..=100) is ejected at once. Default 50.
    #[serde(default = "default_max_ejected")]
    pub max_ejected_pct: u32,
}

fn default_max_ejected() -> u32 {
    50
}

impl OutlierDetectionConfig {
    pub fn to_runtime(&self) -> crate::pool::OutlierCfg {
        crate::pool::OutlierCfg {
            error_rate_pct: self.error_rate_pct,
            min_requests: self.min_requests,
            window_secs: self.window_secs,
            eject_secs: self.eject_secs,
            max_ejected_pct: self.max_ejected_pct,
        }
    }

    fn errors(&self, name: &str) -> Vec<String> {
        let mut e = Vec::new();
        let p = format!("upstream.{name}.outlier_detection");
        if !(1..=100).contains(&self.error_rate_pct) {
            e.push(format!("{p}.error_rate_pct must be 1..=100"));
        }
        if self.min_requests == 0 {
            e.push(format!("{p}.min_requests must be >= 1"));
        }
        if !(1..=60).contains(&self.window_secs) {
            e.push(format!("{p}.window_secs must be 1..=60"));
        }
        if !(1..=3600).contains(&self.eject_secs) {
            e.push(format!("{p}.eject_secs must be 1..=3600"));
        }
        if !(1..=100).contains(&self.max_ejected_pct) {
            e.push(format!("{p}.max_ejected_pct must be 1..=100"));
        }
        e
    }
}

/// `[upstream.<name>] circuit_breaker = { ... }`: stop sending requests to an upstream that
/// is failing. See `breaker.rs`. Absent = no breaker. Applies to a route whose upstream has a
/// SINGLE endpoint (a pool with several already fails over between them).
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Open when at least this percentage (1..=100) of the requests in the window failed
    /// (a 502, 503 or 504, which is what a refused connection, a timeout or an overloaded
    /// origin become). Default 50.
    #[serde(default = "default_cb_error_rate")]
    pub error_rate_pct: u32,
    /// ...and at least this many requests were seen in it, so a quiet upstream is not
    /// tripped by one error (>= 1). Default 20.
    #[serde(default = "default_cb_min_requests")]
    pub min_requests: u32,
    /// Sliding window in seconds (1..=60). Default 10.
    #[serde(default = "default_cb_window")]
    pub window_secs: u32,
    /// Seconds the circuit stays open before one probe request is let through (1..=3600).
    /// While open, requests get `503` with `Retry-After`. Default 30.
    #[serde(default = "default_cb_open")]
    pub open_secs: u32,
}

fn default_cb_error_rate() -> u32 {
    50
}
fn default_cb_min_requests() -> u32 {
    20
}
fn default_cb_window() -> u32 {
    10
}
fn default_cb_open() -> u32 {
    30
}

impl CircuitBreakerConfig {
    pub fn to_runtime(&self) -> crate::breaker::BreakerCfg {
        crate::breaker::BreakerCfg {
            error_rate_pct: self.error_rate_pct,
            min_requests: self.min_requests,
            window_secs: self.window_secs,
            open_secs: self.open_secs,
        }
    }

    fn errors(&self, name: &str) -> Vec<String> {
        let mut e = Vec::new();
        if !(1..=100).contains(&self.error_rate_pct) {
            e.push(format!(
                "upstream.{name}.circuit_breaker.error_rate_pct must be 1..=100"
            ));
        }
        if self.min_requests == 0 {
            e.push(format!(
                "upstream.{name}.circuit_breaker.min_requests must be >= 1"
            ));
        }
        if !(1..=crate::breaker::MAX_WINDOW_SECS).contains(&self.window_secs) {
            e.push(format!(
                "upstream.{name}.circuit_breaker.window_secs must be 1..={}",
                crate::breaker::MAX_WINDOW_SECS
            ));
        }
        if !(1..=3600).contains(&self.open_secs) {
            e.push(format!(
                "upstream.{name}.circuit_breaker.open_secs must be 1..=3600"
            ));
        }
        e
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(try_from = "RawUpstream")]
pub struct UpstreamConfig {
    /// Endpoints in failover order, **never empty**. `url` and `urls` are two
    /// spellings of the same thing and are merged once, here: `urls` first, then
    /// `url` if both were written. An upstream with neither is refused at parse
    /// time, so no code past the loader can see an empty list.
    urls: Vec<String>,
    /// TCP connect deadline for this upstream, in milliseconds (default 3000, `0`
    /// = none). It is applied to the connector of the HTTP client used for routes
    /// that point here, so a black-holed member (packets dropped, no RST) is
    /// abandoned after this long and the next HA member is tried, instead of
    /// costing the full request timeout per attempt. It covers the TCP connect
    /// only; the TLS handshake and the response are bounded by `request_timeout_ms`.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    /// How long one attempt may take from sending the request to receiving the upstream's
    /// response headers, in milliseconds (default 30000). On expiry the client gets `504`
    /// (or, in a pool, the next member is tried for an idempotent request). It does not
    /// bound the response body once it is streaming, nor `sse_stream` and `websocket`
    /// routes. Raise it for long-polling or slow report endpoints, lower it for an API
    /// that should fail fast; like nginx `proxy_read_timeout` up to the first byte.
    /// `None` (omitted) is the default, [`crate::proxy::DEFAULT_REQUEST_TIMEOUT_MS`].
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
    #[serde(default = "default_keepalive")]
    pub keepalive: usize,
    #[serde(default)]
    pub tls: bool, // backend is HTTPS
    /// Client certificate for upstream mTLS (Zion → backend).
    #[serde(default)]
    pub client_cert_path: Option<String>,
    /// Client key for upstream mTLS.
    #[serde(default)]
    pub client_key_path: Option<String>,
    /// Opt-in circuit breaker (see [`CircuitBreakerConfig`]).
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    /// How a pool of several endpoints picks a member (default `p2c`).
    #[serde(default)]
    pub load_balancing: LoadBalancing,
    /// Opt-in passive health for a pool: eject a member that is failing in-band.
    #[serde(default)]
    pub outlier_detection: Option<OutlierDetectionConfig>,
    /// Opt-in concurrency cap for this upstream (the whole pool): at most this many requests
    /// are inside it at once, the next gets `503` + `Retry-After` immediately. Counts `standard`
    /// and `sse_stream` requests until their response has been sent; `static_cache` and
    /// `websocket` routes are not counted. Omit for no limit.
    #[serde(default)]
    pub max_in_flight: Option<u32>,
    /// Send the client's `Host` (as received; the HTTP/2 `:authority` for HTTP/2 clients)
    /// to this upstream instead of the upstream's own authority, like nginx
    /// `proxy_set_header Host $http_host`. This upstream is then spoken to over HTTP/1.1
    /// only (HTTP/2 cannot carry a `Host` that differs from `:authority`); TLS still
    /// verifies the upstream's own name. Default `false` (ADR-0024).
    #[serde(default)]
    pub preserve_host: bool,
    /// The `Host` the active health probe sends (default: the endpoint's own authority).
    /// Set it with `preserve_host` when the backend refuses unknown hosts (Django
    /// `ALLOWED_HOSTS`): it would answer the probe 4xx and be marked down.
    #[serde(default)]
    pub health_host: Option<String>,
}

impl TryFrom<RawUpstream> for UpstreamConfig {
    type Error = String;

    fn try_from(raw: RawUpstream) -> Result<Self, String> {
        let mut urls = raw.urls;
        if let Some(u) = raw.url {
            urls.push(u);
        }
        if urls.is_empty() {
            return Err(
                "an upstream needs at least one endpoint: set `url = \"http://host:port\"` \
                 or `urls = [\"http://a:1\", \"http://b:2\"]`"
                    .to_string(),
            );
        }
        Ok(Self {
            urls,
            connect_timeout_ms: raw.connect_timeout_ms,
            request_timeout_ms: raw.request_timeout_ms,
            keepalive: raw.keepalive,
            tls: raw.tls,
            client_cert_path: raw.client_cert_path,
            client_key_path: raw.client_key_path,
            circuit_breaker: raw.circuit_breaker,
            load_balancing: raw.load_balancing,
            outlier_detection: raw.outlier_detection,
            max_in_flight: raw.max_in_flight,
            preserve_host: raw.preserve_host,
            health_host: raw.health_host,
        })
    }
}

impl UpstreamConfig {
    /// The endpoints, in failover order. Never empty.
    #[allow(dead_code)]
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    pub fn get_urls(&self) -> Vec<String> {
        self.urls.clone()
    }

    /// The endpoints without cloning them.
    pub(crate) fn urls_ref(&self) -> &[String] {
        &self.urls
    }
}

pub(crate) fn default_connect_timeout() -> u64 {
    3000
}
fn default_keepalive() -> usize {
    crate::proxy::DEFAULT_KEEPALIVE
}
pub(crate) fn default_client_auth() -> String {
    "none".to_string()
}

// ============================================================================
// WAF PROFILES (layered, named, per-route)
// ============================================================================

// `WafMode` and `WafProfile` are defined in `crate::waf` (their semantic home
// — they're the inputs the scanner consumes). Re-exported here so existing
// `config::WafProfile` import sites keep working unchanged. The move was
// driven by the microbench harness (issue #54): the bench needs to construct
// a profile via the lib surface without dragging the full config-loader
// dependency graph (auth, security, audit, sovereign).
#[allow(unused_imports)]
// `WafMode` re-exported for downstream/test code; bin uses `crate::waf::WafMode`.
pub use crate::waf::{WafMode, WafProfile};

// ============================================================================
// CACHE PROFILES
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
pub struct CacheProfile {
    #[serde(default = "default_cache_mode")]
    pub mode: CacheMode,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    /// Largest response body, in MiB, this profile will store. A bigger one is streamed
    /// to the client and never cached, so one large object cannot push thousands of
    /// small ones out. Default 50; must be at least 1. A declared `Content-Length`
    /// over the limit skips buffering altogether.
    #[serde(default = "default_max_object_mb")]
    pub max_object_mb: u64,
    /// Sort the query parameters in the CACHE KEY, so `?b=2&a=1` and `?a=1&b=2` share an
    /// entry. Off by default: it is only safe when the origin does not care about the
    /// order of parameters. Parameters with the same name keep their relative order, and
    /// the upstream is always sent the query exactly as the client wrote it.
    #[serde(default)]
    pub normalize_query: bool,
}

pub(crate) fn default_max_object_mb() -> u64 {
    50
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    Memory,
    None,
}

fn default_cache_mode() -> CacheMode {
    CacheMode::Memory
}
pub(crate) fn default_max_entries() -> usize {
    10_000
}
pub(crate) fn default_ttl() -> u64 {
    // Conservative heuristic-freshness default (RFC 9111 §4.2.2) for a
    // static_cache route that names no explicit lifetime: cache for 1 hour, not
    // a year. A header-less origin response must not be frozen (the audiolibri
    // staleness root cause) — set `ttl_seconds` explicitly for longer/immutable.
    3600
} // 1 hour

// ============================================================================
// ROUTE CONFIG
// ============================================================================

/// A `[[route]]` table exactly as written: every field is a flat sibling, so
/// contradictory combinations (a static route with no `serve_dir`, `waf = true`
/// next to a `waf_profile`, …) are *representable* here. It is only ever an input
/// to [`RouteConfig`], whose `TryFrom` refuses those combinations, so no value of
/// the real type can hold one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    path: String,
    #[serde(default)]
    hosts: Option<Vec<String>>,
    #[serde(default)]
    upstream: String,
    #[serde(default)]
    mode: RouteMode,
    serve_dir: Option<String>,
    #[serde(default)]
    spa_fallback: bool,
    #[serde(default)]
    precompressed: bool,
    #[serde(default)]
    internal_only: bool,
    waf_profile: Option<String>,
    cache_profile: Option<String>,
    csp: Option<String>,
    auth_profile: Option<String>,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    waf: bool,
    max_body_mb: Option<u64>,
    #[serde(default)]
    waf_shadow: bool,
    cors: Option<CorsConfig>,
}

/// What a route serves. The two arms carry disjoint data, so a static route cannot
/// have an upstream and a proxy route cannot have a `serve_dir`.
#[derive(Clone, Debug, PartialEq)]
pub enum RouteTarget {
    /// Proxy to the named `[upstream.*]` / `[upstreams]` entry. The name is
    /// resolved against the rest of the config in `validate_config`.
    Upstream { name: String, mode: UpstreamMode },
    /// Serve files from a local directory (ADR-0015); no upstream.
    Static {
        /// Never empty.
        serve_dir: String,
        /// Serve `index.html` for any path that maps to no file (SPA fallback).
        spa_fallback: bool,
        /// Serve a `.br`/`.gz` sidecar when the client's `Accept-Encoding` allows.
        precompressed: bool,
    },
}

/// The proxying flavours of a route (everything in [`RouteMode`] except `static`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamMode {
    Standard,
    SseStream,
    StaticCache,
    Websocket,
}

impl From<UpstreamMode> for RouteMode {
    fn from(m: UpstreamMode) -> Self {
        match m {
            UpstreamMode::Standard => RouteMode::Standard,
            UpstreamMode::SseStream => RouteMode::SseStream,
            UpstreamMode::StaticCache => RouteMode::StaticCache,
            UpstreamMode::Websocket => RouteMode::Websocket,
        }
    }
}

/// The route's WAF setting. `waf`, `waf_profile` and `max_body_mb` are one policy
/// decision in the TOML, three sibling keys; here it is one value.
#[derive(Clone, Debug, PartialEq)]
pub enum WafPolicy {
    /// No WAF on this route. `ignored_max_body_mb` keeps a `max_body_mb` that was
    /// written anyway, only so the boot warning ("not enforced") can name it.
    Off { ignored_max_body_mb: Option<u64> },
    /// Legacy `waf = true`: an inline default profile with an optional body cap
    /// (default 10 MiB).
    Inline { max_body_mb: Option<u64> },
    /// `waf_profile = "name"`: a named `[waf_profile.*]`, which carries its own
    /// body cap.
    Profile(String),
}

impl WafPolicy {
    /// Is any WAF attached to this route?
    pub fn is_enabled(&self) -> bool {
        !matches!(self, WafPolicy::Off { .. })
    }
}

/// One `[[route]]`, validated at parse time (see [`RawRoute`]).
#[derive(Deserialize, Clone, Debug)]
#[serde(try_from = "RawRoute")]
pub struct RouteConfig {
    pub path: String,

    /// Optional Host/authority bindings (ADR-0010). When set, this route is
    /// served only for these hosts; when unset, the route is a *shared* route
    /// matching every host (the hostless fallback layer). Entries are bare
    /// hostnames — validated as fixed points of
    /// [`crate::security::normalize_host`] (lowercase modulo case-folding, no
    /// scheme/path/port/trailing dot) so a config key and a normalized request
    /// authority compare in the same form.
    pub hosts: Option<Vec<String>>,

    /// Where the route sends (or serves) requests.
    pub target: RouteTarget,
    pub internal_only: bool,

    /// The WAF policy (`waf`, `waf_profile`, `max_body_mb`).
    pub waf: WafPolicy,
    /// Shadow mode: run WAF checks but do NOT block on violation.
    /// Each would-be denial is logged (`logging::warn`) with the matched
    /// reason and counted in the `waf_shadow_would_block` metric. Lets
    /// operators migrating from nginx/ModSecurity test their WAF profile
    /// against real traffic for hours/days before flipping to enforce.
    /// Has no effect when no WAF is attached to the route.
    pub waf_shadow: bool,

    pub cache_profile: Option<String>,

    /// Per-route Content-Security-Policy header. If set, injected into responses.
    /// If unset, upstream CSP is passed through unmodified.
    pub csp: Option<String>,

    /// Auth profile name for JWT/OIDC validation.
    /// If set, requests must carry a valid Bearer token.
    pub auth_profile: Option<String>,

    /// Declares the route deliberately unauthenticated. Only meaningful with
    /// `[server] require_route_auth = true`, where it is the explicit opt-out.
    /// Cannot be combined with `auth_profile`.
    pub public: bool,

    /// Per-route CORS configuration. If unset, no CORS headers are injected.
    pub cors: Option<CorsConfig>,
}

impl RouteConfig {
    /// The `mode` this route was written with, derived from its target.
    pub fn mode(&self) -> RouteMode {
        match &self.target {
            RouteTarget::Static { .. } => RouteMode::Static,
            RouteTarget::Upstream { mode, .. } => (*mode).into(),
        }
    }

    /// The upstream this route proxies to; `None` for a static route.
    pub fn upstream_name(&self) -> Option<&str> {
        match &self.target {
            RouteTarget::Upstream { name, .. } => Some(name),
            RouteTarget::Static { .. } => None,
        }
    }
}

impl TryFrom<RawRoute> for RouteConfig {
    type Error = String;

    fn try_from(r: RawRoute) -> Result<Self, String> {
        let path = r.path;

        // ---- target: an upstream, or a directory — never a mixture ----
        let target = if r.mode == RouteMode::Static {
            let serve_dir = r
                .serve_dir
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("route '{path}' is mode=static but has no serve_dir"))?;
            // A static route serves from disk and needs no upstream; refuse a
            // non-empty one so the mismatch is a boot error, not a surprise.
            if !r.upstream.is_empty() {
                return Err(format!(
                    "route '{path}' is mode=static but sets upstream = '{}' — a static route \
                     serves from serve_dir and ignores upstream; remove it",
                    r.upstream
                ));
            }
            RouteTarget::Static {
                serve_dir,
                spa_fallback: r.spa_fallback,
                precompressed: r.precompressed,
            }
        } else {
            // serve_dir / spa_fallback / precompressed are honoured ONLY under
            // mode=static; anywhere else they would be silently ignored and the
            // operator expecting disk serving would get proxy behaviour.
            let mut static_only = Vec::new();
            if r.serve_dir.as_deref().is_some_and(|s| !s.is_empty()) {
                static_only.push("serve_dir");
            }
            if r.spa_fallback {
                static_only.push("spa_fallback");
            }
            if r.precompressed {
                static_only.push("precompressed");
            }
            if !static_only.is_empty() {
                return Err(format!(
                    "route '{path}' is mode={:?} but sets static-only field(s) {static_only:?}; \
                     these apply only to mode=static and would be silently ignored — set \
                     mode = \"static\" or remove them",
                    r.mode
                ));
            }
            let mode = match r.mode {
                RouteMode::Standard => UpstreamMode::Standard,
                RouteMode::SseStream => UpstreamMode::SseStream,
                RouteMode::StaticCache => UpstreamMode::StaticCache,
                RouteMode::Websocket => UpstreamMode::Websocket,
                RouteMode::Static => unreachable!("handled by the branch above"),
            };
            RouteTarget::Upstream {
                name: r.upstream,
                mode,
            }
        };

        if r.public && r.auth_profile.is_some() {
            return Err(format!(
                "route '{path}' sets both `public = true` and `auth_profile` — pick one"
            ));
        }

        // ---- WAF: one policy, not three keys ----
        let waf = match (r.waf_profile, r.waf) {
            (Some(_), true) => {
                return Err(format!(
                    "route '{path}' sets both `waf = true` and `waf_profile` — the profile wins \
                     and `waf = true` (with its inline max_body_mb) has no effect; remove `waf = true`"
                ));
            }
            (Some(_), false) if r.max_body_mb.is_some() => {
                return Err(format!(
                    "route '{path}' sets `max_body_mb` together with `waf_profile` — the profile \
                     carries its own body cap and the route-level value has no effect; set \
                     `max_body_mb` inside the [waf_profile] instead"
                ));
            }
            (Some(name), false) => WafPolicy::Profile(name),
            (None, true) => WafPolicy::Inline {
                max_body_mb: r.max_body_mb,
            },
            (None, false) => WafPolicy::Off {
                ignored_max_body_mb: r.max_body_mb,
            },
        };

        Ok(Self {
            path,
            hosts: r.hosts,
            target,
            internal_only: r.internal_only,
            waf,
            waf_shadow: r.waf_shadow,
            cache_profile: r.cache_profile,
            csp: r.csp,
            auth_profile: r.auth_profile,
            public: r.public,
            cors: r.cors,
        })
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    #[default]
    Standard,
    SseStream,
    StaticCache,
    Websocket,
    /// Serve files from a local directory (`serve_dir`); no upstream. ADR-0015.
    Static,
}

// ============================================================================
// LOADING & BUILDING
// ============================================================================

/// Read the file's declared `schema_version` FIRST, before the strict typed
/// parse — a lenient probe that ignores every other key. If the file targets a
/// NEWER schema than this binary understands, return targeted upgrade guidance
/// rather than letting the strict parse fail on an unknown key it can't explain.
/// A missing, older, or equal version is accepted (the strict parse then runs).
pub fn check_schema_version(raw: &str, label: &str) -> Result<(), String> {
    // No deny_unknown_fields: this probe deliberately tolerates every other key.
    #[derive(Deserialize)]
    struct SchemaProbe {
        #[serde(default)]
        schema_version: Option<u32>,
    }
    // A malformed TOML is reported by the real parse with a better message; the
    // probe stays silent on parse errors so we don't double-report.
    if let Ok(probe) = toml::from_str::<SchemaProbe>(raw) {
        if let Some(v) = probe.schema_version {
            if v == 0 {
                return Err(format!(
                    "{label}: schema_version = 0 is not a valid schema (versions start at \
                     {LEGACY_SCHEMA_VERSION}); omit the key for an unversioned file"
                ));
            }
            if v > CURRENT_SCHEMA_VERSION {
                return Err(format!(
                    "{label}: config declares schema_version = {v}, but this zion supports up to \
                     {CURRENT_SCHEMA_VERSION}. Upgrade zion to a build that understands schema \
                     {v}, or target the older schema (see the CHANGELOG for the config changes \
                     between schema versions)."
                ));
            }
        }
    }
    Ok(())
}

/// Parse one config document: version handshake, the strict typed parse, then the
/// per-version reader. Every loader goes through here so no path can skip the
/// migration step.
fn parse_document(raw: &str, label: &str) -> Result<ZionConfig, String> {
    check_schema_version(raw, label)?;
    let config: ZionConfig = toml::from_str(raw)
        .map_err(|e| format!("Invalid TOML in {label}: {}", describe_toml_error(&e, raw)))?;
    upgrade_schema(config).map_err(|e| format!("{label}: {e}"))
}

/// A TOML error as `line L, column C: message`, without the excerpt of the source line the
/// `toml` crate prints, and without the string value serde quotes in a type error.
///
/// The excerpt is the offending line verbatim, and that line can be `secret = "..."` or
/// `ip_hmac_key = "..."`: a typo next to a secret would copy it to the log, to the answer of
/// a rejected `POST /admin/config` and to the audit trail. The position is enough to find it.
pub(crate) fn describe_toml_error(e: &toml::de::Error, raw: &str) -> String {
    let message = mask_quoted_values(e.message());
    match e.span() {
        Some(span) => {
            let upto = &raw[..span.start.min(raw.len())];
            let line = upto.bytes().filter(|b| *b == b'\n').count() + 1;
            let column = upto.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            format!("line {line}, column {column}: {message}")
        }
        None => message,
    }
}

/// serde reports a value of the wrong type as `invalid type: string "the value", expected ..`:
/// the value may be a secret pasted into the wrong field. Keep the kind, drop the content.
fn mask_quoted_values(message: &str) -> String {
    const MARK: &str = "string \"";
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find(MARK) {
        out.push_str(&rest[..at]);
        out.push_str("a string");
        let after = &rest[at + MARK.len()..];
        // The value is printed with `{:?}`: its end is the first quote not preceded by `\`.
        let mut end = after.len();
        let mut escaped = false;
        for (i, c) in after.char_indices() {
            match c {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    end = i + 1;
                    break;
                }
                _ => escaped = false,
            }
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Bring a config that was written for schema `config.schema_version` up to the
/// current shape. There is one arm per supported version, so bumping
/// `CURRENT_SCHEMA_VERSION` without adding its reader here fails the
/// `every_supported_schema_version_has_a_reader` test instead of silently
/// misreading old files. Only schema 1 exists today, so this is the identity.
fn upgrade_schema(config: ZionConfig) -> Result<ZionConfig, String> {
    match config.schema_version {
        1 => Ok(config),
        v => Err(format!(
            "no reader for schema_version {v} (this build supports 1..={CURRENT_SCHEMA_VERSION})"
        )),
    }
}

pub fn load_config(path: &str) -> Result<ZionConfig, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let config = parse_document(&raw, path)?;
    validate_config(&config, path)?;
    Ok(config)
}

/// Schema-level round-trip: does this config string deserialize into the typed
/// `ZionConfig` (serde + `deny_unknown_fields`)? This is what `zion suggest`
/// self-validates against before emitting — the issue-#133 guarantee that the
/// *parser* never rejects a generated config. It deliberately does NOT run
/// `validate_config` (which checks runtime facts like cert-file existence): a
/// suggested config carries placeholder cert paths the operator fills in, so
/// file existence isn't a schema concern.
pub fn parse_schema(raw: &str, label: &str) -> Result<ZionConfig, String> {
    parse_document(raw, label)
}

/// Full validation of a config from an in-memory string — the same schema AND
/// semantic checks `load_config` runs (route refs, CIDRs, cert-file existence,
/// …), minus the file read. Used by the admin API's `POST /admin/config`, where
/// the pushed body must be fully deployable (real cert paths and all), unlike
/// `zion suggest` which only needs the schema-level [`parse_schema`].
pub fn validate_str(raw: &str, label: &str) -> Result<ZionConfig, String> {
    let config = parse_document(raw, label)?;
    validate_config(&config, label)?;
    Ok(config)
}

/// An upstream URL must parse AND use http/https. A scheme-less `host:port` or
/// an `ftp://`/`ws://` URL parses as a valid `Uri` but fails cryptically at the
/// first proxied request, so reject it at startup with an actionable message.
/// Returns `Some(error)` on rejection, `None` when valid.
fn validate_upstream_url(label: &str, url: &str) -> Option<String> {
    // The message goes to the log, the admin API's answer and the audit trail: it must not
    // carry the credentials an upstream URL may hold.
    let shown = crate::http_util::redact_userinfo(url);
    match url.parse::<hyper::Uri>() {
        Err(_) => Some(format!("{label} '{shown}' is not a valid URL")),
        Ok(uri) => match uri.scheme_str() {
            Some("http") | Some("https") => None,
            other => Some(format!(
                "{label} '{shown}' must use http:// or https:// (got {})",
                other.unwrap_or("no scheme")
            )),
        },
    }
}

/// A route `hosts` entry must be a canonical bare host — a fixed point of
/// [`crate::security::normalize_host`] (ADR-0010): lowercase modulo case
/// folding, with no scheme, path, port, or trailing FQDN dot. That guarantees
/// the host-routing key equals the normalized request authority the dispatcher
/// will look up, so a subtly-different config entry (a stray `:443`, an
/// uppercased or dotted FQDN) can never silently fail to match. Uppercase is
/// accepted and folded; anything else non-canonical is rejected. Returns
/// `Some(error)` on rejection, `None` when valid.
fn validate_host_entry(label: &str, host: &str) -> Option<String> {
    // A leading-label wildcard `*.example.com` is valid: validate the domain
    // after `*.` as a canonical bare host (ADR-0010).
    if let Some(domain) = host.strip_prefix("*.") {
        if domain.is_empty() || domain.contains('*') {
            return Some(format!(
                "{label} host '{host}': a wildcard must be `*.<domain>` with a \
                 concrete domain (e.g. `*.example.com`)"
            ));
        }
        return bare_host_error(label, host, domain);
    }
    // Any other use of `*` (embedded or trailing) is not supported.
    if host.contains('*') {
        return Some(format!(
            "{label} host '{host}': only leading-label wildcards `*.<domain>` are \
             supported (not embedded or trailing `*`)"
        ));
    }
    bare_host_error(label, host, host)
}

/// Shared fixed-point check for a bare host: `candidate` must be canonical under
/// [`crate::security::normalize_host`] (modulo case folding). `original` is the
/// raw entry, used only in the error message. Returns `Some(error)` on
/// rejection, `None` when valid.
fn bare_host_error(label: &str, original: &str, candidate: &str) -> Option<String> {
    let lower = candidate.to_ascii_lowercase();
    if crate::security::normalize_host(candidate).as_deref() == Some(lower.as_str()) {
        None
    } else {
        Some(format!(
            "{label} host '{original}' must be a bare hostname \
             (no scheme, path, port, or trailing dot)"
        ))
    }
}

/// Validate config at startup — fail fast with actionable error messages.
/// Semantic checks first ([`semantic_errors`]), then deploy-time facts
/// ([`deploy_errors`]: referenced files must exist on disk).
fn validate_config(config: &ZionConfig, path: &str) -> Result<(), String> {
    let mut errors = semantic_errors(config);
    errors.extend(deploy_errors(config));
    finish_validation(errors, path)
}

/// Semantic validation only — every check that can run on an in-memory
/// `ZionConfig` without touching the filesystem: listen addresses,
/// route→upstream/profile reference integrity, host bindings (ADR-0010),
/// upstream URL schemes, `[admin]` invariants. `zion import` (ADR-0011) runs
/// this on top of [`parse_schema`]: an imported config carries placeholder
/// cert paths, so the deploy-time file checks cannot apply, but a dangling
/// reference or a malformed host must still refuse to emit.
pub fn validate_semantics(config: &ZionConfig, label: &str) -> Result<(), String> {
    finish_validation(semantic_errors(config), label)
}

fn finish_validation(errors: Vec<String>, label: &str) -> Result<(), String> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "config validation failed ({}):\n  - {}",
            label,
            errors.join("\n  - ")
        ))
    }
}

/// Deploy-time checks: files the config references must exist on disk.
fn deploy_errors(config: &ZionConfig) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    // TLS cert files must exist
    if !std::path::Path::new(&config.tls.cert_path).exists() {
        errors.push(format!(
            "tls.cert_path '{}' does not exist",
            config.tls.cert_path
        ));
    }
    if !std::path::Path::new(&config.tls.key_path).exists() {
        errors.push(format!(
            "tls.key_path '{}' does not exist",
            config.tls.key_path
        ));
    }

    // SNI cert files must exist
    for (i, sni) in config.tls.sni.iter().enumerate() {
        if !std::path::Path::new(&sni.cert_path).exists() {
            errors.push(format!(
                "tls.sni[{}] cert_path '{}' does not exist",
                i, sni.cert_path
            ));
        }
        if !std::path::Path::new(&sni.key_path).exists() {
            errors.push(format!(
                "tls.sni[{}] key_path '{}' does not exist",
                i, sni.key_path
            ));
        }
    }

    errors
}

/// Filesystem-free semantic checks; see [`validate_semantics`].
/// A JWKS URL Zion may fetch signing keys from: `https://`, or `http://` to a loopback
/// host only (a sidecar on the same machine). Decided on the parsed host, so
/// `http://localhost.evil.example` is not mistaken for loopback.
fn jwks_url_is_safe(url: &str) -> bool {
    let Ok(uri) = url.parse::<hyper::Uri>() else {
        return false;
    };
    match (uri.scheme_str(), uri.host()) {
        (Some("https"), Some(_)) => true,
        (Some("http"), Some(host)) => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        _ => false,
    }
}

/// Paths zion answers itself, before route lookup, on every host (see
/// `dispatch::gates::builtin_endpoint`): a route on one of them never receives a request.
pub const BUILT_IN_PATHS: &[&str] = &[
    "/healthz",
    "/readyz",
    "/metrics",
    "/_zion/snapshot.json",
    "/_zion/cache/purge",
];

fn semantic_errors(config: &ZionConfig) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    errors.extend(config.redact.errors());
    // Closed sets that used to fall back silently: an unknown xff_mode ran as `append`
    // (the most permissive), an unknown log_format as `text`.
    if crate::proxy::XffMode::parse(&config.server.xff_mode).is_none() {
        errors.push(format!(
            "server.xff_mode '{}' is not one of append, rewrite, drop",
            config.server.xff_mode
        ));
    }
    if !matches!(config.server.log_format.as_str(), "text" | "json") {
        errors.push(format!(
            "server.log_format '{}' is not one of text, json",
            config.server.log_format
        ));
    }
    // Signing keys fetched over plain http can be swapped by anyone on the path, who can
    // then mint tokens the gateway accepts. Only a loopback JWKS may use http.
    for (name, p) in &config.auth_profile {
        if let Some(url) = &p.jwks_url {
            if !jwks_url_is_safe(url) {
                errors.push(format!(
                    "auth_profile.{name}.jwks_url must use https:// (http is accepted only for a \
                     loopback address), got {:?}",
                    crate::http_util::redact_userinfo(url)
                ));
            }
        }
    }
    // A route that names an auth_profile is meant to be authenticated. A binary built
    // without `--features auth` cannot do that and used to serve it unauthenticated
    // with only a warning: refuse the config instead (fail closed), at boot and on reload.
    #[cfg(not(feature = "auth"))]
    if let Some(route) = config.route.iter().find(|r| r.auth_profile.is_some()) {
        errors.push(format!(
            "route '{}' sets auth_profile, but this binary was built without `--features auth`: \
             it cannot authenticate, and would serve those routes unauthenticated. Use a build \
             with auth (the official release binaries and container include it), or remove \
             auth_profile from the routes",
            route.path
        ));
    }
    for (name, up) in &config.upstream {
        // Documented, parsed, and used by nothing: a config that sets them believed its
        // upstream connections were authenticated. Refuse until it exists (#503).
        if up.client_cert_path.is_some() || up.client_key_path.is_some() {
            errors.push(format!(
                "upstream.{name}: client_cert_path / client_key_path (mTLS to the upstream) are \
                 not supported yet and were never applied: Zion presents no client certificate. \
                 Remove them (see https://github.com/fabriziosalmi/zion/issues/503)"
            ));
        }
        // `tls = true` with an http:// URL used to connect in plaintext: the URL scheme is
        // what decides, so say so instead of sending cleartext the operator did not ask for.
        if up.tls {
            for url in up.urls_ref() {
                if !url.starts_with("https://") {
                    errors.push(format!(
                        "upstream.{name}: tls = true but {:?} is not https:// (the URL scheme \
                         decides; use an https:// URL, and drop `tls`)",
                        crate::http_util::redact_userinfo(url)
                    ));
                }
            }
        }
        // No "0 = none" here: a request with no deadline holds its connection slot until
        // the 1 h connection cap, which is what the timeout exists to prevent.
        if let Some(ms) = up.request_timeout_ms {
            if !(crate::proxy::MIN_REQUEST_TIMEOUT_MS..=crate::proxy::MAX_REQUEST_TIMEOUT_MS)
                .contains(&ms)
            {
                errors.push(format!(
                    "upstream.{name}.request_timeout_ms must be {}..={} (milliseconds until the \
                     upstream's response headers; there is no \"0 = none\"), got {ms}",
                    crate::proxy::MIN_REQUEST_TIMEOUT_MS,
                    crate::proxy::MAX_REQUEST_TIMEOUT_MS,
                ));
            }
        }
        if up.keepalive > 10_000 {
            errors.push(format!(
                "upstream.{name}.keepalive must be 0..=10000 (idle pooled connections per host), got {}",
                up.keepalive
            ));
        }
        if let Some(h) = &up.health_host {
            // A Host value: a host name or address, with an optional port.
            let valid = crate::security::normalize_host(h).is_some()
                && hyper::header::HeaderValue::from_str(h).is_ok()
                && h.trim() == h;
            if !valid {
                errors.push(format!(
                    "upstream.{name}.health_host must be a host name (optionally with :port), got {h:?}"
                ));
            }
        }
        if let Some(n) = up.max_in_flight {
            if !(1..=1_000_000).contains(&n) {
                errors.push(format!(
                    "upstream.{name}.max_in_flight must be 1..=1000000 (omit it for no limit), got {n}"
                ));
            }
        }
        if let Some(cb) = &up.circuit_breaker {
            errors.extend(cb.errors(name));
        }
        if let Some(od) = &up.outlier_detection {
            errors.extend(od.errors(name));
            if up.urls_ref().len() < 2 {
                errors.push(format!(
                    "upstream.{name}.outlier_detection needs a pool of at least two endpoints \
                     (`urls = [...]`); a single endpoint has no peer to be an outlier against \
                     (use `circuit_breaker` for that)"
                ));
            }
        }
    }
    // One URL, one breaker: the health entry (and its breaker) is shared by every upstream
    // that names the URL, so two single-endpoint definitions of it must agree on whether it
    // has a breaker and on its thresholds. Pools and the `[upstreams]` shorthand are listed
    // too: they carry no breaker, so they conflict with a table that has one.
    {
        let mut by_url: std::collections::BTreeMap<
            &str,
            Vec<(String, Option<&CircuitBreakerConfig>)>,
        > = std::collections::BTreeMap::new();
        for (name, up) in &config.upstream {
            if let [u] = up.urls_ref() {
                by_url
                    .entry(u.as_str())
                    .or_default()
                    .push((format!("upstream.{name}"), up.circuit_breaker.as_ref()));
            }
        }
        for (name, url) in &config.upstreams {
            by_url
                .entry(url.as_str())
                .or_default()
                .push((format!("upstreams.{name}"), None));
        }
        for (url, mut defs) in by_url {
            defs.sort_by(|a, b| a.0.cmp(&b.0));
            if defs.windows(2).any(|w| w[0].1 != w[1].1) {
                errors.push(format!(
                    "{} all point at {} but disagree about its circuit breaker; they share one \
                     health entry, so give them the same `circuit_breaker` (or none)",
                    defs.iter()
                        .map(|d| d.0.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    crate::http_util::redact_userinfo(url)
                ));
            }
        }
    }
    for (name, cp) in &config.cache_profile {
        if cp.max_object_mb == 0 {
            errors.push(format!(
                "cache_profile.{name}.max_object_mb must be >= 1 (0 would cache nothing; \
                 use `mode = \"none\"` for that)"
            ));
        }
    }
    if config.server.rate_limit_max_tracked_ips == 0 {
        errors.push(
            "server.rate_limit_max_tracked_ips must be >= 1 (a cap of 0 would deny every new client)"
                .to_string(),
        );
    }

    // Server addresses must parse
    if config
        .server
        .listen_http
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        errors.push(format!(
            "server.listen_http '{}' is not a valid address",
            config.server.listen_http
        ));
    }
    if config
        .server
        .listen_https
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        errors.push(format!(
            "server.listen_https '{}' is not a valid address",
            config.server.listen_https
        ));
    }

    // [tls.fingerprint]: an allowlist that drops every unknown but lists no
    // allowed entries would deny ALL traffic — refuse to boot into a total
    // outage. Only enforced where it would actually bite (feature on); a
    // feature-off build is handled by warn_feature_config_gaps instead.
    #[cfg(feature = "tls-fingerprint")]
    if let Some(fp) = &config.tls.fingerprint {
        if fp.mode == FingerprintMode::Allowlist
            && fp.on_unknown == OnUnknown::Drop
            && fp.allowed.is_empty()
        {
            errors.push(
                "[tls.fingerprint] mode = \"allowlist\" with on_unknown = \"drop\" and an \
                 empty `allowed` list would drop EVERY connection. Add allowed entries, set \
                 on_unknown = \"log_only\", or use mode = \"shadow\"."
                    .to_string(),
            );
        }
        // An ENFORCING allowlist (unknowns dropped) that still lets an
        // UN-fingerprintable ClientHello through fails open: an attacker sends
        // a deliberately malformed hello the parser can't fingerprint and
        // sidesteps the allowlist entirely, defeating the very drop it just
        // configured for unknowns. The `on_unfingerprintable = allow` default
        // is availability-first and inconsistent with `on_unknown = drop`.
        // Refuse to boot into that silent bypass; an observe posture
        // (on_unknown = log_only, or mode = shadow) is unaffected.
        if fp.mode == FingerprintMode::Allowlist
            && fp.on_unknown == OnUnknown::Drop
            && fp.on_unfingerprintable == OnUnfingerprintable::Allow
        {
            errors.push(
                "[tls.fingerprint] mode = \"allowlist\" with on_unknown = \"drop\" but \
                 on_unfingerprintable = \"allow\" fails OPEN — a ClientHello the parser cannot \
                 fingerprint bypasses the allowlist while unknowns are dropped. Set \
                 on_unfingerprintable = \"drop\" to fail closed consistently, or use \
                 on_unknown = \"log_only\" / mode = \"shadow\" to observe without enforcing."
                    .to_string(),
            );
        }
        // A malformed allowlist entry can never match a computed JA4, so under
        // on_unknown = drop it is a silent deny-all the empty-list check above
        // misses. Surface the typo at boot instead of as a production outage.
        for a in &fp.allowed {
            if !crate::tls_fp::looks_like_ja4(&a.ja4) {
                errors.push(format!(
                    "[tls.fingerprint] allowed entry '{}' has an invalid JA4 '{}' \
                     (expected e.g. t13d1516h2_8daaf6152771_e5627efa2ab1)",
                    a.name, a.ja4
                ));
            }
        }
        // allowed_routes patterns must compile (#27 follow-up): a typo'd
        // pattern would otherwise be discovered as a runtime surprise — either
        // a silent no-restriction or a silent deny — instead of a boot error.
        for a in &fp.allowed {
            if !a.allowed_routes.is_empty() {
                if let Err(e) = compile_path_set(&a.allowed_routes) {
                    errors.push(format!(
                        "[tls.fingerprint] allowed entry '{}': {e} (allowed_routes uses \
                         the same pattern syntax as [[route]] path)",
                        a.name
                    ));
                }
            }
        }
        // The entry name becomes the X-Client-TLS-Allowlisted header value
        // (#27 commit 5). HeaderValue::from_str is NOT a sufficient guard —
        // it accepts the empty string and bytes >= 0x80 — so a sloppy name
        // would silently degrade the attestation (header absent or mangled)
        // with zero diagnostics. Refuse anything but non-empty visible ASCII.
        for a in &fp.allowed {
            if a.name.trim().is_empty() || !a.name.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                errors.push(format!(
                    "[tls.fingerprint] allowed entry with ja4 '{}' has an invalid name {:?} — \
                     the name is forwarded as the X-Client-TLS-Allowlisted header and must be \
                     non-empty printable ASCII",
                    a.ja4, a.name
                ));
            }
        }
        // Duplicate JA4s would silently last-win in the runtime's HashMap —
        // harmless when entries only carried a name, but now the surviving
        // entry's rate_limit_cps (or lack of one) silently replaces the
        // other's. Make the collision an operator error instead.
        let mut seen = std::collections::HashMap::new();
        for a in &fp.allowed {
            let norm = a.ja4.trim().to_ascii_lowercase();
            if let Some(first) = seen.insert(norm, &a.name) {
                errors.push(format!(
                    "[tls.fingerprint] entries '{}' and '{}' list the same JA4 '{}' — \
                     merge them (only one would take effect, chosen arbitrarily)",
                    first,
                    a.name,
                    a.ja4.trim()
                ));
            }
        }
        // An absurd ban TTL would overflow `Instant + Duration` on the first
        // ban insert — a panic, and with the release profile's panic=abort a
        // dead proxy. Bans are process-local; "permanent" is not a thing here.
        if fp.ban_ttl_secs > MAX_BAN_TTL_SECS {
            errors.push(format!(
                "[tls.fingerprint] ban_ttl_secs = {} exceeds the maximum {} (1 year). \
                 The ban set is process-local and never outlives a restart — for a \
                 permanent block, remove the fingerprint from `allowed` and keep \
                 on_unknown = \"drop\".",
                fp.ban_ttl_secs, MAX_BAN_TTL_SECS
            ));
        }
    }

    // SNI entries need a subject to match on (file existence is deploy-time)
    for (i, sni) in config.tls.sni.iter().enumerate() {
        if sni.server_name.is_empty() {
            errors.push(format!("tls.sni[{i}] server_name is empty"));
        }
    }

    // A [tls.acme] block must name at least one domain and a non-empty e-mail —
    // an empty one would parse and build a router yet issue nothing at runtime.
    if let Some(acme) = &config.tls.acme {
        if acme.domains.is_empty() {
            errors.push("[tls.acme] must list at least one domain".to_string());
        }
        if acme.email.trim().is_empty() {
            errors.push("[tls.acme] email must not be empty".to_string());
        }
    }

    // Must have at least one route
    if config.route.is_empty() {
        errors.push("no [[route]] defined — at least one route is required".to_string());
    }

    // Route shape (a static route has a serve_dir and no upstream, a proxy route
    // has no static-only fields, `waf` vs `waf_profile`) is enforced at parse time
    // by `RouteConfig`'s TryFrom. What is left here are references that need the
    // rest of the config to resolve.
    for route in &config.route {
        if let Some(name) = route.upstream_name() {
            let has_upstream =
                config.upstream.contains_key(name) || config.upstreams.contains_key(name);
            if !has_upstream {
                errors.push(format!(
                    "route '{}' references unknown upstream '{}'",
                    route.path, name
                ));
            }
        }

        // WAF profile reference must exist
        if let WafPolicy::Profile(profile) = &route.waf {
            if !config.waf_profile.contains_key(profile) {
                errors.push(format!(
                    "route '{}' references unknown waf_profile '{}'",
                    route.path, profile
                ));
            }
        }

        // Cache profile reference must exist
        if let Some(ref profile) = route.cache_profile {
            if !config.cache_profile.contains_key(profile) {
                errors.push(format!(
                    "route '{}' references unknown cache_profile '{}'",
                    route.path, profile
                ));
            }
        }

        if config.server.require_route_auth
            && route.auth_profile.is_none()
            && !route.public
            && !route.internal_only
        {
            errors.push(format!(
                "route '{}' has no auth_profile and [server] require_route_auth = true — \
                 add `auth_profile`, or `public = true` to serve it unauthenticated on purpose \
                 (or `internal_only = true`)",
                route.path
            ));
        }

        // A route on a built-in endpoint is dead: zion answers that path itself first.
        if BUILT_IN_PATHS.contains(&route.path.as_str()) {
            errors.push(format!(
                "route '{}' can never receive a request: zion answers {} itself, before \
                 routing, on every host. Use another path (for example /status), or rely on \
                 the built-in endpoint",
                route.path, route.path
            ));
        }

        // Auth profile reference must exist
        if let Some(ref profile) = route.auth_profile {
            if !config.auth_profile.contains_key(profile) {
                errors.push(format!(
                    "route '{}' references unknown auth_profile '{}'",
                    route.path, profile
                ));
            }
        }

        // Host bindings (ADR-0010): each entry must be a canonical bare host so
        // the routing key matches the normalized request authority. An explicit
        // empty list is meaningless — omit `hosts` for a shared route.
        if let Some(hosts) = &route.hosts {
            if hosts.is_empty() {
                errors.push(format!(
                    "route '{}' has `hosts = []` — omit `hosts` for a shared route, \
                     or list at least one host",
                    route.path
                ));
            }
            for h in hosts {
                if let Some(e) = validate_host_entry(&format!("route '{}'", route.path), h) {
                    errors.push(e);
                }
            }
        }
    }

    // Upstream URLs must be valid
    for (name, up) in &config.upstream {
        // (an upstream with no endpoint is refused at parse time, see UpstreamConfig)
        for u in up.get_urls() {
            if u.parse::<hyper::Uri>().is_err() {
                errors.push(format!("upstream.{name}.url '{u}' is not a valid URL"));
            }
        }
    }
    // Both upstream styles must use http/https (legacy flat map + structured).
    for (name, url) in &config.upstreams {
        if let Some(e) = validate_upstream_url(&format!("upstreams.{name}"), url) {
            errors.push(e);
        }
    }
    for (name, up) in &config.upstream {
        for url in up.get_urls() {
            if let Some(e) = validate_upstream_url(&format!("upstream.{name}"), &url) {
                errors.push(e);
            }
        }
    }

    // [server] internal_networks — a bad entry must be an error: dropping it would
    // leave the list shorter, or empty, and an empty list means the permissive
    // built-in "any private address" rule.
    for cidr in &config.server.internal_networks {
        if !crate::security::is_valid_cidr(cidr) {
            errors.push(format!(
                "server.internal_networks '{cidr}' is not a valid CIDR (e.g. \"10.20.0.0/24\" or \"127.0.0.1\")"
            ));
        }
    }

    // [admin] — listen must be a real socket address; auth a known mode.
    if let Some(ref admin) = config.admin {
        if admin.listen.parse::<std::net::SocketAddr>().is_err() {
            errors.push(format!(
                "admin.listen '{}' is not a valid socket address (e.g. 127.0.0.1:9180)",
                admin.listen
            ));
        }
        match admin.auth.as_str() {
            "internal-ip" => {
                // `internal-ip` authorizes any loopback/private-range *peer*, and the
                // authorized peer can replace the whole running config. Bound to a
                // routable address (or published from a container, where a bridge
                // SNATs every client to a private address) that is every host on the
                // network, so it is only safe on loopback. Routable binds need mtls.
                if let Ok(addr) = admin.listen.parse::<std::net::SocketAddr>() {
                    if !addr.ip().is_loopback() {
                        errors.push(format!(
                            "admin.listen '{}' is not a loopback address but admin.auth = \"internal-ip\" \
                             trusts every private-range peer, and that peer can replace the whole config. \
                             Bind 127.0.0.1 (reach it over an SSH tunnel or a sidecar) or set admin.auth = \"mtls\"",
                            admin.listen
                        ));
                    }
                }
            }
            "mtls" => {}
            other => errors.push(format!(
                "admin.auth '{other}' must be \"internal-ip\" or \"mtls\""
            )),
        }
        if admin.rate_limit_rps == 0 {
            errors.push("admin.rate_limit_rps must be > 0".to_string());
        }
        // mTLS needs its own CA: with the data-plane one, every client certificate
        // issued to call the gateway would also authorize config pushes.
        if admin.auth == "mtls" && admin.client_ca_path.is_none() {
            errors.push(
                "admin.auth = \"mtls\" requires admin.client_ca_path: the CA that signs ADMIN \
                 client certificates (not tls.client_ca_path, whose data-plane client \
                 certificates would otherwise open the admin API too)"
                    .to_string(),
            );
        }
    }

    // `client_auth` is a closed set; a typo would silently coerce to "none"
    // (no client auth) — reject an unknown value so it fails closed at boot.
    if !matches!(
        config.tls.client_auth.as_str(),
        "none" | "required" | "optional"
    ) {
        errors.push(format!(
            "tls.client_auth '{}' must be \"none\", \"required\", or \"optional\"",
            config.tls.client_auth
        ));
    }
    // Data-plane mTLS: `client_auth = required|optional` needs a CA to verify
    // presented client certs against. Without `tls.client_ca_path` the listener
    // silently builds with NO client auth (fail-open) — the enforcement the
    // operator asked for would be off with no signal. Reject it at boot.
    // A CRL nobody consults is a revocation the operator believes in and Zion ignores.
    if config.tls.client_crl_path.is_some()
        && !matches!(config.tls.client_auth.as_str(), "required" | "optional")
    {
        errors.push(
            "tls.client_crl_path is set but tls.client_auth is \"none\": no client certificate \
             is verified, so nothing would be checked against the CRL"
                .to_string(),
        );
    }
    if let Some(admin) = &config.admin {
        if admin.client_crl_path.is_some() && admin.auth != "mtls" {
            errors.push(
                "admin.client_crl_path is set but admin.auth is not \"mtls\": no client \
                 certificate is verified, so nothing would be checked against the CRL"
                    .to_string(),
            );
        }
    }
    if matches!(config.tls.client_auth.as_str(), "required" | "optional")
        && config.tls.client_ca_path.is_none()
    {
        errors.push(format!(
            "tls.client_auth = \"{}\" requires tls.client_ca_path (the CA that verifies \
             presented client certificates); without it client-cert enforcement is silently off",
            config.tls.client_auth
        ));
    }

    // [sovereign_aimp] — when the mesh is enabled and a listen address is set
    // in TOML, it MUST parse. Previously a malformed value silently fell back
    // to `0.0.0.0:9443` at boot, binding the gossip control plane to every
    // interface — a fat-fingered address would quietly expose it to the
    // internet. Fail validation instead of guessing a (world-open) default.
    // The mesh accepts reputation claims that can get clients refused: only from
    // nodes the operator named. Without the list, anyone who reaches the UDP port
    // could mint a key and inject scores.
    #[cfg(feature = "sovereign-aimp")]
    if config.sovereign_aimp.enabled {
        if config.sovereign_aimp.trusted_keys.is_empty() {
            errors.push(
                "sovereign_aimp.enabled = true needs sovereign_aimp.trusted_keys: the node ids \
                 (64 hex characters each node prints at boot as `node_id=`) whose claims are \
                 accepted"
                    .to_string(),
            );
        }
        for k in &config.sovereign_aimp.trusted_keys {
            if crate::aimp_cp::parse_node_key(k).is_none() {
                errors.push(format!(
                    "sovereign_aimp.trusted_keys entry {k:?} is not a node id (64 hex characters)"
                ));
            }
        }
    }
    #[cfg(feature = "sovereign-aimp")]
    if config.sovereign_aimp.enabled && !config.sovereign_aimp.listen.is_empty() {
        if let Err(e) = config.sovereign_aimp.listen.parse::<std::net::SocketAddr>() {
            errors.push(format!(
                "sovereign_aimp.listen '{}' is not a valid socket address (e.g. 127.0.0.1:9443): {e}",
                config.sovereign_aimp.listen
            ));
        }
    }

    // An upstream name defined in BOTH the structured `[upstream.<name>]` map
    // and the legacy flat `[upstreams]` map is ambiguous: resolve_upstream
    // silently prefers the structured one and drops the legacy URL, so two
    // divergent definitions can coexist with zero diagnostics. Reject the
    // collision so the operator picks one home for the name.
    for name in config.upstream.keys() {
        if config.upstreams.contains_key(name) {
            errors.push(format!(
                "upstream '{name}' is defined in both [upstream.{name}] and [upstreams]; \
                 remove one — the legacy [upstreams] entry would be silently ignored"
            ));
        }
    }

    errors
}

/// If `path` is a matchit catch-all (`<prefix>/{*name}`), return the bare
/// prefix the catch-all should also serve (`/` for a root catch-all). matchit's
/// catch-all does not match the bare prefix, so without registering it a
/// `/{*rest}` route returns 404 on `/` — surprising for a "match everything"
/// fallback. Returns `None` for non-catch-all paths.
pub(crate) fn catchall_bare_prefix(path: &str) -> Option<String> {
    let slash = path.rfind('/')?;
    let seg = &path[slash + 1..];
    if seg.starts_with("{*") && seg.ends_with('}') {
        Some(if slash == 0 {
            "/".to_string()
        } else {
            path[..slash].to_string()
        })
    } else {
        None
    }
}

/// The trailing-slash-toggled variant of an explicit (non-catch-all) route
/// path, registered as a best-effort alias so "/x" and "/x/" resolve to the
/// SAME route. matchit treats them as distinct, so without this "/x/" falls
/// through to whatever broader route matches — silently downgrading a stricter
/// per-route WAF profile. Returns `None` for the bare root "/".
pub(crate) fn trailing_slash_variant(path: &str) -> Option<String> {
    if path == "/" {
        None
    } else if let Some(stripped) = path.strip_suffix('/') {
        Some(stripped.to_string())
    } else {
        Some(format!("{path}/"))
    }
}

/// Compile a set of route-path patterns into a bare matcher with the SAME
/// alias semantics as the request router (bare prefix for catch-alls,
/// trailing-slash variant otherwise — see `RouterBuilder::insert`). Used by
/// `[tls.fingerprint]` `allowed_routes` (#27 follow-up) so a restriction list
/// matches paths exactly the way `[[route]] path` does — two pattern dialects
/// in one config would be a trap. Alias inserts are best-effort, mirroring
/// `RouterBuilder::finish`.
#[allow(dead_code)] // read only under `--features tls-fingerprint`
pub(crate) fn compile_path_set(patterns: &[String]) -> Result<matchit::Router<()>, String> {
    let mut router = matchit::Router::new();
    let mut aliases: Vec<String> = Vec::new();
    for p in patterns {
        router
            .insert(p.clone(), ())
            .map_err(|e| format!("bad route pattern '{p}': {e}"))?;
        match catchall_bare_prefix(p) {
            Some(bare) => aliases.push(bare),
            None => {
                if let Some(v) = trailing_slash_variant(p) {
                    aliases.push(v);
                }
            }
        }
    }
    for a in aliases {
        let _ = router.insert(a, ());
    }
    Ok(router)
}

#[cfg(test)]
mod tests {
    #[test]
    fn pool_balancing_and_outlier_config() {
        let cfg = |up: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.p]\n{up}\n\
                 [[route]]\npath=\"/{{*r}}\"\nupstream=\"p\"\n"
            )
        };
        let pool = "urls=[\"http://a:1\",\"http://b:2\"]";
        let d: ZionConfig = toml::from_str(&cfg(pool)).unwrap();
        assert_eq!(
            d.upstream["p"].load_balancing,
            LoadBalancing::P2c,
            "p2c is the default"
        );
        assert!(
            d.upstream["p"].outlier_detection.is_none(),
            "outlier detection is opt-in"
        );
        let ll: ZionConfig = toml::from_str(&cfg(&format!(
            "{pool}\nload_balancing = \"lowest_latency\""
        )))
        .unwrap();
        assert_eq!(
            ll.upstream["p"].load_balancing,
            LoadBalancing::LowestLatency
        );
        assert!(toml::from_str::<ZionConfig>(&cfg(&format!(
            "{pool}\nload_balancing = \"round_robin\""
        )))
        .is_err());
        let od: ZionConfig =
            toml::from_str(&cfg(&format!("{pool}\noutlier_detection = {{}}"))).unwrap();
        let o = od.upstream["p"].outlier_detection.clone().unwrap();
        assert_eq!(
            (
                o.error_rate_pct,
                o.min_requests,
                o.window_secs,
                o.eject_secs,
                o.max_ejected_pct
            ),
            (50, 20, 10, 30, 50)
        );
        for (bad, why) in [
            ("error_rate_pct = 0", "error_rate_pct must be 1..=100"),
            ("min_requests = 0", "min_requests must be >= 1"),
            ("window_secs = 61", "window_secs must be 1..=60"),
            ("eject_secs = 0", "eject_secs must be 1..=3600"),
            ("max_ejected_pct = 0", "max_ejected_pct must be 1..=100"),
            ("max_ejected_pct = 101", "max_ejected_pct must be 1..=100"),
        ] {
            let e = validate_str(
                &cfg(&format!("{pool}\noutlier_detection = {{ {bad} }}")),
                "t",
            )
            .err()
            .unwrap_or_default();
            assert!(e.contains(why), "{bad}: {e}");
        }
        // a single endpoint has no peer to be an outlier against
        let e = validate_str(&cfg("url=\"http://a:1\"\noutlier_detection = {}"), "t")
            .err()
            .unwrap_or_default();
        assert!(e.contains("needs a pool of at least two endpoints"), "{e}");
        assert!(toml::from_str::<ZionConfig>(&cfg(&format!(
            "{pool}\noutlier_detection = {{ error_rate = 5 }}"
        )))
        .is_err());
    }

    #[test]
    fn circuit_breaker_config_defaults_and_ranges() {
        let cfg = |cb: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.be]\nurl=\"http://127.0.0.1:8000\"\n{cb}\n\
                 [[route]]\npath=\"/{{*rest}}\"\nupstream=\"be\"\n"
            )
        };
        let none: ZionConfig = toml::from_str(&cfg("")).unwrap();
        assert!(
            none.upstream["be"].circuit_breaker.is_none(),
            "off unless asked for"
        );
        let d: ZionConfig = toml::from_str(&cfg("circuit_breaker = {}")).unwrap();
        let cb = d.upstream["be"].circuit_breaker.clone().unwrap();
        assert_eq!(
            (
                cb.error_rate_pct,
                cb.min_requests,
                cb.window_secs,
                cb.open_secs
            ),
            (50, 20, 10, 30)
        );
        for (bad, why) in [
            (
                "circuit_breaker = { error_rate_pct = 0 }",
                "error_rate_pct must be 1..=100",
            ),
            (
                "circuit_breaker = { error_rate_pct = 101 }",
                "error_rate_pct must be 1..=100",
            ),
            (
                "circuit_breaker = { min_requests = 0 }",
                "min_requests must be >= 1",
            ),
            (
                "circuit_breaker = { window_secs = 0 }",
                "window_secs must be 1..=",
            ),
            (
                "circuit_breaker = { window_secs = 61 }",
                "window_secs must be 1..=",
            ),
            (
                "circuit_breaker = { open_secs = 0 }",
                "open_secs must be 1..=3600",
            ),
            (
                "circuit_breaker = { open_secs = 3601 }",
                "open_secs must be 1..=3600",
            ),
        ] {
            let e = validate_str(&cfg(bad), "t").err().unwrap_or_default();
            assert!(e.contains(why), "{bad}: {e}");
        }
        let typo = toml::from_str::<ZionConfig>(&cfg("circuit_breaker = { error_rate = 5 }")).err();
        assert!(typo.is_some(), "an unknown key is refused, not ignored");
    }

    #[test]
    fn max_object_mb_defaults_to_50_and_zero_is_refused() {
        let cfg = |extra: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
                 [cache_profile.c]\nttl_seconds=60\n{extra}\n\
                 [[route]]\npath=\"/{{*rest}}\"\nupstream=\"be\"\nmode=\"static_cache\"\ncache_profile=\"c\"\n"
            )
        };
        let parsed: ZionConfig = toml::from_str(&cfg("")).unwrap();
        assert_eq!(parsed.cache_profile["c"].max_object_mb, 50);
        let parsed: ZionConfig = toml::from_str(&cfg("max_object_mb = 10")).unwrap();
        assert_eq!(parsed.cache_profile["c"].max_object_mb, 10);
        let e = validate_str(&cfg("max_object_mb = 0"), "t")
            .err()
            .unwrap_or_default();
        assert!(e.contains("max_object_mb must be >= 1"), "{e}");
    }

    #[test]
    fn redact_ip_settings_are_validated_with_the_rest_of_the_config() {
        let cfg = |redact: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\nurl=\"http://a:1\"\n\
                 [redact]\n{redact}\n[[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
            )
        };
        // (the placeholder cert/key paths fail the file checks; only the redact checks matter here)
        for ok in ["ip = \"truncate\"", ""] {
            let e = validate_str(&cfg(ok), "t").err().unwrap_or_default();
            assert!(!e.contains("redact"), "{ok}: {e}");
        }
        let e = validate_str(&cfg("ip = \"hmac\""), "t")
            .err()
            .unwrap_or_default();
        assert!(e.contains("needs redact.ip_hmac_key"), "{e}");
        let e = validate_str(&cfg("ip = \"hmac\"\nip_hmac_key = \"short\""), "t")
            .err()
            .unwrap_or_default();
        assert!(e.contains("at least 16 bytes"), "{e}");
    }

    #[test]
    fn closed_sets_and_jwks_urls_are_validated() {
        let cfg = |server: &str, profile: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n{server}\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
                 {profile}\n[[route]]\npath=\"/{{*r}}\"\nupstream=\"be\"\n"
            )
        };
        let errs = |server: &str, profile: &str| {
            let c: ZionConfig = toml::from_str(&cfg(server, profile)).unwrap();
            semantic_errors(&c).join("\n")
        };
        for ok in ["append", "rewrite", "drop"] {
            assert!(
                !errs(&format!("xff_mode=\"{ok}\""), "").contains("xff_mode"),
                "{ok}"
            );
        }
        assert!(errs("xff_mode=\"rewite\"", "").contains("server.xff_mode 'rewite'"));
        for ok in ["text", "json"] {
            assert!(
                !errs(&format!("log_format=\"{ok}\""), "").contains("log_format"),
                "{ok}"
            );
        }
        assert!(errs("log_format=\"JSON\"", "").contains("server.log_format 'JSON'"));
        let jwks = |url: &str| errs("", &format!("[auth_profile.p]\njwks_url=\"{url}\"\n"));
        for ok in [
            "https://idp.example/.well-known/jwks.json",
            "http://localhost:8080/jwks",
            "http://127.0.0.1/jwks",
            "http://[::1]:9000/jwks",
        ] {
            assert!(!jwks(ok).contains("jwks_url"), "{ok}");
        }
        for bad in [
            "http://idp.example/jwks",
            "http://localhost.evil.example/jwks",
            "http://10.0.0.5/jwks",
            "ftp://idp.example/jwks",
            "not a url",
        ] {
            assert!(jwks(bad).contains("jwks_url must use https"), "{bad}");
        }
    }

    #[test]
    fn upstream_fields_that_did_nothing_are_refused_or_checked() {
        let cfg = |up: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\n{up}\n\
                 [[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
            )
        };
        let errs = |up: &str| {
            let c: ZionConfig = toml::from_str(&cfg(up)).unwrap();
            semantic_errors(&c).join("\n")
        };
        for mtls in [
            "client_cert_path = \"/c.pem\"",
            "client_key_path = \"/k.pem\"",
        ] {
            let e = errs(&format!("url = \"https://a:1\"\n{mtls}"));
            assert!(
                e.contains("not supported yet") && e.contains("issues/503"),
                "{e}"
            );
        }
        assert!(errs("url = \"http://a:1\"\ntls = true").contains("is not https://"));
        assert!(!errs("url = \"https://a:1\"\ntls = true").contains("tls = true"));
        assert!(!errs("url = \"http://a:1\"").contains("tls = true"));
        assert!(errs("url = \"http://a:1\"\nkeepalive = 10001").contains("keepalive must be"));
        let c: ZionConfig = toml::from_str(&cfg("url = \"http://a:1\"")).unwrap();
        assert_eq!(
            c.upstream["u"].keepalive,
            crate::proxy::DEFAULT_KEEPALIVE,
            "default unchanged"
        );
    }

    #[test]
    fn upstream_request_timeout_ms_is_bounded_and_optional() {
        let cfg = |up: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\n{up}\n\
                 [[route]]\npath=\"/{{*rest}}\"\nupstream=\"u\"\n"
            )
        };
        let errs = |up: &str| {
            let c: ZionConfig = toml::from_str(&cfg(up)).unwrap();
            semantic_errors(&c).join("\n")
        };
        // No "0 = none": a request with no deadline is what the timeout exists to prevent.
        for bad in ["0", "3600001"] {
            let e = errs(&format!("url = \"http://a:1\"\nrequest_timeout_ms = {bad}"));
            assert!(
                e.contains("upstream.u.request_timeout_ms must be 1..=3600000") && e.contains(bad),
                "{bad}: {e}"
            );
        }
        for good in ["1", "120000", "3600000"] {
            let e = errs(&format!(
                "url = \"http://a:1\"\nrequest_timeout_ms = {good}"
            ));
            assert!(!e.contains("request_timeout_ms"), "{good}: {e}");
        }
        // Omitted = the default, carried as "not set" so nothing marks the request.
        let c: ZionConfig = toml::from_str(&cfg("url = \"http://a:1\"")).unwrap();
        assert_eq!(c.upstream["u"].request_timeout_ms, None);
        let c: ZionConfig =
            toml::from_str(&cfg("url = \"http://a:1\"\nrequest_timeout_ms = 90000")).unwrap();
        assert_eq!(c.upstream["u"].request_timeout_ms, Some(90_000));
    }

    /// A rejected config must say where the problem is without quoting the source: the
    /// offending line can hold a secret, and the message goes to the log, to the answer of a
    /// rejected `POST /admin/config` and to the audit trail (ZION-SEC-05).
    #[test]
    fn a_config_error_never_quotes_the_offending_line() {
        const SECRET: &str = "sup3r-s3cret-hmac-key-do-not-leak";
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                    [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n";
        // 1. A syntax error on the secret's own line (unterminated string).
        let doc = format!("{base}[auth_profile.p]\nsecret = \"{SECRET}\nalgorithm = \"HS256\"\n");
        let e = parse_schema(&doc, "pushed").err().expect("refused");
        assert!(!e.contains(SECRET) && !e.contains("s3cret"), "{e}");
        assert!(e.contains("Invalid TOML in pushed: line 8, column"), "{e}");
        // 2. A secret pasted into a field of another type: serde quotes the value.
        let doc = format!(
            "{base}[upstream.u]\nurl = \"http://a:1\"\nconnect_timeout_ms = \"{SECRET}\"\n"
        );
        let e = parse_schema(&doc, "pushed").err().expect("refused");
        assert!(!e.contains(SECRET), "{e}");
        assert!(
            e.contains("line 9, column") && e.contains("a string"),
            "{e}"
        );
        // 3. The useful part of a typo stays: the field that is not known, and the choices.
        let doc = format!("{base}[redact]\nip_hmac_ky = \"{SECRET}\"\n");
        let e = parse_schema(&doc, "pushed").err().expect("refused");
        assert!(!e.contains(SECRET), "{e}");
        assert!(e.contains("ip_hmac_ky") && e.contains("ip_hmac_key"), "{e}");
    }

    #[test]
    fn masking_drops_the_value_and_keeps_the_rest() {
        assert_eq!(
            mask_quoted_values("invalid type: string \"s3cret\", expected u64"),
            "invalid type: a string, expected u64"
        );
        // An escaped quote inside the value does not end it early.
        assert_eq!(
            mask_quoted_values(r#"invalid value: string "a\"b", expected x"#),
            "invalid value: a string, expected x"
        );
        assert_eq!(
            mask_quoted_values("unknown field `secrt`, expected `secret`"),
            "unknown field `secrt`, expected `secret`"
        );
        assert_eq!(mask_quoted_values("string \"unterminated"), "a string");
    }

    /// An upstream URL can carry `user:pass@`; the validation messages that name the URL
    /// must not (ZION-SEC-05).
    #[test]
    fn url_errors_never_show_credentials() {
        let cfg = |up: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\n{up}\n\
                 [[route]]\npath=\"/{{*rest}}\"\nupstream=\"u\"\n"
            )
        };
        let errs = |up: &str| {
            let c: ZionConfig = toml::from_str(&cfg(up)).unwrap();
            semantic_errors(&c).join("\n")
        };
        for up in [
            "url = \"ftp://deploy:s3cr3t@files.internal\"",
            "url = \"http://deploy:s3cr3t@backend.internal\"\ntls = true",
        ] {
            let e = errs(up);
            assert!(!e.is_empty(), "{up} is refused");
            assert!(!e.contains("s3cr3t") && !e.contains("deploy:"), "{e}");
            assert!(e.contains("internal"), "the host is still named: {e}");
        }
    }

    /// A CRL that no verifier consults is a revocation the operator believes in and Zion
    /// ignores: refuse the config.
    #[test]
    fn a_crl_needs_a_listener_that_verifies_client_certificates() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let errs = |tls: &str, admin: &str| {
            let c: ZionConfig = toml::from_str(&format!(
                "{base}[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n{tls}\n[admin]\n{admin}\n"
            ))
            .unwrap();
            semantic_errors(&c).join("\n")
        };
        let e = errs("client_crl_path=\"/crl\"", "");
        assert!(
            e.contains("tls.client_crl_path is set but tls.client_auth is \"none\""),
            "{e}"
        );
        let e = errs("", "client_crl_path=\"/crl\"");
        assert!(
            e.contains("admin.client_crl_path is set but admin.auth is not \"mtls\""),
            "{e}"
        );
        let e = errs(
            "client_auth=\"required\"\nclient_ca_path=\"/ca\"\nclient_crl_path=\"/crl\"",
            "auth=\"mtls\"\nclient_ca_path=\"/admin-ca\"\nclient_crl_path=\"/admin-crl\"",
        );
        assert!(!e.contains("client_crl_path"), "{e}");
    }

    #[test]
    fn admin_mtls_needs_its_own_ca() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let errs = |tls_extra: &str, admin_extra: &str| {
            let toml = format!(
                "{base}[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n{tls_extra}\n\
                 [admin]\nlisten=\"0.0.0.0:9180\"\nauth=\"mtls\"\n{admin_extra}\n"
            );
            let c: ZionConfig = toml::from_str(&toml).unwrap();
            semantic_errors(&c).join("\n")
        };
        // the data-plane CA alone no longer authorizes the admin API
        let e = errs("client_auth=\"required\"\nclient_ca_path=\"/data-ca\"", "");
        assert!(e.contains("requires admin.client_ca_path"), "{e}");
        let e = errs("", "client_ca_path=\"/admin-ca\"");
        assert!(!e.contains("admin.client_ca_path"), "{e}");
    }

    #[test]
    fn a_route_on_a_built_in_endpoint_is_refused() {
        let cfg = |path: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
                 [[route]]\npath=\"{path}\"\nupstream=\"be\"\n"
            )
        };
        for b in BUILT_IN_PATHS {
            let c: ZionConfig = toml::from_str(&cfg(b)).unwrap();
            let e = semantic_errors(&c).join("\n");
            assert!(e.contains("can never receive a request"), "{b}: {e}");
        }
        for ok in ["/{*rest}", "/status", "/metrics/{*rest}", "/healthzz"] {
            let c: ZionConfig = toml::from_str(&cfg(ok)).unwrap();
            assert!(
                !semantic_errors(&c).join("\n").contains("never receive"),
                "{ok}"
            );
        }
    }

    #[test]
    fn preserve_host_is_opt_in() {
        let cfg = |up: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\nurl=\"http://a:1\"\n{up}\n\
                 [[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
            )
        };
        let d: ZionConfig = toml::from_str(&cfg("")).unwrap();
        assert!(!d.upstream["u"].preserve_host, "off unless asked for");
        let c: ZionConfig = toml::from_str(&cfg("preserve_host = true")).unwrap();
        assert!(c.upstream["u"].preserve_host);
        assert!(toml::from_str::<ZionConfig>(&cfg("preserve_host = \"yes\"")).is_err());
        assert_eq!(d.upstream["u"].health_host, None);
        for good in ["app.example", "app.example:8443", "10.0.0.5"] {
            let c = cfg(&format!("health_host = \"{good}\""));
            assert!(
                !validate_str(&c, "t")
                    .err()
                    .unwrap_or_default()
                    .contains("health_host"),
                "{good}"
            );
        }
        for bad in [
            "",
            " app.example",
            "app example",
            "app.example/x",
            "http://app.example",
        ] {
            let e = validate_str(&cfg(&format!("health_host = \"{bad}\"")), "t")
                .err()
                .unwrap_or_default();
            assert!(
                e.contains("health_host must be a host name"),
                "{bad:?}: {e}"
            );
        }
    }

    #[test]
    fn max_in_flight_is_opt_in_and_bounded() {
        let cfg = |up: &str| {
            format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\nurl=\"http://a:1\"\n{up}\n\
                 [[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
            )
        };
        let d: ZionConfig = toml::from_str(&cfg("")).unwrap();
        assert_eq!(
            d.upstream["u"].max_in_flight, None,
            "no limit unless asked for"
        );
        let c: ZionConfig = toml::from_str(&cfg("max_in_flight = 64")).unwrap();
        assert_eq!(c.upstream["u"].max_in_flight, Some(64));
        for bad in ["max_in_flight = 0", "max_in_flight = 1000001"] {
            let e = validate_str(&cfg(bad), "t").err().unwrap_or_default();
            assert!(
                e.contains("max_in_flight must be 1..=1000000"),
                "{bad}: {e}"
            );
        }
        assert!(toml::from_str::<ZionConfig>(&cfg("max_in_flight = -1")).is_err());
    }

    #[test]
    fn dns_settings_default_to_an_hour_of_stale_answers_and_a_two_second_deadline() {
        let parse = |extra: &str| -> ZionConfig {
            toml::from_str(&format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n{extra}\n[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\nurl=\"http://a:1\"\n[[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
            ))
            .unwrap()
        };
        let d = parse("");
        assert_eq!(
            (d.server.dns_stale_secs, d.server.dns_timeout_ms),
            (3600, 2000)
        );
        let c = parse("dns_stale_secs = 0\ndns_timeout_ms = 500");
        assert_eq!((c.server.dns_stale_secs, c.server.dns_timeout_ms), (0, 500));
    }

    #[test]
    fn log_queue_lines_defaults_to_a_bounded_queue_and_zero_means_synchronous() {
        let parse = |extra: &str| -> ZionConfig {
            toml::from_str(&format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n{extra}\n[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\nurl=\"http://a:1\"\n[[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
            ))
            .unwrap()
        };
        assert_eq!(parse("").server.log_queue_lines, 8192);
        assert_eq!(parse("log_queue_lines = 100").server.log_queue_lines, 100);
        assert_eq!(parse("log_queue_lines = 0").server.log_queue_lines, 0);
    }

    #[test]
    fn tcp_user_timeout_secs_is_opt_in_and_can_be_set() {
        let parse = |extra: &str| -> ZionConfig {
            toml::from_str(&format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n{extra}\n[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstream.u]\nurl=\"http://a:1\"\n[[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
            ))
            .unwrap()
        };
        assert_eq!(parse("").server.tcp_user_timeout_secs, 0, "opt-in");
        assert_eq!(
            parse("tcp_user_timeout_secs = 30")
                .server
                .tcp_user_timeout_secs,
            30
        );
        assert_eq!(
            parse("tcp_user_timeout_secs = 0")
                .server
                .tcp_user_timeout_secs,
            0
        );
    }

    #[test]
    fn tcp_keepalive_secs_defaults_to_60_and_can_be_changed_or_turned_off() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n";
        let rest = "[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let parse =
            |extra: &str| toml::from_str::<ZionConfig>(&format!("{base}{extra}\n{rest}")).unwrap();
        assert_eq!(parse("").server.tcp_keepalive_secs, 60);
        assert_eq!(
            parse("tcp_keepalive_secs = 120").server.tcp_keepalive_secs,
            120
        );
        assert_eq!(parse("tcp_keepalive_secs = 0").server.tcp_keepalive_secs, 0);
    }

    use super::*;
    use crate::routing::{build_router, build_router_quiet};

    #[cfg(feature = "tls-fingerprint")]
    #[test]
    fn allowlist_drop_empty_list_refuses_boot() {
        // mode=allowlist + on_unknown=drop + empty allowed = drop EVERYTHING.
        let deny_all = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"drop\"\nallowed=[]\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        // Semantic (filesystem-free) validation — the cert paths need not exist.
        let cfg = parse_schema(deny_all, "test").expect("parse");
        let err = validate_semantics(&cfg, "test").err().unwrap_or_default();
        assert!(err.contains("drop EVERY connection"), "got: {err}");
    }

    #[cfg(feature = "tls-fingerprint")]
    #[test]
    fn allowlist_malformed_ja4_is_rejected() {
        // A non-empty allowlist of unmatchable entries is an equivalent deny-all;
        // surface the typo at boot, not as a silent production outage.
        let bad = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"drop\"\n\
             allowed=[{name=\"typo\",ja4=\"not-a-ja4\"}]\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let cfg = parse_schema(bad, "test").expect("parse");
        let err = validate_semantics(&cfg, "test").err().unwrap_or_default();
        assert!(err.contains("invalid JA4"), "got: {err}");
    }

    #[cfg(feature = "tls-fingerprint")]
    #[test]
    fn allowlist_duplicate_ja4_is_rejected() {
        // Two entries with the same (normalized) JA4 would silently last-win in
        // the runtime map — and one of them may carry a rate_limit_cps the
        // other silently disables. Refuse at boot.
        let dup = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"drop\"\n\
             allowed=[{name=\"a\",ja4=\"t13d1516h2_8daaf6152771_e5627efa2ab1\",rate_limit_cps=10},\
                      {name=\"b\",ja4=\"T13D1516H2_8DAAF6152771_E5627EFA2AB1\"}]\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let cfg = parse_schema(dup, "test").expect("parse");
        let err = validate_semantics(&cfg, "test").err().unwrap_or_default();
        assert!(err.contains("same JA4"), "got: {err}");
    }

    #[cfg(feature = "tls-fingerprint")]
    #[test]
    fn allowed_routes_bad_pattern_is_rejected() {
        // A typo'd pattern must be a boot error, not a runtime surprise.
        let bad = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"drop\"\non_unfingerprintable=\"drop\"\n\
             allowed=[{name=\"a\",ja4=\"t13d1516h2_8daaf6152771_e5627efa2ab1\",allowed_routes=[\"/api/{unclosed\"]}]\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let cfg = parse_schema(bad, "test").expect("parse");
        let err = validate_semantics(&cfg, "test").err().unwrap_or_default();
        assert!(err.contains("allowed_routes"), "got: {err}");
        // And a valid list passes.
        let ok = bad.replace("[\"/api/{unclosed\"]", "[\"/api/{*rest}\", \"/healthz\"]");
        let cfg = parse_schema(&ok, "test").expect("parse");
        assert!(
            validate_semantics(&cfg, "test").is_ok(),
            "valid allowed_routes must pass: {:?}",
            validate_semantics(&cfg, "test").err()
        );
    }

    #[cfg(feature = "tls-fingerprint")]
    #[test]
    fn allowlist_name_must_be_printable_ascii() {
        // The name becomes the X-Client-TLS-Allowlisted header value;
        // HeaderValue::from_str alone would accept "" and bytes >= 0x80 and
        // silently degrade the attestation. The validator refuses at boot.
        // TOML-escaped literals (Rust's Debug escapes are not valid TOML):
        // empty, blank, non-ASCII, control character.
        for bad_name_toml in ["\"\"", "\"   \"", "\"café-agent\"", "\"bell\\u0007\""] {
            let toml = format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
                 [tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"drop\"\n\
                 allowed=[{{name={bad_name_toml},ja4=\"t13d1516h2_8daaf6152771_e5627efa2ab1\"}}]\n\
                 [upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
                 [[route]]\npath=\"/{{*rest}}\"\nupstream=\"be\"\n"
            );
            let cfg = parse_schema(&toml, "test").expect("parse");
            let err = validate_semantics(&cfg, "test").err().unwrap_or_default();
            assert!(err.contains("invalid name"), "{bad_name_toml} got: {err}");
        }
    }

    #[cfg(feature = "tls-fingerprint")]
    #[test]
    fn ban_ttl_over_a_year_is_rejected() {
        // An absurd TTL is an operator error (and, far enough out, would
        // overflow Instant + Duration on the first ban insert — TOML itself
        // already rejects anything above i64::MAX). Two years must refuse.
        let huge = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"drop\"\nban_ttl_secs=63072000\n\
             allowed=[{name=\"a\",ja4=\"t13d1516h2_8daaf6152771_e5627efa2ab1\"}]\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let cfg = parse_schema(huge, "test").expect("parse");
        let err = validate_semantics(&cfg, "test").err().unwrap_or_default();
        assert!(err.contains("ban_ttl_secs"), "got: {err}");
    }

    #[cfg(feature = "tls-fingerprint")]
    #[test]
    fn allowlist_log_only_empty_list_boots() {
        // log_only never drops, so an empty allowlist is harmless — must pass.
        let ok = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"log_only\"\nallowed=[]\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let cfg = parse_schema(ok, "test").expect("parse");
        assert!(
            validate_semantics(&cfg, "test").is_ok(),
            "log_only empty allowlist must pass semantics, got: {:?}",
            validate_semantics(&cfg, "test").err()
        );
    }

    #[cfg(feature = "tls-fingerprint")]
    #[test]
    fn enforcing_allowlist_rejects_fail_open_unfingerprintable() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let allowed = "allowed=[{name=\"a\",ja4=\"t13d1516h2_8daaf6152771_e5627efa2ab1\"}]\n";

        // Enforcing (on_unknown=drop) + default on_unfingerprintable (allow) is
        // a fail-open bypass → must be rejected.
        let open =
            format!("{base}[tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"drop\"\n{allowed}");
        let err = validate_str(&open, "test").err().unwrap_or_default();
        assert!(
            err.contains("on_unfingerprintable"),
            "enforcing allowlist with allow-unfingerprintable must be rejected, got: {err}"
        );

        // Explicit fail-closed passes.
        let closed = format!(
            "{base}[tls.fingerprint]\nmode=\"allowlist\"\non_unknown=\"drop\"\non_unfingerprintable=\"drop\"\n{allowed}"
        );
        let cfg = parse_schema(&closed, "test").expect("parse");
        assert!(
            validate_semantics(&cfg, "test").is_ok(),
            "fail-closed allowlist must pass: {:?}",
            validate_semantics(&cfg, "test").err()
        );
    }

    #[test]
    fn illegal_route_mode_field_combinations_are_rejected() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n";

        // A static route that also names an upstream: upstream is silently
        // dropped by resolve_route → reject.
        let static_with_upstream = format!(
            "{base}[[route]]\npath=\"/{{*rest}}\"\nmode=\"static\"\nserve_dir=\"/srv\"\nupstream=\"be\"\n"
        );
        let err = validate_str(&static_with_upstream, "test")
            .err()
            .unwrap_or_default();
        assert!(
            err.contains("mode=static but sets upstream"),
            "static + upstream must be rejected, got: {err}"
        );

        // A standard (proxy) route that sets serve_dir: honoured only under
        // mode=static → reject.
        let standard_with_serve_dir =
            format!("{base}[[route]]\npath=\"/{{*rest}}\"\nupstream=\"be\"\nserve_dir=\"/srv\"\n");
        let err = validate_str(&standard_with_serve_dir, "test")
            .err()
            .unwrap_or_default();
        assert!(
            err.contains("static-only field"),
            "non-static + serve_dir must be rejected, got: {err}"
        );
    }

    fn one_route(route_body: &str) -> Result<ZionConfig, String> {
        parse_schema(
            &format!(
                "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
                 [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
                 [waf_profile.strict]\n[[route]]\npath=\"/{{*rest}}\"\n{route_body}"
            ),
            "t",
        )
    }

    #[test]
    fn shipped_example_configs_still_parse() {
        // Parsing is now where contradictory routes/upstreams are refused, so every
        // config the repo ships must clear it. Schema-level only (no cert files).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let files = [
            "zion.example.toml",
            "tests/zion-test.toml",
            "examples/multi-site.toml",
            "benchmarks/zion-bench-tls-waf.toml",
            "benchmarks/zion-bench-tls-waf-cache.toml",
            "benchmarks/zion-docker-full.toml",
            "benchmarks/zion-bench-tls-cache.toml",
            "benchmarks/zion-bench-tls.toml",
            "benchmarks/baseline/zion-lab.toml",
            "benchmarks/zion-docker-waf.toml",
            "benchmarks/zion-docker.toml",
            "configs/full-stack.toml",
            "configs/basic.toml",
            "configs/waf-strict.toml",
            "benches/e2e/config/zion-fullstack.toml",
        ];
        let mut bad = Vec::new();
        for f in files {
            let raw = std::fs::read_to_string(root.join(f)).unwrap_or_else(|e| panic!("{f}: {e}"));
            if let Err(e) = parse_schema(&raw, f) {
                bad.push(format!("{f}: {e}"));
            }
        }
        assert!(
            bad.is_empty(),
            "shipped configs no longer parse:\n{}",
            bad.join("\n")
        );
    }

    #[test]
    fn waf_is_one_policy_and_contradictions_cannot_be_built() {
        // ZION-DOM-01: `waf`, `waf_profile` and `max_body_mb` are one decision.
        let e = one_route("upstream=\"be\"\nwaf=true\nwaf_profile=\"strict\"\n")
            .err()
            .expect("waf = true next to a waf_profile is contradictory");
        assert!(e.contains("both `waf = true` and `waf_profile`"), "{e}");
        let e = one_route("upstream=\"be\"\nwaf_profile=\"strict\"\nmax_body_mb=500\n")
            .err()
            .expect("a route-level max_body_mb is dead next to a waf_profile");
        assert!(
            e.contains("max_body_mb") && e.contains("waf_profile"),
            "{e}"
        );

        let policy = |body: &str| one_route(body).unwrap().route[0].waf.clone();
        assert_eq!(
            policy("upstream=\"be\"\nwaf_profile=\"strict\"\n"),
            WafPolicy::Profile("strict".into())
        );
        assert_eq!(
            policy("upstream=\"be\"\nwaf=true\nmax_body_mb=50\n"),
            WafPolicy::Inline {
                max_body_mb: Some(50)
            }
        );
        assert_eq!(
            policy("upstream=\"be\"\n"),
            WafPolicy::Off {
                ignored_max_body_mb: None
            }
        );
        // a max_body_mb on a WAF-off route stays a boot WARNING (kept for
        // compatibility), not an error
        assert_eq!(
            policy("upstream=\"be\"\nmax_body_mb=50\n"),
            WafPolicy::Off {
                ignored_max_body_mb: Some(50)
            }
        );
        assert!(!WafPolicy::Off {
            ignored_max_body_mb: Some(1)
        }
        .is_enabled());
        assert!(WafPolicy::Inline { max_body_mb: None }.is_enabled());
    }

    #[test]
    fn a_route_is_either_an_upstream_or_a_directory() {
        // ZION-DOM-02: the two shapes carry disjoint data.
        let c = one_route("upstream=\"be\"\nmode=\"sse_stream\"\n").unwrap();
        assert_eq!(
            c.route[0].target,
            RouteTarget::Upstream {
                name: "be".into(),
                mode: UpstreamMode::SseStream
            }
        );
        assert_eq!(c.route[0].mode(), RouteMode::SseStream);
        assert_eq!(c.route[0].upstream_name(), Some("be"));

        let c = one_route("mode=\"static\"\nserve_dir=\"/srv\"\nspa_fallback=true\n").unwrap();
        assert_eq!(
            c.route[0].target,
            RouteTarget::Static {
                serve_dir: "/srv".into(),
                spa_fallback: true,
                precompressed: false
            }
        );
        assert_eq!(c.route[0].mode(), RouteMode::Static);
        assert_eq!(c.route[0].upstream_name(), None);

        // the illegal mixtures do not parse
        for (body, needle) in [
            ("mode=\"static\"\n", "no serve_dir"),
            ("mode=\"static\"\nserve_dir=\"\"\n", "no serve_dir"),
            (
                "mode=\"static\"\nserve_dir=\"/s\"\nupstream=\"be\"\n",
                "sets upstream",
            ),
            ("upstream=\"be\"\nserve_dir=\"/s\"\n", "static-only"),
            ("upstream=\"be\"\nspa_fallback=true\n", "static-only"),
            ("upstream=\"be\"\nprecompressed=true\n", "static-only"),
        ] {
            let e = one_route(body)
                .err()
                .unwrap_or_else(|| panic!("{body:?} must not parse"));
            assert!(e.contains(needle), "{body:?} -> {e}");
        }
    }

    #[test]
    fn static_route_builds_without_an_upstream() {
        let toml = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/c"
key_path = "/k"
[[route]]
path = "/assets/{*rest}"
upstream = ""
mode = "static"
serve_dir = "/var/www/assets"
spa_fallback = true
"#;
        let cfg = parse_schema(toml, "test").expect("parse");
        validate_semantics(&cfg, "test").expect("semantics");
        let router = build_router_quiet(&cfg).expect("build");
        let r = router.at(None, "/assets/css/app.css").expect("route");
        assert_eq!(r.mode, RouteMode::Static);
        assert_eq!(
            r.serve_dir.as_deref(),
            Some(std::path::Path::new("/var/www/assets"))
        );
        assert!(r.spa_fallback);
        assert_eq!(r.static_prefix, "/assets");
    }

    #[test]
    fn static_route_without_serve_dir_is_rejected() {
        let toml = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/c"
key_path = "/k"
[[route]]
path = "/{*rest}"
upstream = ""
mode = "static"
"#;
        // ZION-DOM-02: this used to parse and only fail later, in validation. A
        // static route with no serve_dir is now not constructible at all.
        let err = parse_schema(toml, "test")
            .err()
            .expect("a static route with no serve_dir must not parse");
        assert!(err.contains("mode=static but has no serve_dir"), "{err}");
        assert!(validate_str(toml, "test").is_err());
    }

    #[test]
    fn empty_acme_domains_are_rejected() {
        // Backstop: an empty [tls.acme] domains list parses + builds a router
        // but would issue nothing at runtime — validate_semantics must reject it.
        let toml = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/c"
key_path = "/k"
[tls.acme]
email = "ops@example.com"
domains = []
[[route]]
path = "/{*rest}"
upstream = "b"
[upstream.b]
url = "http://127.0.0.1:8080"
"#;
        let cfg = parse_schema(toml, "test").expect("parse");
        assert!(validate_semantics(&cfg, "test").is_err());
    }

    fn minimal_toml() -> &'static str {
        r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"

[tls]
cert_path = "/tmp/cert.pem"
key_path = "/tmp/key.pem"

[upstreams]
backend = "http://127.0.0.1:8000"

[[route]]
path = "/api/{*rest}"
upstream = "backend"
waf = true
"#
    }

    fn profile_toml() -> &'static str {
        r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"

[tls]
cert_path = "/tmp/cert.pem"
key_path = "/tmp/key.pem"

[upstream.api]
url = "http://127.0.0.1:8000"
connect_timeout_ms = 5000
keepalive = 128

[upstream.frontend]
url = "http://127.0.0.1:3000"

[waf_profile.strict]
max_body_mb = 5
max_depth = 8
max_string_len = 524288

[waf_profile.upload]
max_body_mb = 200
deny_unknown_content_types = false

[waf_profile.streamed]
max_body_mb = 50
streaming = true

[cache_profile.immutable]
mode = "memory"
max_entries = 5000
ttl_seconds = 86400

[[route]]
path = "/api/{*rest}"
upstream = "api"
waf_profile = "strict"

[[route]]
path = "/upload"
upstream = "api"
waf_profile = "upload"

[[route]]
path = "/_next/static/{*rest}"
upstream = "frontend"
cache_profile = "immutable"

[[route]]
path = "/{*rest}"
upstream = "frontend"
"#
    }

    #[test]
    fn parse_minimal_config() {
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(config.server.listen_http, "0.0.0.0:80");
        assert_eq!(config.server.listen_https, "0.0.0.0:443");
        assert_eq!(config.tls.cert_path, "/tmp/cert.pem");
        assert!(config.tls.hot_reload); // default true
        assert_eq!(config.tls.min_version, "1.3"); // default
        assert_eq!(config.route.len(), 1);
    }

    #[test]
    fn access_log_default_back_compat() {
        // Issue #60: a config without `[access_log]` produces empty
        // include_headers AND mtls_fingerprint = true. The default-true
        // is intentional — the fingerprint is already opaque (SHA-256)
        // so an operator who configures mTLS expects to see it logged.
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        assert!(config.access_log.include_headers.is_empty());
        assert!(config.access_log.mtls_fingerprint);
    }

    #[test]
    fn access_log_lowercases_include_headers() {
        // Issue #60: header names from the operator's TOML are
        // matched against `req.headers().get(name)` on the hot path,
        // and `HeaderName::as_str()` returns lowercase. Lowercasing
        // at parse time means the dispatcher uses one canonical form.
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/cert.pem"
key_path = "/tmp/cert.key"
[upstreams]
backend = "http://127.0.0.1:8000"
[[route]]
path = "/{*rest}"
upstream = "backend"

[access_log]
include_headers = ["User-Agent", "Authorization", "X-Forwarded-For"]
mtls_fingerprint = false
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.access_log.include_headers,
            vec![
                "user-agent".to_string(),
                "authorization".to_string(),
                "x-forwarded-for".to_string()
            ]
        );
        assert!(!config.access_log.mtls_fingerprint);
    }

    #[test]
    fn parse_legacy_upstreams() {
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(
            config.upstreams.get("backend"),
            Some(&"http://127.0.0.1:8000".to_string())
        );
    }

    #[test]
    fn validate_upstream_url_accepts_http_and_https() {
        assert!(validate_upstream_url("u", "http://127.0.0.1:8000").is_none());
        assert!(validate_upstream_url("u", "https://backend.internal").is_none());
    }

    #[test]
    fn validate_upstream_url_rejects_non_http_and_schemeless() {
        // These parse as a Uri (or fail) but must be rejected at startup so the
        // operator gets a clear error instead of a cryptic first-request failure.
        for bad in ["ftp://host/", "ws://host/", "tcp://h:9", "example.com:9000"] {
            assert!(
                validate_upstream_url("u", bad).is_some(),
                "should reject upstream URL: {bad}"
            );
        }
    }

    #[test]
    fn validate_host_entry_accepts_bare_and_folds_case() {
        // A bare host is accepted; uppercase is folded (friendly); an IPv6
        // literal is a valid host key.
        assert!(validate_host_entry("r", "api.example.com").is_none());
        assert!(validate_host_entry("r", "API.Example.COM").is_none());
        assert!(validate_host_entry("r", "[::1]").is_none());
    }

    #[test]
    fn validate_host_entry_rejects_non_canonical() {
        // Anything that isn't a fixed point of normalize_host (modulo case) is
        // rejected with an actionable error — a stray port, trailing dot,
        // scheme, path, userinfo, or empty entry can never silently mis-match.
        for bad in [
            "api.example.com:8443",
            "api.example.com.",
            "https://api.example.com",
            "api.example.com/x",
            "user@api.example.com",
            "",
        ] {
            assert!(
                validate_host_entry("r", bad).is_some(),
                "should reject host: {bad:?}"
            );
        }
    }

    #[test]
    fn validate_host_entry_wildcards() {
        // Leading-label wildcards are accepted (domain case-folded)...
        assert!(validate_host_entry("r", "*.example.com").is_none());
        assert!(validate_host_entry("r", "*.API.example.com").is_none());
        // ...but the domain must be canonical, and embedded / trailing / bare
        // `*` (or an empty domain / a port) is rejected.
        for bad in [
            "*.",
            "*.example.com:8443",
            "api.*.example.com",
            "www.example.*",
            "*",
        ] {
            assert!(
                validate_host_entry("r", bad).is_some(),
                "should reject wildcard host: {bad:?}"
            );
        }
    }

    #[test]
    fn parse_route_hosts_field() {
        // A route may bind one or more hosts; a route without `hosts` is shared.
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/cert.pem"
key_path = "/tmp/key.pem"
[upstreams]
backend = "http://127.0.0.1:8000"
[[route]]
path = "/api/{*rest}"
upstream = "backend"
hosts = ["api.example.com", "api2.example.com"]
[[route]]
path = "/{*rest}"
upstream = "backend"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.route[0].hosts,
            Some(vec![
                "api.example.com".to_string(),
                "api2.example.com".to_string()
            ])
        );
        assert!(config.route[1].hosts.is_none(), "shared route ⇒ hosts None");
    }

    #[test]
    fn example_config_parses_with_deny_unknown_fields() {
        // Every shipped reference/example config MUST deserialize — this guards
        // `deny_unknown_fields` against drift between the docs and the structs
        // (a new/renamed/misplaced TOML key fails here loudly, not in prod).
        // Covers zion.example.toml + all examples/*.toml so a new example can't
        // silently ship un-loadable (this caught examples/multi-site.toml's
        // top-level [cors] block).
        let root = env!("CARGO_MANIFEST_DIR");
        let mut files = vec![std::path::PathBuf::from(format!(
            "{root}/zion.example.toml"
        ))];
        for entry in std::fs::read_dir(format!("{root}/examples")).expect("read examples/") {
            let p = entry.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) == Some("toml") {
                files.push(p);
            }
        }
        for f in &files {
            let toml = std::fs::read_to_string(f).unwrap_or_else(|e| panic!("read {f:?}: {e}"));
            let parsed: Result<ZionConfig, _> = toml::from_str(&toml);
            assert!(parsed.is_ok(), "{f:?} failed to parse: {:?}", parsed.err());
        }
    }

    #[test]
    fn unknown_config_key_is_rejected() {
        // deny_unknown_fields: a misspelled key must fail fast at load, not be
        // silently ignored (the #1 operability footgun this closes).
        let toml = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
listen_htttp = "oops typo"
[tls]
cert_path = "/c"
key_path = "/k"
[upstreams]
be = "http://127.0.0.1:8000"
[[route]]
path = "/{*rest}"
upstream = "be"
"#;
        let parsed: Result<ZionConfig, _> = toml::from_str(toml);
        assert!(parsed.is_err(), "an unknown config key must be rejected");
        let e = parsed.err().unwrap().to_string();
        assert!(
            e.contains("listen_htttp") || e.contains("unknown field"),
            "error should name the unknown field, got: {e}"
        );
    }

    #[test]
    fn unknown_key_in_cross_module_subtable_is_rejected() {
        // deny_unknown_fields reaches the cross-module sub-tables too (here
        // [audit], whose struct lives in audit.rs) — a typo there is no longer
        // silently ignored either.
        let toml = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/c"
key_path = "/k"
[upstreams]
be = "http://127.0.0.1:8000"
[[route]]
path = "/{*rest}"
upstream = "be"
[audit]
enabledd = true
"#;
        let parsed: Result<ZionConfig, _> = toml::from_str(toml);
        assert!(
            parsed.is_err(),
            "an unknown key in [audit] must be rejected"
        );
        let e = parsed.err().unwrap().to_string();
        assert!(
            e.contains("enabledd") || e.contains("unknown field"),
            "error should name the unknown sub-table field, got: {e}"
        );
    }

    /// A config whose only interesting parts are `[server]` extras and the route table.
    fn route_auth_cfg(server_extra: &str, routes: &str) -> String {
        format!(
            "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n{server_extra}\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [auth_profile.p]\nsecret=\"0123456789abcdef0123456789abcdef\"\nalgorithm=\"HS256\"\n{routes}"
        )
    }

    #[test]
    fn require_route_auth_demands_a_stated_choice_per_route() {
        let open = "[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        // off (default): an unprotected route is fine, as before
        assert!(!validate_str(&route_auth_cfg("", open), "t")
            .err()
            .unwrap_or_default()
            .contains("require_route_auth"));
        // on: the same route is refused, and the message says how to fix it
        let e = validate_str(&route_auth_cfg("require_route_auth=true", open), "t")
            .err()
            .unwrap_or_default();
        assert!(
            e.contains("require_route_auth") && e.contains("public = true"),
            "{e}"
        );
        // each of the three explicit choices satisfies it
        for ok in [
            "[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\nauth_profile=\"p\"\n",
            "[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\npublic=true\n",
            "[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\ninternal_only=true\n",
        ] {
            let e = validate_str(&route_auth_cfg("require_route_auth=true", ok), "t")
                .err()
                .unwrap_or_default();
            assert!(!e.contains("require_route_auth"), "{ok}: {e}");
        }
    }

    #[test]
    fn a_route_with_auth_profile_needs_the_auth_feature() {
        let protected = "[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\nauth_profile=\"p\"\n";
        let e = validate_str(&route_auth_cfg("", protected), "t")
            .err()
            .unwrap_or_default();
        if cfg!(feature = "auth") {
            assert!(!e.contains("--features auth"), "{e}");
        } else {
            assert!(
                e.contains("sets auth_profile") && e.contains("--features auth"),
                "a build without auth must refuse, not serve unauthenticated: {e}"
            );
        }
        // a profile no route uses protects nothing and changes nothing
        let open = "[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let e = validate_str(&route_auth_cfg("", open), "t")
            .err()
            .unwrap_or_default();
        assert!(!e.contains("--features auth"), "{e}");
    }

    #[test]
    fn public_and_auth_profile_together_are_refused() {
        let both =
            "[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\npublic=true\nauth_profile=\"p\"\n";
        let e = toml::from_str::<ZionConfig>(&route_auth_cfg("", both))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(e.contains("public") && e.contains("auth_profile"), "{e}");
    }

    #[test]
    fn admin_config_defaults_and_validation() {
        // Present-but-empty [admin] → loopback defaults.
        let cfg: ZionConfig = toml::from_str(
            "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n[admin]\n",
        )
        .unwrap();
        let admin = cfg.admin.expect("[admin] present → Some");
        assert_eq!(admin.listen, "127.0.0.1:9180");
        assert_eq!(admin.auth, "internal-ip");
        assert_eq!(admin.rate_limit_rps, 10);

        // A bogus auth mode is rejected by validate_str (semantic validation).
        let bad = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n[admin]\nauth=\"bogus\"\n";
        let err = validate_str(bad, "test").err().unwrap_or_default();
        assert!(
            err.contains("admin.auth"),
            "bad admin.auth must be rejected, got: {err}"
        );

        // rate_limit_rps = 0 is rejected too.
        let zero = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n[admin]\nrate_limit_rps=0\n";
        let err = validate_str(zero, "test").err().unwrap_or_default();
        assert!(
            err.contains("admin.rate_limit_rps"),
            "rate_limit_rps=0 must be rejected, got: {err}"
        );

        // auth = "mtls" without tls.client_ca_path is rejected (nothing to
        // verify client certs against).
        let mtls_no_ca = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n[admin]\nauth=\"mtls\"\n";
        let err = validate_str(mtls_no_ca, "test").err().unwrap_or_default();
        assert!(
            err.contains("client_ca_path"),
            "auth=mtls without client_ca_path must be rejected, got: {err}"
        );
    }

    #[test]
    fn internal_networks_entries_are_validated() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n{NET}\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let with = |net: &str| {
            validate_str(&base.replace("{NET}", net), "t")
                .err()
                .unwrap_or_default()
        };
        let e = with("internal_networks=[\"10.0.0.0/99\"]\n");
        assert!(e.contains("server.internal_networks '10.0.0.0/99'"), "{e}");
        // a good list raises no internal_networks error (other errors may exist: cert files)
        let e = with("internal_networks=[\"10.20.0.0/24\",\"127.0.0.1\"]\n");
        assert!(!e.contains("internal_networks"), "{e}");
    }

    #[test]
    fn admin_internal_ip_must_bind_loopback() {
        // ZION-AUTH-01: `internal-ip` trusts every private-range peer, and that peer
        // can replace the whole config, so it is only allowed on loopback.
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let admin = |listen: &str, auth: &str| {
            let toml = format!("{base}[admin]\nlisten=\"{listen}\"\nauth=\"{auth}\"\n");
            validate_str(&toml, "test").err().unwrap_or_default()
        };
        // routable / wildcard / container-bridge binds are refused
        for bad in [
            "0.0.0.0:9180",
            "10.0.0.5:9180",
            "192.168.1.10:9180",
            "[::]:9180",
            "172.17.0.2:9180",
        ] {
            let e = admin(bad, "internal-ip");
            assert!(
                e.contains("not a loopback address") && e.contains("mtls"),
                "{bad} with internal-ip must be rejected with guidance, got: {e}"
            );
        }
        // loopback stays fine (the failure, if any, is only the missing cert files)
        for ok in ["127.0.0.1:9180", "127.0.0.2:9180", "[::1]:9180"] {
            let e = admin(ok, "internal-ip");
            assert!(
                !e.contains("not a loopback address"),
                "{ok} must be accepted: {e}"
            );
        }
        // mtls may bind anywhere: the handshake, not the peer IP, is the gate
        let e = admin("0.0.0.0:9180", "mtls");
        assert!(
            !e.contains("not a loopback address"),
            "mtls on a routable bind: {e}"
        );
    }

    const MIN_DOC: &str = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
         [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
         [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";

    #[test]
    fn an_unversioned_file_is_schema_one_not_whatever_is_current() {
        // ZION-DOM-03: absent must mean a fixed, documented version.
        let cfg = parse_schema(MIN_DOC, "t").unwrap();
        assert_eq!(cfg.schema_version, LEGACY_SCHEMA_VERSION);
        assert_eq!(
            LEGACY_SCHEMA_VERSION, 1,
            "the meaning of an unversioned file must never change"
        );
        let v1 = parse_schema(&format!("schema_version = 1\n{MIN_DOC}"), "t").unwrap();
        assert_eq!(v1.schema_version, 1);
        // 0 is not a version
        let e = parse_schema(&format!("schema_version = 0\n{MIN_DOC}"), "t")
            .err()
            .expect("0 must be rejected");
        assert!(e.contains("schema_version = 0"), "{e}");
    }

    #[test]
    fn every_supported_schema_version_has_a_reader() {
        // Bumping CURRENT_SCHEMA_VERSION without adding its arm to `upgrade_schema`
        // (and a fixture for it) must fail here, not misread users' old files.
        for v in LEGACY_SCHEMA_VERSION..=CURRENT_SCHEMA_VERSION {
            let doc = format!("schema_version = {v}\n{MIN_DOC}");
            let cfg =
                parse_schema(&doc, "t").unwrap_or_else(|e| panic!("schema {v} has no reader: {e}"));
            assert_eq!(cfg.schema_version, v);
        }
    }

    #[test]
    fn an_upstream_is_a_single_non_empty_endpoint_list() {
        // ZION-DOM-04: url / urls are two spellings of one thing.
        let doc = |up: &str| format!("{MIN_DOC}[upstream.a]\n{up}\n");
        let ups = |up: &str| parse_schema(&doc(up), "t").map(|c| c.upstream["a"].urls().to_vec());
        assert_eq!(ups("url=\"http://x:1\"").unwrap(), ["http://x:1"]);
        assert_eq!(
            ups("urls=[\"http://x:1\",\"http://y:2\"]").unwrap(),
            ["http://x:1", "http://y:2"]
        );
        // both written: merged once, `urls` first then `url` (the documented order)
        assert_eq!(
            ups("urls=[\"http://x:1\"]\nurl=\"http://y:2\"").unwrap(),
            ["http://x:1", "http://y:2"]
        );
        // neither: refused at parse time, so no later code can see an empty list
        for none in ["", "urls=[]", "keepalive=8"] {
            let e = ups(none).unwrap_err();
            assert!(e.contains("at least one endpoint"), "{none:?} -> {e}");
        }
        // unknown keys are still rejected
        assert!(ups("url=\"http://x:1\"\nbogus=1").is_err());
    }

    #[test]
    fn schema_version_handshake() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";

        // No schema_version → accepted (backward compatible).
        assert!(check_schema_version(base, "t").is_ok());
        assert!(parse_schema(base, "t").is_ok());

        // Equal / older → accepted.
        let cur = format!("schema_version = {CURRENT_SCHEMA_VERSION}\n{base}");
        assert!(parse_schema(&cur, "t").is_ok());

        // Newer than this binary → targeted guidance, even before the strict
        // parse would choke on hypothetical new keys.
        let newer = format!(
            "schema_version = {}\nfuture_key = \"x\"\n{base}",
            CURRENT_SCHEMA_VERSION + 1
        );
        let err = check_schema_version(&newer, "t").unwrap_err();
        assert!(
            err.contains("schema_version") && err.contains("Upgrade zion"),
            "too-new schema must give upgrade guidance, got: {err}"
        );
    }

    #[test]
    fn client_auth_requires_ca_and_valid_value() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [upstreams]\nbe=\"http://127.0.0.1:8000\"\n[[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";

        // required without a CA → fail-open, must be rejected.
        let no_ca =
            format!("{base}[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\nclient_auth=\"required\"\n");
        let err = validate_str(&no_ca, "test").err().unwrap_or_default();
        assert!(
            err.contains("client_auth") && err.contains("client_ca_path"),
            "required client_auth without a CA must be rejected, got: {err}"
        );

        // A typo'd value must be rejected (would silently coerce to none).
        let typo =
            format!("{base}[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\nclient_auth=\"requird\"\n");
        let err = validate_str(&typo, "test").err().unwrap_or_default();
        assert!(
            err.contains("client_auth") && err.contains("must be"),
            "unknown client_auth must be rejected, got: {err}"
        );

        // required WITH a CA passes semantics (cert files are a deploy check).
        let ok = format!(
            "{base}[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\nclient_auth=\"required\"\nclient_ca_path=\"/ca\"\n"
        );
        let cfg = parse_schema(&ok, "test").expect("parse");
        assert!(
            !semantic_errors(&cfg)
                .iter()
                .any(|e| e.contains("client_auth")),
            "required client_auth WITH a CA must pass semantics"
        );

        // Default (none) needs no CA.
        let none = format!("{base}[tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n");
        let cfg = parse_schema(&none, "test").expect("parse");
        assert!(!semantic_errors(&cfg)
            .iter()
            .any(|e| e.contains("client_auth")));
    }

    #[test]
    fn upstream_defined_in_both_maps_is_rejected() {
        // Same name in [upstream.api] and [upstreams] → ambiguous, must fail.
        let both = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [upstream.api]\nurl=\"http://127.0.0.1:8000\"\n\
             [upstreams]\napi=\"http://127.0.0.1:9000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"api\"\n";
        let err = validate_str(both, "test").err().unwrap_or_default();
        assert!(
            err.contains("defined in both"),
            "colliding upstream name must be rejected, got: {err}"
        );

        // Distinct names in the two maps are fine.
        let ok = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [upstream.api]\nurl=\"http://127.0.0.1:8000\"\n\
             [upstreams]\nlegacy=\"http://127.0.0.1:9000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"api\"\n";
        let cfg: ZionConfig = toml::from_str(ok).unwrap();
        assert!(
            !semantic_errors(&cfg)
                .iter()
                .any(|e| e.contains("defined in both")),
            "distinct upstream names must not collide"
        );
    }

    #[cfg(feature = "sovereign-aimp")]
    #[test]
    fn an_enabled_mesh_needs_valid_trusted_keys() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";
        let errs = |mesh: &str| {
            let cfg: ZionConfig =
                toml::from_str(&format!("{base}[sovereign_aimp]\n{mesh}")).unwrap();
            semantic_errors(&cfg).join("\n")
        };
        let key = "ab".repeat(32);
        assert!(errs("enabled=true\nlisten=\"127.0.0.1:9443\"\n")
            .contains("needs sovereign_aimp.trusted_keys"));
        let ok = errs(&format!(
            "enabled=true\nlisten=\"127.0.0.1:9443\"\ntrusted_keys=[\"{key}\"]\n"
        ));
        assert!(!ok.contains("trusted_keys"), "{ok}");
        let bad = errs("enabled=true\nlisten=\"127.0.0.1:9443\"\ntrusted_keys=[\"abcd\"]\n");
        assert!(bad.contains("\"abcd\" is not a node id"), "{bad}");
        // a disabled mesh accepts nothing, so it needs no list
        assert!(!errs("enabled=false\n").contains("trusted_keys"));
    }

    #[cfg(feature = "sovereign-aimp")]
    #[test]
    fn sovereign_aimp_listen_must_parse_when_enabled() {
        let base = "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nbe=\"http://127.0.0.1:8000\"\n\
             [[route]]\npath=\"/{*rest}\"\nupstream=\"be\"\n";

        // Malformed listen (missing port) must fail validation — NOT silently
        // fall back to a world-open 0.0.0.0 bind.
        let bad = format!("{base}[sovereign_aimp]\nenabled=true\nlisten=\"127.0.0.1\"\n");
        let err = validate_str(&bad, "test").err().unwrap_or_default();
        assert!(
            err.contains("sovereign_aimp.listen"),
            "malformed aimp listen must be rejected, got: {err}"
        );

        // A valid listen passes (semantic layer; cert files are a deploy check).
        let good = format!("{base}[sovereign_aimp]\nenabled=true\nlisten=\"127.0.0.1:9443\"\n");
        let cfg: ZionConfig = toml::from_str(&good).unwrap();
        assert!(
            !semantic_errors(&cfg)
                .iter()
                .any(|e| e.contains("sovereign_aimp.listen")),
            "valid aimp listen must not be flagged"
        );

        // Disabled mesh: listen is not validated even if malformed (never bound).
        let disabled = format!("{base}[sovereign_aimp]\nenabled=false\nlisten=\"nonsense\"\n");
        let cfg: ZionConfig = toml::from_str(&disabled).unwrap();
        assert!(
            !semantic_errors(&cfg)
                .iter()
                .any(|e| e.contains("sovereign_aimp.listen")),
            "disabled mesh must not validate its listen"
        );
    }

    /// The `validate_semantics` / `validate_config` split (ADR-0011): the
    /// semantic layer runs every filesystem-free check, while cert-file
    /// existence stays a deploy-time concern. A config with placeholder cert
    /// paths (what `zion import`/`zion suggest` emit) must pass semantics but
    /// fail full validation on a machine where those files don't exist.
    #[test]
    fn validate_semantics_skips_files_keeps_references() {
        let placeholder_certs = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"

[tls]
cert_path = "/etc/ssl/zion/definitely-not-here.crt"
key_path = "/etc/ssl/zion/definitely-not-here.key"

[upstreams]
backend = "http://127.0.0.1:8000"

[[route]]
path = "/{*rest}"
upstream = "backend"
"#;
        let cfg = parse_schema(placeholder_certs, "test").expect("schema-valid");
        validate_semantics(&cfg, "test").expect("placeholder certs pass semantics");
        let err = match validate_str(placeholder_certs, "test") {
            Err(e) => e,
            Ok(_) => panic!("full validation must fail on missing cert files"),
        };
        assert!(err.contains("does not exist"), "got: {err}");

        // A dangling upstream reference is a SEMANTIC error — caught without
        // touching the filesystem.
        let dangling = placeholder_certs.replace("upstream = \"backend\"", "upstream = \"ghost\"");
        let cfg = parse_schema(&dangling, "test").expect("schema-valid");
        let err = match validate_semantics(&cfg, "test") {
            Err(e) => e,
            Ok(()) => panic!("dangling upstream must fail semantics"),
        };
        assert!(err.contains("unknown upstream 'ghost'"), "got: {err}");

        // A malformed hosts entry too (ADR-0010 host rules live in semantics).
        let bad_host = placeholder_certs.replace(
            "upstream = \"backend\"",
            "upstream = \"backend\"\nhosts = [\"https://nope.example.com\"]",
        );
        let cfg = parse_schema(&bad_host, "test").expect("schema-valid");
        assert!(validate_semantics(&cfg, "test").is_err());
    }

    #[test]
    fn parse_named_upstream() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let api = config.upstream.get("api").unwrap();
        assert_eq!(api.urls(), ["http://127.0.0.1:8000".to_string()]);
        assert_eq!(api.connect_timeout_ms, 5000);
        assert_eq!(api.keepalive, 128);
        assert!(!api.tls); // default false
    }

    #[test]
    fn upstream_defaults() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let fe = config.upstream.get("frontend").unwrap();
        assert_eq!(fe.connect_timeout_ms, 3000); // default
        assert_eq!(fe.keepalive, crate::proxy::DEFAULT_KEEPALIVE); // default
    }

    #[test]
    fn parse_waf_profiles() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let strict = config.waf_profile.get("strict").unwrap();
        assert_eq!(strict.max_body_mb, 5);
        assert_eq!(strict.max_depth, 8);
        assert_eq!(strict.max_string_len, 524288);
        assert!(strict.deny_unknown_content_types); // default true
        assert!(!strict.streaming); // default false (#49)

        let upload = config.waf_profile.get("upload").unwrap();
        assert_eq!(upload.max_body_mb, 200);
        assert!(!upload.deny_unknown_content_types);

        // `streaming = true` is parsed and surfaced (issue #49 wire-up).
        let streamed = config.waf_profile.get("streamed").unwrap();
        assert!(streamed.streaming);
        assert_eq!(streamed.max_body_mb, 50);
    }

    #[test]
    fn parse_cache_profiles() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let imm = config.cache_profile.get("immutable").unwrap();
        assert_eq!(imm.mode, CacheMode::Memory);
        assert_eq!(imm.max_entries, 5000);
        assert_eq!(imm.ttl_seconds, 86400);
    }

    #[test]
    fn build_router_with_legacy_upstreams() {
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        let router = build_router(&config).unwrap();
        let matched = router.at(None, "/api/v1/users").unwrap();
        assert_eq!(matched.upstream_url[0], "http://127.0.0.1:8000");
        assert!(matched.waf.is_some()); // legacy waf=true
        assert_eq!(matched.waf.as_ref().unwrap().max_body_mb, 10); // default
    }

    #[test]
    fn build_router_with_named_profiles() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let router = build_router(&config).unwrap();

        // API route with strict WAF
        let api = router.at(None, "/api/v1/test").unwrap();
        assert_eq!(api.upstream_url[0], "http://127.0.0.1:8000");
        let waf = api.waf.as_ref().unwrap();
        assert_eq!(waf.max_body_mb, 5);
        assert_eq!(waf.max_depth, 8);

        // Upload route with upload WAF
        let upload = router.at(None, "/upload").unwrap();
        let waf = upload.waf.as_ref().unwrap();
        assert_eq!(waf.max_body_mb, 200);
        // Trailing-slash variant resolves to the SAME route (rank 18: without
        // the alias, "/upload/" falls through and loses the upload WAF profile).
        assert_eq!(
            router
                .at(None, "/upload/")
                .expect("/upload/ should alias /upload")
                .waf
                .as_ref()
                .unwrap()
                .max_body_mb,
            200
        );

        // Static cache route
        let statics = router.at(None, "/_next/static/chunk.js").unwrap();
        assert_eq!(statics.upstream_url[0], "http://127.0.0.1:3000");
        let cache = statics.cache.as_ref().unwrap();
        assert_eq!(cache.ttl_seconds, 86400);
        assert_eq!(cache.max_entries, 5000);

        // Catch-all has no WAF or cache
        let catchall = router.at(None, "/about").unwrap();
        assert!(catchall.waf.is_none());
        assert!(catchall.cache.is_none());

        // Bare-prefix fallback: a catch-all "<prefix>/{*rest}" must also serve
        // its bare prefix. matchit alone would 404 these (regression guard for
        // the root-route bug found in the e2e harness).
        // Root "/{*rest}" → "/" resolves to the catch-all (no WAF/cache).
        let root = router
            .at(None, "/")
            .expect("root '/' should match the catch-all");
        assert!(root.waf.is_none());
        assert!(root.cache.is_none());
        // "/api/{*rest}" → bare "/api" resolves to the API route (strict WAF).
        assert!(router
            .at(None, "/api")
            .expect("/api should match its catch-all")
            .waf
            .is_some());
        // "/_next/static/{*rest}" → bare "/_next/static" resolves to the cache route.
        assert!(router
            .at(None, "/_next/static")
            .expect("/_next/static should match its catch-all")
            .cache
            .is_some());
    }

    #[test]
    fn legacy_waf_with_custom_body_limit() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
backend = "http://127.0.0.1:8000"
[[route]]
path = "/upload"
upstream = "backend"
waf = true
max_body_mb = 500
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at(None, "/upload").unwrap();
        assert_eq!(route.waf.as_ref().unwrap().max_body_mb, 500);
    }

    #[test]
    fn static_cache_mode_auto_creates_cache_profile() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
fe = "http://127.0.0.1:3000"
[[route]]
path = "/_next/static/{*rest}"
upstream = "fe"
mode = "static_cache"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at(None, "/_next/static/chunk.js").unwrap();
        assert!(route.cache.is_some());
        // Profile-less static_cache route → conservative 1h default (was 1 year;
        // the audiolibri staleness fix). Operators set ttl_seconds for longer.
        assert_eq!(route.cache.as_ref().unwrap().ttl_seconds, 3600);
    }

    #[test]
    fn internal_only_route() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
backend = "http://127.0.0.1:8000"
[[route]]
path = "/metrics"
upstream = "backend"
internal_only = true
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at(None, "/metrics").unwrap();
        assert!(route.internal_only);
    }

    #[test]
    fn route_mode_sse_stream() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
backend = "http://127.0.0.1:8000"
[[route]]
path = "/events"
upstream = "backend"
mode = "sse_stream"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at(None, "/events").unwrap();
        assert_eq!(route.mode, RouteMode::SseStream);
    }

    #[test]
    fn tls_defaults() {
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(config.tls.min_version, "1.3");
        assert_eq!(config.tls.alpn, vec!["h2", "http/1.1"]);
        assert!(config.tls.hot_reload);
    }

    #[test]
    fn tls_custom_values() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
hot_reload = false
min_version = "1.2"
alpn = ["http/1.1"]
[[route]]
path = "/{*rest}"
upstream = "be"
[upstreams]
be = "http://127.0.0.1:8000"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.tls.hot_reload);
        assert_eq!(config.tls.min_version, "1.2");
        assert_eq!(config.tls.alpn, vec!["http/1.1"]);
    }

    #[test]
    fn err_on_unknown_upstream() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[[route]]
path = "/test"
upstream = "nonexistent"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let err = build_router(&config).unwrap_err();
        assert!(err.contains("Unknown upstream"), "got: {err}");
    }

    #[test]
    fn err_on_unknown_waf_profile() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
be = "http://127.0.0.1:8000"
[[route]]
path = "/test"
upstream = "be"
waf_profile = "nonexistent"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let err = build_router(&config).unwrap_err();
        assert!(err.contains("Unknown waf_profile"), "got: {err}");
    }

    #[test]
    fn err_on_unknown_cache_profile() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstreams]
be = "http://127.0.0.1:8000"
[[route]]
path = "/test"
upstream = "be"
cache_profile = "nonexistent"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let err = build_router(&config).unwrap_err();
        assert!(err.contains("Unknown cache_profile"), "got: {err}");
    }

    #[test]
    fn waf_profile_defaults() {
        let profile = WafProfile::default();
        assert_eq!(profile.max_body_mb, 10);
        assert_eq!(profile.max_depth, 10);
        assert_eq!(profile.max_string_len, 1_048_576);
        assert!(profile.deny_unknown_content_types);
        assert_eq!(
            profile.allowed_content_types,
            vec!["application/json", "multipart/form-data"]
        );
        // Streaming WAF body inspection (issue #49) defaults to off so
        // existing deployments are byte-for-byte unchanged after the
        // upgrade. Operators opt in per profile via `streaming = true`.
        assert!(!profile.streaming);
    }

    // ── Host-based L7 routing (ADR-0010) ──────────────────────────────────

    #[test]
    fn host_router_falls_back_to_shared_on_path_miss() {
        // A host with its own tree still falls through to the shared layer for a
        // path it doesn't define (hostless-as-shared-layer, decision #1).
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstream.api]
url = "http://127.0.0.1:8000"
[upstream.shared]
url = "http://127.0.0.1:9000"
[[route]]
path = "/api/{*rest}"
hosts = ["api.example.com"]
upstream = "api"
[[route]]
path = "/health"
upstream = "shared"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();

        // api.example.com/api/* → its own route.
        assert_eq!(
            router
                .at(Some("api.example.com"), "/api/v1")
                .unwrap()
                .upstream_url[0],
            "http://127.0.0.1:8000"
        );
        // api.example.com/health → NOT in api's tree → shared /health.
        assert_eq!(
            router
                .at(Some("api.example.com"), "/health")
                .unwrap()
                .upstream_url[0],
            "http://127.0.0.1:9000"
        );
        // A path in NO tree → 404 (None).
        assert!(router.at(Some("api.example.com"), "/nope").is_none());
    }
}
