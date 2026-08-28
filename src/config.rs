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

use matchit::Router;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

// ============================================================================
// TOP-LEVEL CONFIG
// ============================================================================

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ZionConfig {
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
/// Env vars `ZION_AIMP_*` still work and override the TOML values when set,
/// so existing deployments keep working. Operators are encouraged to migrate
/// to TOML for review/diffability.
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
    /// Rate limit window in seconds. Default: 1.
    #[serde(default = "default_rate_window")]
    pub rate_limit_window_secs: u64,
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
    /// Log format: "text" (default) or "json".
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// Trusted proxy CIDR ranges. When the TCP peer IP matches one of these,
    /// the real client IP is extracted from X-Forwarded-For (rightmost untrusted hop).
    /// Example: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
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

fn default_log_format() -> String {
    "text".to_string()
}

fn default_rate_window() -> u64 {
    1
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
    /// Where to store ACME account key + certs. Default: /etc/zion/acme/
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

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub url: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
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
}

impl UpstreamConfig {
    pub fn get_urls(&self) -> Vec<String> {
        let mut all = self.urls.clone();
        if let Some(u) = &self.url {
            all.push(u.clone());
        }
        all
    }
}

fn default_connect_timeout() -> u64 {
    3000
}
fn default_keepalive() -> usize {
    64
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
fn default_max_entries() -> usize {
    10_000
}
fn default_ttl() -> u64 {
    // Conservative heuristic-freshness default (RFC 9111 §4.2.2) for a
    // static_cache route that names no explicit lifetime: cache for 1 hour, not
    // a year. A header-less origin response must not be frozen (the audiolibri
    // staleness root cause) — set `ttl_seconds` explicitly for longer/immutable.
    3600
} // 1 hour

// ============================================================================
// ROUTE CONFIG
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub path: String,

    /// Optional Host/authority bindings (ADR-0010). When set, this route is
    /// served only for these hosts; when unset, the route is a *shared* route
    /// matching every host (the hostless fallback layer). Entries are bare
    /// hostnames — validated as fixed points of
    /// [`crate::security::normalize_host`] (lowercase modulo case-folding, no
    /// scheme/path/port/trailing dot) so a config key and a normalized request
    /// authority compare in the same form. Parsed and validated here; wired
    /// into the router in a follow-up.
    #[serde(default)]
    pub hosts: Option<Vec<String>>,

    #[serde(default)]
    pub upstream: String,
    #[serde(default)]
    pub mode: RouteMode,
    /// For `mode = "static"`: the directory served from disk. Files under it are
    /// served safely (no `..` traversal, no dotfiles); anything outside 404s.
    pub serve_dir: Option<String>,
    /// For `mode = "static"`: serve `index.html` for any path that maps to no
    /// file (single-page-app fallback). Off by default.
    #[serde(default)]
    pub spa_fallback: bool,
    /// For `mode = "static"`: when a `.br`/`.gz` sidecar sits next to a file and
    /// the client's `Accept-Encoding` allows it, serve the precompressed variant
    /// (like nginx `gzip_static` / Caddy `precompressed`). Off by default.
    #[serde(default)]
    pub precompressed: bool,
    #[serde(default)]
    pub internal_only: bool,

    // New: named profile references (None = disabled)
    pub waf_profile: Option<String>,
    pub cache_profile: Option<String>,

    /// Per-route Content-Security-Policy header. If set, injected into responses.
    /// If unset, upstream CSP is passed through unmodified.
    pub csp: Option<String>,

    /// Auth profile name for JWT/OIDC validation.
    /// If set, requests must carry a valid Bearer token.
    pub auth_profile: Option<String>,

    // Legacy compat: bool waf flag + inline max_body_mb
    #[serde(default)]
    pub waf: bool,
    pub max_body_mb: Option<u64>,

    /// Shadow mode: run WAF checks but do NOT block on violation.
    /// Each would-be denial is logged (`logging::warn`) with the matched
    /// reason and counted in the `waf_shadow_would_block` metric. Lets
    /// operators migrating from nginx/ModSecurity test their WAF profile
    /// against real traffic for hours/days before flipping to enforce.
    /// Has no effect when no WAF profile is attached to the route.
    #[serde(default)]
    pub waf_shadow: bool,

    /// Per-route CORS configuration. If unset, no CORS headers are injected.
    pub cors: Option<CorsConfig>,
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
// RESOLVED ROUTE (fully resolved at startup, zero lookups at runtime)
// ============================================================================

#[derive(Clone, Debug)]
pub struct ResolvedRoute {
    #[allow(dead_code)]
    pub upstream_url: Vec<String>,
    /// Pre-parsed URI parts — avoids full URI parse on every request.
    pub upstream_scheme: hyper::http::uri::Scheme,
    pub upstream_authority: hyper::http::uri::Authority,
    pub mode: RouteMode,
    /// For `RouteMode::Static`: the serve directory (not canonicalized here —
    /// existence is a per-request check so an imported config validates offline).
    pub serve_dir: Option<std::path::PathBuf>,
    /// SPA fallback (serve `index.html` on a miss) for `RouteMode::Static`.
    pub spa_fallback: bool,
    /// Serve `.br`/`.gz` sidecars via `Accept-Encoding` for `RouteMode::Static`.
    pub precompressed: bool,
    /// Literal path prefix stripped before the on-disk file lookup.
    pub static_prefix: String,
    pub waf: Option<WafProfile>,
    /// True iff the route is in WAF shadow mode (log + count, no block).
    pub waf_shadow: bool,
    pub cache: Option<CacheProfile>,
    pub internal_only: bool,
    /// Per-route CSP header value (pre-parsed at startup, zero cost at runtime).
    pub csp: Option<hyper::header::HeaderValue>,
    /// Resolved auth profile (pre-built at startup).
    #[cfg(feature = "auth")]
    pub auth: Option<crate::auth::ResolvedAuthProfile>,
    /// Pre-compiled CORS headers for lightning-fast matching per-route.
    pub cors: Option<std::sync::Arc<crate::security::CorsHeaders>>,
}

// ============================================================================
// LOADING & BUILDING
// ============================================================================

pub fn load_config(path: &str) -> Result<ZionConfig, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let config: ZionConfig =
        toml::from_str(&raw).map_err(|e| format!("Invalid TOML in {path}: {e}"))?;
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
    toml::from_str(raw).map_err(|e| format!("Invalid TOML in {label}: {e}"))
}

/// Full validation of a config from an in-memory string — the same schema AND
/// semantic checks `load_config` runs (route refs, CIDRs, cert-file existence,
/// …), minus the file read. Used by the admin API's `POST /admin/config`, where
/// the pushed body must be fully deployable (real cert paths and all), unlike
/// `zion suggest` which only needs the schema-level [`parse_schema`].
pub fn validate_str(raw: &str, label: &str) -> Result<ZionConfig, String> {
    let config: ZionConfig =
        toml::from_str(raw).map_err(|e| format!("Invalid TOML in {label}: {e}"))?;
    validate_config(&config, label)?;
    Ok(config)
}

/// An upstream URL must parse AND use http/https. A scheme-less `host:port` or
/// an `ftp://`/`ws://` URL parses as a valid `Uri` but fails cryptically at the
/// first proxied request, so reject it at startup with an actionable message.
/// Returns `Some(error)` on rejection, `None` when valid.
fn validate_upstream_url(label: &str, url: &str) -> Option<String> {
    match url.parse::<hyper::Uri>() {
        Err(_) => Some(format!("{label} '{url}' is not a valid URL")),
        Ok(uri) => match uri.scheme_str() {
            Some("http") | Some("https") => None,
            other => Some(format!(
                "{label} '{url}' must use http:// or https:// (got {})",
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
fn semantic_errors(config: &ZionConfig) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

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

    // Each route must reference a valid upstream — except a static route, which
    // serves from disk and instead needs a serve_dir (ADR-0015).
    for route in &config.route {
        if route.mode == RouteMode::Static {
            if route.serve_dir.as_deref().unwrap_or("").is_empty() {
                errors.push(format!(
                    "route '{}' is mode=static but has no serve_dir",
                    route.path
                ));
            }
        } else {
            let has_upstream = config.upstream.contains_key(&route.upstream)
                || config.upstreams.contains_key(&route.upstream);
            if !has_upstream {
                errors.push(format!(
                    "route '{}' references unknown upstream '{}'",
                    route.path, route.upstream
                ));
            }
        }

        // WAF profile reference must exist
        if let Some(ref profile) = route.waf_profile {
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
        let all_urls = up.get_urls();
        if all_urls.is_empty() {
            errors.push(format!("upstream '{name}' must have at least one url"));
        }
        for u in all_urls {
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

    // [admin] — listen must be a real socket address; auth a known mode.
    if let Some(ref admin) = config.admin {
        if admin.listen.parse::<std::net::SocketAddr>().is_err() {
            errors.push(format!(
                "admin.listen '{}' is not a valid socket address (e.g. 127.0.0.1:9180)",
                admin.listen
            ));
        }
        if !matches!(admin.auth.as_str(), "internal-ip" | "mtls") {
            errors.push(format!(
                "admin.auth '{}' must be \"internal-ip\" or \"mtls\"",
                admin.auth
            ));
        }
        if admin.rate_limit_rps == 0 {
            errors.push("admin.rate_limit_rps must be > 0".to_string());
        }
        // mTLS needs a client CA to verify presented certs against.
        if admin.auth == "mtls" && config.tls.client_ca_path.is_none() {
            errors.push(
                "admin.auth = \"mtls\" requires tls.client_ca_path (the CA that signs admin client certs)"
                    .to_string(),
            );
        }
    }

    errors
}

/// Resolve upstream name to URLs. Checks new `[upstream.X]` first, then legacy `[upstreams]`.
/// Returns Err if the upstream name is not defined — callers propagate the
/// error to reject the config rather than panicking (important during hot-reload).
fn resolve_upstream(config: &ZionConfig, name: &str) -> Result<Vec<String>, String> {
    if let Some(up) = config.upstream.get(name) {
        return Ok(up.get_urls());
    }
    if let Some(url) = config.upstreams.get(name) {
        return Ok(vec![url.clone()]);
    }
    Err(format!(
        "Unknown upstream '{name}' — define it in [upstream.{name}] or [upstreams]"
    ))
}

/// Host-aware L7 router (ADR-0010). Holds the hostless/shared radix tree, one
/// tree per exact bound host, and one tree per `*.suffix` wildcard. A route with
/// no `hosts` lands in `default` and is reachable from every authority (the
/// shared fallback layer). When no route declares `hosts`, `active` is false and
/// lookups go straight to `default` — identical, and identically cheap, to the
/// pre-host-routing single router. Precedence: exact host > most-specific
/// wildcard > shared.
#[derive(Debug)]
pub struct HostRouter {
    /// Hostless / shared routes — matched for every authority.
    default: Router<Arc<ResolvedRoute>>,
    /// Exact-host radix trees, keyed by normalized authority.
    by_host: HashMap<Box<str>, Router<Arc<ResolvedRoute>>>,
    /// Wildcard trees keyed by their dotted suffix (`*.example.com` →
    /// `.example.com`), sorted longest-suffix-first so the most specific wins.
    /// A request host matches when it `ends_with` the suffix.
    wildcards: Vec<(String, Router<Arc<ResolvedRoute>>)>,
    /// True iff at least one route is host-bound (exact or wildcard). Lets the
    /// hot path skip authority extraction entirely in the hostless deployment.
    active: bool,
}

impl Default for HostRouter {
    fn default() -> Self {
        Self {
            default: Router::new(),
            by_host: HashMap::new(),
            wildcards: Vec::new(),
            active: false,
        }
    }
}

impl HostRouter {
    /// Whether any host-bound route exists. Callers gate authority extraction
    /// and cache-key hashing on this, so a hostless deployment pays nothing.
    #[inline]
    pub fn host_routing_active(&self) -> bool {
        self.active
    }

    /// Resolve `(host, path)` to a route, per ADR-0010's hostless-as-shared-layer
    /// rule with precedence exact > wildcard > shared: an exact-host tree wins;
    /// otherwise the most-specific matching `*.suffix` wildcard; then the shared
    /// `default` tree. On a path-miss within the selected host tree we still fall
    /// through to shared (shared routes are reachable from every host). `host` is
    /// the normalized request authority ([`crate::security::normalize_host`]), or
    /// `None` when absent/invalid — then only the shared layer is consulted.
    #[inline]
    pub fn at(&self, host: Option<&str>, path: &str) -> Option<&Arc<ResolvedRoute>> {
        if self.active {
            if let Some(h) = host {
                if let Some(tree) = self.by_host.get(h) {
                    // Exact host wins outright (nginx-style); path-miss → shared.
                    if let Ok(m) = tree.at(path) {
                        return Some(m.value);
                    }
                } else {
                    // No exact host: the most-specific matching wildcard, if any.
                    // `wildcards` is sorted longest-suffix-first, so the first
                    // `ends_with` hit is the most specific one.
                    for (suffix, tree) in &self.wildcards {
                        if h.ends_with(suffix.as_str()) {
                            if let Ok(m) = tree.at(path) {
                                return Some(m.value);
                            }
                            break; // most-specific wildcard chosen; fall to shared
                        }
                    }
                }
            }
        }
        self.default.at(path).ok().map(|m| m.value)
    }
}

/// Accumulates the routes of a single host-group into one radix tree, deferring
/// the catch-all bare-prefix and trailing-slash aliases until every explicit
/// route of the group is inserted (so an explicit route always wins a conflict).
struct RouterBuilder {
    router: Router<Arc<ResolvedRoute>>,
    aliases: Vec<(String, Arc<ResolvedRoute>)>,
}

impl Default for RouterBuilder {
    fn default() -> Self {
        Self {
            router: Router::new(),
            aliases: Vec::new(),
        }
    }
}

impl RouterBuilder {
    /// Insert one explicit route and record its bare-prefix / trailing-slash
    /// alias for the deferred second pass.
    fn insert(&mut self, path: &str, resolved: Arc<ResolvedRoute>) -> Result<(), String> {
        // A matchit catch-all "<prefix>/{*name}" does NOT match the bare
        // "<prefix>" (nor the root "/" when the prefix is empty), so a
        // "/{*rest}" route silently 404s on "/" even though it is meant to be
        // the fallback for everything. Record the bare prefix so we can also
        // map it to this route in a second pass (after all explicit routes).
        match catchall_bare_prefix(path) {
            Some(bare) => {
                self.router
                    .insert(path.to_string(), resolved.clone())
                    .map_err(|e| format!("Bad route pattern '{path}': {e}"))?;
                self.aliases.push((bare, resolved));
            }
            None => {
                // Non-catch-all: also alias the trailing-slash-toggled variant
                // so "/x" and "/x/" resolve to the SAME route. matchit treats
                // them as distinct, so "/x/" would otherwise fall through to a
                // different (often more permissive) route — e.g. a stricter
                // per-route WAF profile silently downgraded.
                match trailing_slash_variant(path) {
                    Some(variant) => {
                        self.router
                            .insert(path.to_string(), resolved.clone())
                            .map_err(|e| format!("Bad route pattern '{path}': {e}"))?;
                        self.aliases.push((variant, resolved));
                    }
                    None => {
                        self.router
                            .insert(path.to_string(), resolved)
                            .map_err(|e| format!("Bad route pattern '{path}': {e}"))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Apply the deferred aliases and return the finished tree. Alias inserts
    /// are best-effort: a conflict means an explicit route already owns the
    /// slot — exactly the precedence we want (matchit specificity then makes an
    /// exact prefix win over a less-specific parent catch-all, e.g. "/api" →
    /// "/api/{*rest}", not the root "/{*rest}").
    fn finish(mut self) -> Router<Arc<ResolvedRoute>> {
        for (alias, resolved) in self.aliases {
            let _ = self.router.insert(alias, resolved);
        }
        self.router
    }
}

/// Build the host-aware router from config routes, pre-resolving all references.
/// A route with `hosts` is inserted into each of its host trees; a route without
/// `hosts` goes into the shared/default tree (ADR-0010, hostless-as-shared).
///
/// Returns `Err` if any route references an unknown upstream, profile, or
/// contains an invalid pattern. The caller (boot path or hot-reload) decides
/// whether to abort or log-and-keep the previous snapshot.
pub fn build_router(config: &ZionConfig) -> Result<HostRouter, String> {
    let router = build_router_quiet(config)?;
    print_routes_table(&config.route);
    Ok(router)
}

/// [`build_router`] without the boot-banner routes table — for callers that
/// build a router as a validation step, not to serve traffic (`zion import`'s
/// self-validation gate, ADR-0011).
pub fn build_router_quiet(config: &ZionConfig) -> Result<HostRouter, String> {
    let mut default = RouterBuilder::default();
    let mut by_host: HashMap<Box<str>, RouterBuilder> = HashMap::new();

    let mut wild: HashMap<String, RouterBuilder> = HashMap::new();

    for route in &config.route {
        let resolved = resolve_route(config, route)?;
        match &route.hosts {
            // Shared route: reachable from every authority.
            None => default.insert(&route.path, resolved)?,
            // Host-bound. Validation guarantees each entry is either a canonical
            // exact host or a `*.<canonical-domain>` wildcard.
            Some(hosts) => {
                let mut seen_exact = std::collections::HashSet::new();
                let mut seen_wild = std::collections::HashSet::new();
                for h in hosts {
                    if let Some(rest) = h.strip_prefix("*.") {
                        // Wildcard: the match key is the dotted, normalized
                        // suffix (`*.example.com` → `.example.com`).
                        let domain = crate::security::normalize_host(rest).ok_or_else(|| {
                            format!("route '{}': invalid wildcard host '{}'", route.path, h)
                        })?;
                        let suffix = format!(".{domain}");
                        // A suffix repeated in one route's list inserts once.
                        if !seen_wild.insert(suffix.clone()) {
                            continue;
                        }
                        wild.entry(suffix)
                            .or_default()
                            .insert(&route.path, resolved.clone())?;
                    } else {
                        let key = crate::security::normalize_host(h)
                            .ok_or_else(|| format!("route '{}': invalid host '{}'", route.path, h))?
                            .into_owned();
                        // A host repeated in one route's list must insert once,
                        // not twice into the same tree (matchit rejects a dup).
                        if !seen_exact.insert(key.clone()) {
                            continue;
                        }
                        by_host
                            .entry(key.into_boxed_str())
                            .or_default()
                            .insert(&route.path, resolved.clone())?;
                    }
                }
            }
        }
    }

    let active = !by_host.is_empty() || !wild.is_empty();
    let by_host = by_host
        .into_iter()
        .map(|(host, builder)| (host, builder.finish()))
        .collect();
    // Longest suffix first so the most specific wildcard wins at lookup; the
    // content tiebreak keeps the order deterministic across rebuilds.
    let mut wildcards: Vec<(String, Router<Arc<ResolvedRoute>>)> = wild
        .into_iter()
        .map(|(suffix, builder)| (suffix, builder.finish()))
        .collect();
    wildcards.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));

    Ok(HostRouter {
        default: default.finish(),
        by_host,
        wildcards,
        active,
    })
}

/// Resolve one `[[route]]` into its fully pre-computed [`ResolvedRoute`]
/// (upstream URLs, WAF/cache profiles, CSP, auth, CORS) — everything the hot
/// path needs, computed once at build. Pure: no router insertion, so
/// `build_router` can place the result into one or more host-scoped trees.
fn resolve_route(config: &ZionConfig, route: &RouteConfig) -> Result<Arc<ResolvedRoute>, String> {
    // A static route (ADR-0015) serves from disk and needs no upstream — ignore
    // any stray `upstream` field so `validate_semantics` and `build_router`
    // agree (both skip the upstream for a static route).
    let upstream_url = if route.mode == RouteMode::Static {
        Vec::new()
    } else {
        resolve_upstream(config, &route.upstream)?
    };

    // Resolve WAF: named profile > legacy bool flag
    let waf = if let Some(ref profile_name) = route.waf_profile {
        Some(
            config
                .waf_profile
                .get(profile_name)
                .ok_or_else(|| {
                    format!(
                        "Unknown waf_profile '{}' in route {}",
                        profile_name, route.path
                    )
                })?
                .clone(),
        )
    } else if route.waf {
        // Legacy: create inline profile from max_body_mb
        Some(WafProfile {
            max_body_mb: route.max_body_mb.unwrap_or(10),
            ..WafProfile::default()
        })
    } else {
        // Footgun guard: `max_body_mb` is enforced by the WAF body gate, so
        // on a WAF-off route it has no effect. Surface it at boot rather
        // than silently dropping the operator's intended size cap (a no-WAF
        // route otherwise streams the body to the upstream, hyper-framed).
        if route.max_body_mb.is_some() {
            eprintln!(
                "  ⚠ route '{}': max_body_mb is set but WAF is off (no waf=true / waf_profile) \
                     — the body-size cap is NOT enforced; enable WAF or remove max_body_mb",
                route.path
            );
        }
        None
    };

    // Resolve cache: named profile > legacy mode=static_cache
    let cache = if let Some(ref profile_name) = route.cache_profile {
        Some(
            config
                .cache_profile
                .get(profile_name)
                .ok_or_else(|| {
                    format!(
                        "Unknown cache_profile '{}' in route {}",
                        profile_name, route.path
                    )
                })?
                .clone(),
        )
    } else if route.mode == RouteMode::StaticCache {
        // Default in-RAM profile for a profile-less static_cache route:
        // conservative 1h TTL (default_ttl), NOT immutable. Name an explicit
        // [cache_profile] with a longer ttl_seconds for content-hashed assets.
        Some(CacheProfile {
            mode: CacheMode::Memory,
            max_entries: default_max_entries(),
            ttl_seconds: default_ttl(),
        })
    } else {
        None
    };

    // Pre-parse the FIRST upstream URI at startup for legacy fallback. A static
    // route has no upstream, so it gets placeholder parts the Static dispatch
    // arm never reads.
    let (upstream_scheme, upstream_authority) = if upstream_url.is_empty() {
        ("http".parse().unwrap(), "127.0.0.1".parse().unwrap())
    } else {
        let upstream_uri: hyper::Uri = upstream_url[0]
            .parse()
            .map_err(|e| format!("Invalid upstream URL '{}': {}", upstream_url[0], e))?;
        let scheme = upstream_uri
            .scheme()
            .cloned()
            .unwrap_or_else(|| "http".parse().unwrap());
        let authority = upstream_uri
            .authority()
            .cloned()
            .ok_or_else(|| format!("Upstream '{}' has no authority", upstream_url[0]))?;
        (scheme, authority)
    };

    // Pre-parse CSP at startup for zero-cost injection at runtime
    let csp = match route.csp.as_ref() {
        Some(s) => Some(
            hyper::header::HeaderValue::from_str(s)
                .map_err(|e| format!("Invalid CSP in route '{}': {}", route.path, e))?,
        ),
        None => None,
    };

    // Resolve auth profile at startup (feature-gated)
    #[cfg(feature = "auth")]
    let auth = match route.auth_profile.as_ref() {
        Some(name) => {
            let profile_config = config.auth_profile.get(name).ok_or_else(|| {
                format!("Auth profile '{}' not found (route '{}')", name, route.path)
            })?;
            let resolved = crate::auth::resolve_auth_profile(profile_config)
                .map_err(|e| format!("Auth profile '{}' (route '{}'): {}", name, route.path, e))?;
            eprintln!(
                "  auth: route {} → profile '{}' (alg={})",
                route.path, name, profile_config.algorithm
            );
            Some(resolved)
        }
        None => None,
    };

    let cors = route
        .cors
        .as_ref()
        .map(|c| Arc::new(crate::security::CorsHeaders::from_config(c)));

    // Static file serving (ADR-0015): the serve dir + the literal prefix to
    // strip from the request path. Not canonicalized here — existence is a
    // per-request check so an imported config validates offline.
    let (serve_dir, static_prefix) = if route.mode == RouteMode::Static {
        let dir = route
            .serve_dir
            .as_ref()
            .ok_or_else(|| format!("route '{}' is mode=static but has no serve_dir", route.path))?;
        let prefix = route
            .path
            .split("{*")
            .next()
            .unwrap_or("/")
            .trim_end_matches('/')
            .to_string();
        (Some(std::path::PathBuf::from(dir)), prefix)
    } else {
        (None, String::new())
    };

    Ok(Arc::new(ResolvedRoute {
        upstream_url,
        upstream_scheme,
        upstream_authority,
        mode: route.mode.clone(),
        serve_dir,
        spa_fallback: route.spa_fallback,
        precompressed: route.precompressed,
        static_prefix,
        waf,
        waf_shadow: route.waf_shadow,
        cache,
        internal_only: route.internal_only,
        csp,
        #[cfg(feature = "auth")]
        auth,
        cors,
    }))
}

/// If `path` is a matchit catch-all (`<prefix>/{*name}`), return the bare
/// prefix the catch-all should also serve (`/` for a root catch-all). matchit's
/// catch-all does not match the bare prefix, so without registering it a
/// `/{*rest}` route returns 404 on `/` — surprising for a "match everything"
/// fallback. Returns `None` for non-catch-all paths.
fn catchall_bare_prefix(path: &str) -> Option<String> {
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
fn trailing_slash_variant(path: &str) -> Option<String> {
    if path == "/" {
        None
    } else if let Some(stripped) = path.strip_suffix('/') {
        Some(stripped.to_string())
    } else {
        Some(format!("{path}/"))
    }
}

// ═══════════════════════════════════════════════════════════════════
// ROUTES MINI-TABLE (boot-time visualization)
// ═══════════════════════════════════════════════════════════════════

/// Print the configured routes as a styled mini-table. Replaces the
/// per-route `eprintln!("route ... [waf=, cache=, mode=]")` line with a
/// scannable layout: aligned paths, dim arrow, cyan upstream, semantic
/// tags (`waf`, `cache`, `sse`, `ws`, `static`, `internal`) colored by
/// category. Falls back to plain ASCII when stderr is not a TTY or when
/// `NO_COLOR` / `ZION_BOOT_PLAIN` is set.
fn print_routes_table(routes: &[RouteConfig]) {
    use std::io::IsTerminal;

    let plain =
        std::env::var_os("NO_COLOR").is_some() || std::env::var_os("ZION_BOOT_PLAIN").is_some();
    let color = !plain && std::io::stderr().is_terminal();

    // Cap path column at 40 chars so very long matchers don't blow up the
    // layout. Truncate with an ellipsis when over.
    const PATH_CAP: usize = 40;
    let max_path_chars = routes
        .iter()
        .map(|r| r.path.chars().count().min(PATH_CAP))
        .max()
        .unwrap_or(0);

    let header_dim = if color { "\x1b[2m" } else { "" };
    let arrow_dim = if color { "\x1b[2m" } else { "" };
    let cyan = if color { "\x1b[38;5;51m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };

    eprintln!("  {}routes ({}){}", header_dim, routes.len(), reset);

    for route in routes {
        let path = truncate_chars(&route.path, PATH_CAP);
        let pad = " ".repeat(max_path_chars.saturating_sub(path.chars().count()));
        let tags = render_route_tags(route, color);
        eprintln!(
            "    {}{} {}→{} {}{}{}{}",
            path,
            pad,
            arrow_dim,
            reset,
            cyan,
            route.upstream,
            reset,
            if tags.is_empty() {
                String::new()
            } else {
                format!("    {tags}")
            },
        );
    }
}

/// Build the tag suffix for a route: a `·`-joined list of colored chips
/// (`waf`, `sse`, `ws`, `static`, `cache`, `internal`). Returns "" when
/// the route is a plain pass-through with no special features.
fn render_route_tags(route: &RouteConfig, color: bool) -> String {
    let reset = if color { "\x1b[0m" } else { "" };
    let dim_sep = if color { "\x1b[2m" } else { "" };
    let green = if color { "\x1b[38;5;46m" } else { "" }; // security ON
    let yellow = if color { "\x1b[38;5;220m" } else { "" }; // perf / restricted
    let cyan = if color { "\x1b[38;5;51m" } else { "" }; // streaming / special

    let mut tags: Vec<String> = Vec::new();

    match route.mode {
        RouteMode::SseStream => tags.push(format!("{cyan}sse{reset}")),
        RouteMode::Websocket => tags.push(format!("{cyan}ws{reset}")),
        RouteMode::StaticCache => tags.push(format!("{cyan}static{reset}")),
        RouteMode::Static => tags.push(format!("{cyan}files{reset}")),
        RouteMode::Standard => {}
    }
    if route.waf || route.waf_profile.is_some() {
        if route.waf_shadow {
            // Distinct tag — the operator must see at a glance which routes
            // are simulating vs enforcing. Amber matches "warning" semantics.
            tags.push(format!("{yellow}waf:shadow{reset}"));
        } else {
            tags.push(format!("{green}waf{reset}"));
        }
    }
    if route.cache_profile.is_some() {
        tags.push(format!("{yellow}cache{reset}"));
    }
    if route.internal_only {
        tags.push(format!("{yellow}internal{reset}"));
    }

    if tags.is_empty() {
        return String::new();
    }
    let sep = format!(" {dim_sep}·{reset} ");
    tags.join(&sep)
}

fn truncate_chars(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(path: &str) -> RouteConfig {
        RouteConfig {
            path: path.into(),
            hosts: None,
            upstream: "backend".into(),
            mode: RouteMode::Standard,
            serve_dir: None,
            spa_fallback: false,
            precompressed: false,
            internal_only: false,
            waf_profile: None,
            cache_profile: None,
            csp: None,
            auth_profile: None,
            waf: false,
            max_body_mb: None,
            waf_shadow: false,
            cors: None,
        }
    }

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
        let cfg = parse_schema(toml, "test").expect("parse");
        assert!(validate_semantics(&cfg, "test").is_err());
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

    #[test]
    fn route_tags_plain_passthrough_is_empty() {
        let r = route("/static");
        assert_eq!(render_route_tags(&r, false), "");
    }

    #[test]
    fn route_tags_waf_only() {
        let mut r = route("/api");
        r.waf = true;
        assert_eq!(render_route_tags(&r, false), "waf");
    }

    #[test]
    fn route_tags_named_waf_profile_counts() {
        let mut r = route("/api");
        r.waf_profile = Some("strict".into());
        assert_eq!(render_route_tags(&r, false), "waf");
    }

    #[test]
    fn route_tags_static_with_cache() {
        let mut r = route("/_next/static");
        r.mode = RouteMode::StaticCache;
        r.cache_profile = Some("immutable".into());
        // Mode tag first, then perf tag
        assert_eq!(render_route_tags(&r, false), "static · cache");
    }

    #[test]
    fn route_tags_sse_stream() {
        let mut r = route("/events");
        r.mode = RouteMode::SseStream;
        assert_eq!(render_route_tags(&r, false), "sse");
    }

    #[test]
    fn route_tags_websocket() {
        let mut r = route("/ws");
        r.mode = RouteMode::Websocket;
        assert_eq!(render_route_tags(&r, false), "ws");
    }

    #[test]
    fn route_tags_internal_marked() {
        let mut r = route("/metrics");
        r.internal_only = true;
        assert_eq!(render_route_tags(&r, false), "internal");
    }

    #[test]
    fn route_tags_shadow_replaces_waf_tag() {
        // waf=true alone → "waf"
        let mut r = route("/api");
        r.waf = true;
        assert_eq!(render_route_tags(&r, false), "waf");
        // waf=true + shadow → "waf:shadow" so the visual distinction is
        // unmissable when scanning the boot output.
        r.waf_shadow = true;
        assert_eq!(render_route_tags(&r, false), "waf:shadow");
    }

    #[test]
    fn route_tags_shadow_with_named_profile() {
        let mut r = route("/api");
        r.waf_profile = Some("strict".into());
        r.waf_shadow = true;
        assert_eq!(render_route_tags(&r, false), "waf:shadow");
    }

    #[test]
    fn route_tags_shadow_no_waf_attached_no_tag() {
        // Shadow without any WAF profile attached → no tag (logical no-op).
        let mut r = route("/static");
        r.waf_shadow = true;
        // We still don't render anything because there's no WAF on the route.
        // Treating shadow as a strict modifier of the waf tag.
        assert_eq!(render_route_tags(&r, false), "");
    }

    #[test]
    fn route_tags_color_uses_ansi_per_category() {
        let mut r = route("/api");
        r.waf = true;
        r.internal_only = true;
        let tagged = render_route_tags(&r, true);
        // Green for waf (security), amber for internal (restricted), dim
        // separator between them.
        assert!(tagged.contains("\x1b[38;5;46mwaf"), "got: {tagged}");
        assert!(tagged.contains("\x1b[38;5;220minternal"), "got: {tagged}");
        assert!(
            tagged.contains("\x1b[2m·"),
            "expected dim separator: {tagged}"
        );
    }

    #[test]
    fn truncate_chars_keeps_short_unchanged() {
        assert_eq!(truncate_chars("/api", 40), "/api");
    }

    #[test]
    fn truncate_chars_clips_long_with_ellipsis() {
        let long = "/api/v1/very/long/nested/path/that/exceeds/the/cap/easily";
        let out = truncate_chars(long, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_chars_handles_unicode() {
        // Em-dashes and box characters count as 1 each
        let s = "abc—def★ghi";
        assert_eq!(truncate_chars(s, 5).chars().count(), 5);
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
        assert_eq!(api.url.as_deref(), Some("http://127.0.0.1:8000"));
        assert_eq!(api.connect_timeout_ms, 5000);
        assert_eq!(api.keepalive, 128);
        assert!(!api.tls); // default false
    }

    #[test]
    fn upstream_defaults() {
        let config: ZionConfig = toml::from_str(profile_toml()).unwrap();
        let fe = config.upstream.get("frontend").unwrap();
        assert_eq!(fe.connect_timeout_ms, 3000); // default
        assert_eq!(fe.keepalive, 64); // default
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

    #[test]
    fn resolve_upstream_prefers_new_format_over_legacy() {
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstream.api]
url = "http://new:9000"
[upstreams]
api = "http://old:8000"
[[route]]
path = "/test"
upstream = "api"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        let route = router.at(None, "/test").unwrap();
        // New [upstream.X] takes precedence over [upstreams] legacy
        assert_eq!(route.upstream_url[0], "http://new:9000");
    }

    // ── Host-based L7 routing (ADR-0010) ──────────────────────────────────

    #[test]
    fn host_router_exact_and_shared_fallback() {
        // Two host-bound routes on the SAME path + a shared catch-all — exactly
        // what path-only routing could not express (ADR-0010).
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstream.api]
url = "http://127.0.0.1:8000"
[upstream.app]
url = "http://127.0.0.1:3000"
[upstream.fallback]
url = "http://127.0.0.1:9000"
[[route]]
path = "/{*rest}"
hosts = ["api.example.com"]
upstream = "api"
[[route]]
path = "/{*rest}"
hosts = ["app.example.com"]
upstream = "app"
[[route]]
path = "/{*rest}"
upstream = "fallback"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        assert!(router.active);

        // Same path, different host → different backend (the whole point).
        assert_eq!(
            router
                .at(Some("api.example.com"), "/x")
                .unwrap()
                .upstream_url[0],
            "http://127.0.0.1:8000"
        );
        assert_eq!(
            router
                .at(Some("app.example.com"), "/x")
                .unwrap()
                .upstream_url[0],
            "http://127.0.0.1:3000"
        );
        // Unknown host → shared/default layer.
        assert_eq!(
            router
                .at(Some("other.example.com"), "/x")
                .unwrap()
                .upstream_url[0],
            "http://127.0.0.1:9000"
        );
        // No host (e.g. HTTP/1.0) → shared layer.
        assert_eq!(
            router.at(None, "/x").unwrap().upstream_url[0],
            "http://127.0.0.1:9000"
        );
    }

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

    #[test]
    fn hostless_config_is_not_active() {
        // No route declares `hosts` ⇒ host routing inactive ⇒ the shared tree
        // behaves exactly as the pre-ADR-0010 single router.
        let config: ZionConfig = toml::from_str(minimal_toml()).unwrap();
        let router = build_router(&config).unwrap();
        assert!(!router.active);
        // A host is simply ignored — everything resolves via the shared tree.
        assert!(router.at(Some("whatever.example.com"), "/api/x").is_some());
        assert!(router.at(None, "/api/x").is_some());
    }

    #[test]
    fn host_router_wildcard_and_precedence() {
        fn url<'a>(r: &'a HostRouter, host: &str, path: &str) -> &'a str {
            r.at(Some(host), path)
                .expect("route should resolve")
                .upstream_url[0]
                .as_str()
        }
        let toml_str = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/tmp/c.pem"
key_path = "/tmp/k.pem"
[upstream.exact]
url = "http://127.0.0.1:8000"
[upstream.wild]
url = "http://127.0.0.1:8001"
[upstream.deep]
url = "http://127.0.0.1:8002"
[upstream.shared]
url = "http://127.0.0.1:9000"
[[route]]
path = "/{*rest}"
hosts = ["api.example.com"]
upstream = "exact"
[[route]]
path = "/{*rest}"
hosts = ["*.example.com"]
upstream = "wild"
[[route]]
path = "/{*rest}"
hosts = ["*.api.example.com"]
upstream = "deep"
[[route]]
path = "/{*rest}"
upstream = "shared"
"#;
        let config: ZionConfig = toml::from_str(toml_str).unwrap();
        let router = build_router(&config).unwrap();
        assert!(router.active);

        // Exact host beats any wildcard.
        assert_eq!(
            url(&router, "api.example.com", "/x"),
            "http://127.0.0.1:8000"
        );
        // A subdomain with no exact entry matches the wildcard.
        assert_eq!(
            url(&router, "foo.example.com", "/x"),
            "http://127.0.0.1:8001"
        );
        // The most-specific wildcard wins (`*.api.example.com` > `*.example.com`).
        assert_eq!(
            url(&router, "v1.api.example.com", "/x"),
            "http://127.0.0.1:8002"
        );
        // The apex (no leading label) does NOT match `*.example.com` → shared.
        assert_eq!(url(&router, "example.com", "/x"), "http://127.0.0.1:9000");
        // An unrelated host → shared.
        assert_eq!(url(&router, "other.org", "/x"), "http://127.0.0.1:9000");
    }
}
