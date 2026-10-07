// SPDX-License-Identifier: Apache-2.0
//! Zion Auth Gate — JWT/OIDC validation middleware.
//!
//! Feature-gated: compile with `--features auth` to enable.
//!
//! Supports:
//! - HMAC-SHA256 (symmetric, for internal microservices)
//! - RSA/EC via JWKS (asymmetric, for OIDC providers: Auth0, Keycloak, Okta)
//!
//! Per-route: assign `auth_profile = "name"` in route config.
//! Zero cost when not configured.

#[cfg(feature = "auth")]
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
#[cfg(feature = "auth")]
use std::sync::Arc;

/// Standard JWT claims (subset — we only validate what matters for a proxy).
///
/// The struct is always defined (it appears in `validate_token`'s signature
/// when the `auth` feature is on) but its fields are only read by code
/// behind `#[cfg(feature = "auth")]`. Hence the targeted allow.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: Option<String>,
    /// Email (commonly present in OIDC tokens)
    pub email: Option<String>,
    /// Issuer
    pub iss: Option<String>,
    /// Audience: RFC 7519 §4.1.3 allows a single string or an array of strings, and
    /// OIDC providers commonly send an array. (Matching against the profile's
    /// `audience` is done by `jsonwebtoken` on the raw claims; this field only has
    /// to deserialize whatever shape the token carries.)
    pub aud: Option<Audience>,
    /// Expiration (Unix timestamp)
    pub exp: Option<u64>,
    /// Not before (Unix timestamp)
    pub nbf: Option<u64>,
    /// Token id. Only a token that carries one can be revoked (`POST /admin/revoke`).
    pub jti: Option<String>,
}

/// The `aud` claim: one audience or several.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl From<&str> for Audience {
    fn from(s: &str) -> Self {
        Audience::One(s.to_string())
    }
}

/// A secret string. It never appears in `Debug` output (so a stray `{:?}` of a
/// config struct cannot write a signing key to a log or panic message) and its
/// bytes are wiped when the value is dropped. Deserializes from a plain string.
#[allow(dead_code)]
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

#[allow(dead_code)]
impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_string())
    }
}

/// Auth profile configuration (from TOML).
///
/// `AuthProfileConfig` is always deserialized (config.rs references it
/// outside any feature gate so users get clear "unknown auth_profile"
/// validation errors at startup regardless of build flavour). The fields
/// are only consumed by code under `#[cfg(feature = "auth")]`.
#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AuthProfileConfig {
    /// Expected issuer (validated against token's `iss` claim).
    #[serde(default)]
    pub issuer: Option<String>,
    /// Expected audience (validated against token's `aud` claim).
    #[serde(default)]
    pub audience: Option<String>,
    /// HMAC secret for symmetric validation (base64 or raw string).
    ///
    /// **Deprecated: use `secret_env`.** A literal here puts a live signing key in
    /// zion.toml, which tends to land in version control / config management in
    /// plaintext, and anyone who reads the file can forge valid tokens. Zion
    /// warns at boot when it is used. The value is redacted from `Debug` output
    /// and wiped from memory when the config is dropped.
    #[serde(default)]
    pub secret: Option<Secret>,
    /// Name of an environment variable holding the HMAC secret. Preferred over
    /// the literal `secret` — it keeps the signing key out of the config file,
    /// mirroring `[audit] key_env`. When both are set, `secret_env` wins.
    #[serde(default)]
    pub secret_env: Option<String>,
    /// Name of an environment variable holding the PREVIOUS HMAC secret, for rotation
    /// without an outage: a token whose signature the current secret rejects is checked
    /// against this one. Set it to the old key when you change `secret_env`, and remove it
    /// once every token signed with the old key has expired. Only with an HMAC secret.
    #[serde(default)]
    pub previous_secret_env: Option<String>,
    /// JWKS URL for asymmetric validation (fetched at startup).
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Algorithm hint: "HS256" (default for secret), "RS256" (default for JWKS).
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Forward decoded claims as X-Auth-Subject, X-Auth-Email headers.
    #[serde(default = "default_true")]
    pub forward_claims: bool,
    /// Clock-skew tolerance, in seconds, applied to `exp` and `nbf`. Default 30.
    /// Zero is allowed; above 300 is rejected (a large leeway silently extends
    /// every token's life).
    #[serde(default = "default_leeway_secs")]
    pub leeway_secs: u64,
    /// Upper bound, in seconds, on how far in the future a token's `exp` may be (plus
    /// `leeway_secs`). Tokens that outlive it are rejected even though they are otherwise
    /// valid. Zion has no revocation list that survives key theft, so this is the lever
    /// that bounds how long a stolen or de-provisioned user's token keeps working: set it
    /// to the longest token lifetime you actually issue (e.g. 900).
    ///
    /// Unset = **86400 (24 h)**, the default since 0.10.0 (before it: no cap). `0` = no
    /// cap, said on purpose. A token accepted with more than 24 h left (under `0`, or a cap
    /// above 24 h) is counted in `zion_auth_long_lived_tokens_total`.
    #[serde(default)]
    pub max_token_lifetime_secs: Option<u64>,
}

fn default_leeway_secs() -> u64 {
    30
}
#[cfg(feature = "auth")]
const MAX_LEEWAY_SECS: u64 = 300;

fn default_algorithm() -> String {
    "HS256".to_string()
}
fn default_true() -> bool {
    true
}

/// Resolved auth profile (pre-built at startup, zero cost at runtime).
#[cfg(feature = "auth")]
#[derive(Clone)]
pub struct ResolvedAuthProfile {
    pub jwks_url: Option<String>,
    pub decoding_key: Option<Arc<DecodingKey>>,
    /// The key of `previous_secret_env`: tried when the current one rejects the signature.
    pub previous_decoding_key: Option<Arc<DecodingKey>>,
    pub jwk_set: Arc<arc_swap::ArcSwapOption<jsonwebtoken::jwk::JwkSet>>,
    pub validation: Arc<Validation>,
    pub forward_claims: bool,
    /// See [`AuthProfileConfig::max_token_lifetime_secs`]; `None` is the 24 h default.
    pub max_token_lifetime_secs: Option<u64>,
    pub leeway_secs: u64,
}

#[cfg(feature = "auth")]
impl std::fmt::Debug for ResolvedAuthProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedAuthProfile")
            .field("forward_claims", &self.forward_claims)
            .finish()
    }
}

/// Auth error — returned when validation fails.
/// Reachable only via `validate_token`, which is `#[cfg(feature = "auth")]`.
#[allow(dead_code)]
#[derive(Debug)]
pub enum AuthError {
    /// Token is malformed or signature invalid
    InvalidToken(String),
    /// Token has expired
    Expired,
    /// Token id was revoked through the admin API
    Revoked,
}

/// Extract Bearer token from Authorization header.
/// Case-insensitive prefix per RFC 6750 §2.1.
/// Called only by the auth gate, which is `#[cfg(feature = "auth")]`.
#[allow(dead_code)]
#[inline]
pub fn extract_bearer(auth_header: &str) -> Option<&str> {
    if auth_header.len() < 7 {
        return None;
    }
    if !auth_header.as_bytes()[..7].eq_ignore_ascii_case(b"Bearer ") {
        return None;
    }
    let token = &auth_header[7..];
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Denylist of revoked token ids (`jti`). Per instance; kept across restarts when
/// `[admin] revocations_path` is set ([`revocation::append`] / [`revocation::load`]),
/// in memory only otherwise. An entry only has to outlive the token, so each carries the
/// token's own expiry and is dropped after it. A token without a `jti` cannot be revoked.
pub mod revocation {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// Upper bound on live entries; a full list refuses new ones rather than grow.
    pub const MAX_ENTRIES: usize = 100_000;

    fn list() -> &'static Mutex<HashMap<String, u64>> {
        static L: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Revoke `jti` until `exp` (Unix seconds). Returns the live entry count.
    pub fn revoke(jti: &str, exp: u64) -> Result<usize, &'static str> {
        if jti.is_empty() || jti.len() > 256 {
            return Err("jti must be 1..=256 bytes");
        }
        let mut m = list().lock().unwrap_or_else(|e| e.into_inner());
        let t = now();
        m.retain(|_, e| *e > t);
        if m.len() >= MAX_ENTRIES && !m.contains_key(jti) {
            return Err("revocation list is full");
        }
        m.insert(jti.to_string(), exp);
        Ok(m.len())
    }

    /// One persisted revocation: a line of the file at `[admin] revocations_path`.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Record {
        jti: String,
        exp: u64,
    }

    /// Record a revocation at `path` so it survives a restart: one JSON line, appended and
    /// synced before the caller answers the operator.
    pub fn append(path: &std::path::Path, jti: &str, exp: u64) -> Result<(), String> {
        use std::io::Write;
        let mut line = serde_json::to_string(&Record {
            jti: jti.to_string(),
            exp,
        })
        .map_err(|e| e.to_string())?;
        line.push('\n');
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600); // token ids are not secrets, but they are nobody else's business
        }
        let mut file = options
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_data())
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Load the revocations recorded at `path` (boot), dropping the expired ones, and rewrite
    /// the file with what is still live. Returns the live count. A missing file is an empty
    /// list; an unreadable one is an error, because starting without it would make every
    /// revoked token valid again. A line that does not parse (a write cut short by a crash)
    /// is skipped and counted in the second value.
    pub fn load(path: &std::path::Path) -> Result<(usize, usize), String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let t = now();
        let mut skipped = 0;
        let mut live: Vec<Record> = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Record>(line) {
                Ok(r) if r.exp > t => live.push(r),
                Ok(_) => {} // expired: the token is dead anyway
                Err(_) => skipped += 1,
            }
        }
        {
            let mut m = list().lock().unwrap_or_else(|e| e.into_inner());
            for r in &live {
                if m.len() >= MAX_ENTRIES && !m.contains_key(&r.jti) {
                    break;
                }
                m.insert(r.jti.clone(), r.exp);
            }
        }
        // Compact: without this the file would keep every revocation ever made.
        let mut compact = String::new();
        for r in &live {
            compact.push_str(&serde_json::to_string(r).map_err(|e| e.to_string())?);
            compact.push('\n');
        }
        crate::atomic_file::write_atomic_0600(path, compact.as_bytes())?;
        Ok((live.len(), skipped))
    }

    /// True when `jti` is on the list and its token could still be valid.
    #[cfg_attr(not(feature = "auth"), allow(dead_code))] // read only by the auth gate
    pub fn is_revoked(jti: &str) -> bool {
        let m = list().lock().unwrap_or_else(|e| e.into_inner());
        m.get(jti).is_some_and(|e| *e > now())
    }
}

/// The cap a profile without `max_token_lifetime_secs` gets (24 h), since 0.10.0 (#553).
pub const DEFAULT_MAX_TOKEN_LIFETIME_SECS: u64 = 86_400;

/// What a profile's lifetime cap says about a token expiring at `exp`.
#[cfg_attr(not(feature = "auth"), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
enum Lifetime {
    Ok,
    /// Further out than the cap (the value carried): refused.
    Refused(u64),
    /// Accepted although it expires more than 24 h from now: the operator set `0` or a cap
    /// above the default. Counted, so the long-lived tokens still in use are visible.
    AcceptedBeyondDefault,
}

#[cfg_attr(not(feature = "auth"), allow(dead_code))]
fn lifetime_verdict(cap: Option<u64>, exp: u64, now: u64, leeway: u64) -> Lifetime {
    let beyond = |max: u64| exp > now.saturating_add(max).saturating_add(leeway);
    let past_default = beyond(DEFAULT_MAX_TOKEN_LIFETIME_SECS);
    match cap.unwrap_or(DEFAULT_MAX_TOKEN_LIFETIME_SECS) {
        0 if past_default => Lifetime::AcceptedBeyondDefault, // "no cap", said on purpose
        0 => Lifetime::Ok,
        max if beyond(max) => Lifetime::Refused(max),
        _ if past_default => Lifetime::AcceptedBeyondDefault,
        _ => Lifetime::Ok,
    }
}

/// Count a token accepted past the default cap (`zion_auth_long_lived_tokens_total`).
#[cfg_attr(not(feature = "auth"), allow(dead_code))]
fn count_long_lived_token() {
    crate::metrics::METRICS
        .auth_long_lived_tokens
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Say that a token was refused for its lifetime, at most once a minute: since 0.10.0 an
/// upgrade can start refusing tokens that were accepted before, and the 401 alone does not
/// tell the operator why. The remaining lifetime and the cap only, never the token or its
/// claims.
#[cfg_attr(not(feature = "auth"), allow(dead_code))]
fn note_refused_long_lived_token(remaining_secs: u64, cap: u64, cap_is_default: bool) {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    static LAST_WARNED: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_WARNED.load(Relaxed);
    if now.saturating_sub(last) >= 60
        && LAST_WARNED
            .compare_exchange(last, now, Relaxed, Relaxed)
            .is_ok()
    {
        let which = if cap_is_default {
            "the default cap (max_token_lifetime_secs is not set)"
        } else {
            "its max_token_lifetime_secs"
        };
        crate::logging::warn(
            "auth",
            &format!(
                "refused a token that expires in {} h: {which} is {cap} s. Set \
                 max_token_lifetime_secs to the longest lifetime you issue, or to 0 for no cap",
                remaining_secs / 3600
            ),
        );
    }
}

/// Validate a JWT token against a resolved auth profile.
/// Returns decoded claims on success.
#[cfg(feature = "auth")]
pub fn validate_token(token: &str, profile: &ResolvedAuthProfile) -> Result<Claims, AuthError> {
    let decoding_key_owned;
    let decoding_key_ref = if let Some(ref dk) = profile.decoding_key {
        // HMAC or static key
        dk.as_ref()
    } else if profile.jwks_url.is_some() {
        // Asymmetric JWKS: Extract kid, lookup JWK, build DecodingKey
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("Missing kid in token header".to_string()))?;

        let jwk_set_guard = profile.jwk_set.load();
        let jwk_set = jwk_set_guard.as_ref().ok_or_else(|| {
            AuthError::InvalidToken(
                "JWKS not yet loaded. Please try again in a few seconds.".to_string(),
            )
        })?;

        let jwk = jwk_set
            .find(&kid)
            .ok_or_else(|| AuthError::InvalidToken(format!("Key ID {kid} not found in JWKS")))?;
        decoding_key_owned = DecodingKey::from_jwk(jwk)
            .map_err(|e| AuthError::InvalidToken(format!("Failed to parse JWK: {e}")))?;
        &decoding_key_owned
    } else {
        return Err(AuthError::InvalidToken(
            "No decoding key configured".to_string(),
        ));
    };

    let attempt = |key: &DecodingKey| decode::<Claims>(token, key, &profile.validation);
    let decoded = match attempt(decoding_key_ref) {
        // Rotation window: the current secret does not verify the signature, the previous
        // one may. Every other check (expiry, issuer, audience) is the same for both.
        Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidSignature) => {
            match profile.previous_decoding_key.as_deref() {
                Some(previous) => attempt(previous),
                None => Err(e),
            }
        }
        other => other,
    };
    let token_data: TokenData<Claims> = decoded.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("ExpiredSignature") {
            AuthError::Expired
        } else {
            AuthError::InvalidToken(msg)
        }
    })?;

    if let Some(jti) = token_data.claims.jti.as_deref() {
        if revocation::is_revoked(jti) {
            return Err(AuthError::Revoked);
        }
    }

    // Bound how long a token can be valid for. There is no revocation list, so
    // without this a token with a far-future `exp` (or a stolen one) stays valid
    // until it expires.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = token_data.claims.exp.unwrap_or(u64::MAX);
    match lifetime_verdict(
        profile.max_token_lifetime_secs,
        exp,
        now,
        profile.leeway_secs,
    ) {
        Lifetime::Ok => {}
        Lifetime::Refused(max) => {
            note_refused_long_lived_token(
                exp.saturating_sub(now),
                max,
                profile.max_token_lifetime_secs.is_none(),
            );
            return Err(AuthError::InvalidToken(format!(
                "token lifetime exceeds this profile's max_token_lifetime_secs ({max}s)"
            )));
        }
        Lifetime::AcceptedBeyondDefault => count_long_lived_token(),
    }

    Ok(token_data.claims)
}

/// Build a resolved auth profile from config.
/// Called once at startup — pre-computes DecodingKey and Validation.
///
/// Returns `Err` if the algorithm is unrecognised or if the profile
/// configures neither `secret` (HMAC) nor `jwks_url` (OIDC). The error
/// is a String so the caller (`routing::build_router`) can wrap it with
/// the route/profile name in its own error format.
#[cfg(feature = "auth")]
pub fn resolve_auth_profile(config: &AuthProfileConfig) -> Result<ResolvedAuthProfile, String> {
    // Resolve the effective HMAC secret: `secret_env` (preferred, keeps the key
    // out of the config file) wins over a literal `secret`. A named-but-missing
    // or empty env var is a hard error — failing closed beats silently falling
    // back to no symmetric key (which would then error as "neither configured"
    // and mask the operator's real mistake).
    if config.leeway_secs > MAX_LEEWAY_SECS {
        return Err(format!(
            "auth leeway_secs = {} is too large (max {MAX_LEEWAY_SECS}): it silently extends every token's lifetime",
            config.leeway_secs
        ));
    }
    let effective_secret: Option<zeroize::Zeroizing<String>> =
        if let Some(ref env_name) = config.secret_env {
            match std::env::var(env_name) {
                Ok(v) if !v.is_empty() => Some(zeroize::Zeroizing::new(v)),
                Ok(_) => return Err(format!("auth secret_env '{env_name}' is set but empty")),
                Err(_) => {
                    return Err(format!(
                        "auth secret_env '{env_name}' is not set in the environment"
                    ))
                }
            }
        } else {
            config
                .secret
                .as_ref()
                .map(|s| zeroize::Zeroizing::new(s.expose().to_string()))
        };

    let mut alg_str = config.algorithm.clone();
    if alg_str == "HS256" && config.jwks_url.is_some() && effective_secret.is_none() {
        alg_str = "RS256".to_string(); // Default to RS256 for asymmetric OIDC profiles
    }

    let algorithm = match alg_str.as_str() {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        other => return Err(format!("unsupported JWT algorithm: {other}")),
    };

    // RFC 7518 §3.2: an HMAC key must be at least as long as the hash output. A short
    // secret makes tokens forgeable offline by brute force, so refuse it rather than
    // accept a signature check that only looks like one.
    if let Some(ref secret) = effective_secret {
        let min = match algorithm {
            Algorithm::HS256 => 32,
            Algorithm::HS384 => 48,
            Algorithm::HS512 => 64,
            _ => 0,
        };
        if secret.len() < min {
            return Err(format!(
                "auth secret for {alg_str} is {} bytes; it must be at least {min} (RFC 7518 \
                 §3.2). Generate one with: openssl rand -base64 {min}",
                secret.len()
            ));
        }
    }

    // The previous secret of a rotation: same rules as the current one (set, long enough),
    // and only meaningful next to a current HMAC secret.
    let mut previous_decoding_key = None;
    if let Some(ref env_name) = config.previous_secret_env {
        if effective_secret.is_none() {
            return Err(format!(
                "auth previous_secret_env '{env_name}' is set, but the profile has no HMAC \
                 secret (secret_env / secret): there is nothing to rotate"
            ));
        }
        let previous = match std::env::var(env_name) {
            Ok(v) if !v.is_empty() => zeroize::Zeroizing::new(v),
            _ => {
                return Err(format!(
                    "auth previous_secret_env '{env_name}' is not set in the environment (or \
                     empty): remove the setting once the rotation is over"
                ))
            }
        };
        let min = match algorithm {
            Algorithm::HS256 => 32,
            Algorithm::HS384 => 48,
            Algorithm::HS512 => 64,
            _ => 0,
        };
        if previous.len() < min {
            return Err(format!(
                "auth previous secret for {alg_str} is {} bytes; it must be at least {min}",
                previous.len()
            ));
        }
        previous_decoding_key = Some(Arc::new(DecodingKey::from_secret(previous.as_bytes())));
    }

    let mut decoding_key = None;
    let jwk_set_arc = Arc::new(arc_swap::ArcSwapOption::empty());

    if let Some(ref secret) = effective_secret {
        decoding_key = Some(Arc::new(DecodingKey::from_secret(secret.as_bytes())));
    } else if let Some(ref jwks_url) = config.jwks_url {
        let url = jwks_url.clone();
        let key_store = jwk_set_arc.clone();

        // Spawn background task to periodically fetch JWKS.
        // Uses exponential backoff on failure (5s → 10s → ... → 3600s).
        tokio::spawn(async move {
            let client = loop {
                // Bound both the connect and the overall request: reqwest has
                // NO default timeout, so a JWKS endpoint that accepts the
                // connection but never responds would park `send().await`
                // forever, wedging the refresh loop and freezing key rotation.
                // With a deadline the hung fetch fails and trips the backoff
                // path below instead.
                match reqwest::Client::builder()
                    .connect_timeout(std::time::Duration::from_secs(5))
                    .timeout(std::time::Duration::from_secs(15))
                    .build()
                {
                    Ok(c) => break c,
                    Err(e) => {
                        crate::logging::error(
                            "auth",
                            &format!("Failed to build JWKS HTTP client: {e}, retrying in 5s"),
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            };

            let mut backoff_secs = 5u64;
            loop {
                match client.get(&url).send().await {
                    Ok(resp) => match resp.json::<jsonwebtoken::jwk::JwkSet>().await {
                        Ok(jwks) => {
                            key_store.store(Some(Arc::new(jwks)));
                            crate::logging::info(
                                "auth",
                                &format!("JWKS successfully loaded from {url}"),
                            );
                            backoff_secs = 3600; // success: normal 1h refresh cycle
                        }
                        Err(e) => {
                            crate::logging::error(
                                "auth",
                                &format!("Failed to parse JWKS JSON: {e}"),
                            );
                            if backoff_secs >= 3600 {
                                backoff_secs = 5;
                            }
                            backoff_secs = (backoff_secs * 2).min(300);
                        }
                    },
                    Err(e) => {
                        // On failure after a previous success, reset backoff to short interval
                        if backoff_secs >= 3600 {
                            backoff_secs = 5;
                        }
                        crate::logging::error(
                            "auth",
                            &format!(
                                "Failed to fetch JWKS from {url}: {e}, retry in {backoff_secs}s"
                            ),
                        );
                        backoff_secs = (backoff_secs * 2).min(300); // cap failure backoff at 5min
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            }
        });
    } else {
        return Err(
            "auth profile requires either 'secret' (HMAC) or 'jwks_url' (OIDC); neither is set"
                .to_string(),
        );
    };

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    if let Some(ref iss) = config.issuer {
        validation.set_issuer(&[iss]);
    }
    if let Some(ref aud) = config.audience {
        validation.set_audience(&[aud]);
    }

    // Clock-skew tolerance for distributed systems (default 30s, capped above).
    validation.leeway = config.leeway_secs;

    Ok(ResolvedAuthProfile {
        jwks_url: config.jwks_url.clone(),
        decoding_key,
        previous_decoding_key,
        jwk_set: jwk_set_arc,
        validation: Arc::new(validation),
        forward_claims: config.forward_claims,
        max_token_lifetime_secs: config.max_token_lifetime_secs,
        leeway_secs: config.leeway_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "auth")]
    #[test]
    fn an_hmac_secret_shorter_than_the_hash_is_refused() {
        for (alg, min) in [("HS256", 32), ("HS384", 48), ("HS512", 64)] {
            let profile = |len: usize| -> AuthProfileConfig {
                toml::from_str(&format!(
                    "algorithm = \"{alg}\"\nsecret = \"{}\"\naudience = \"a\"\nissuer = \"i\"",
                    "k".repeat(len)
                ))
                .unwrap()
            };
            let err = resolve_auth_profile(&profile(min - 1))
                .err()
                .unwrap_or_default();
            assert!(err.contains(&format!("at least {min}")), "{alg}: {err}");
            assert!(
                resolve_auth_profile(&profile(min)).is_ok(),
                "{alg} at {min} bytes"
            );
        }
    }

    #[test]
    fn extract_bearer_valid() {
        assert_eq!(
            extract_bearer("Bearer eyJhbGciOiJIUzI1NiJ9"),
            Some("eyJhbGciOiJIUzI1NiJ9")
        );
    }

    #[test]
    fn extract_bearer_missing_prefix() {
        assert_eq!(extract_bearer("Basic dXNlcjpwYXNz"), None);
    }

    #[test]
    fn extract_bearer_empty_token() {
        assert_eq!(extract_bearer("Bearer "), None);
    }

    #[test]
    fn extract_bearer_no_space() {
        assert_eq!(extract_bearer("BearerToken"), None);
    }

    #[test]
    fn revocation_denies_until_expiry_and_is_bounded() {
        use super::revocation::*;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!is_revoked("rev-test-a"));
        revoke("rev-test-a", now + 60).unwrap();
        assert!(is_revoked("rev-test-a"));
        assert!(!is_revoked("rev-test-other"), "only the named id");
        // an entry whose token has already expired no longer counts
        revoke("rev-test-old", now.saturating_sub(5)).unwrap();
        assert!(!is_revoked("rev-test-old"));
        assert!(revoke("", now + 60).is_err());
        assert!(revoke(&"x".repeat(257), now + 60).is_err());
    }

    #[cfg(feature = "auth")]
    #[test]
    fn a_revoked_token_is_refused_even_though_it_verifies() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let secret = "test-secret-key-for-zion-padding-padding-padding-padding";
        let mk = |jti: Option<&str>| {
            let claims = Claims {
                sub: Some("u".into()),
                email: None,
                iss: Some("zion-test".into()),
                aud: Some("api.zion.dev".into()),
                exp: Some(u64::MAX),
                nbf: Some(0),
                jti: jti.map(str::to_string),
            };
            encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_bytes()),
            )
            .unwrap()
        };
        let config = AuthProfileConfig {
            issuer: Some("zion-test".into()),
            audience: Some("api.zion.dev".into()),
            secret: Some(secret.into()),
            secret_env: None,
            previous_secret_env: None,
            jwks_url: None,
            algorithm: "HS256".into(),
            forward_claims: false,
            leeway_secs: 30,
            // These tests are about signatures, audiences and revocation, with tokens that
            // expire far out: "no cap", said on purpose (the default cap has its own tests).
            max_token_lifetime_secs: Some(0),
        };
        let profile = resolve_auth_profile(&config).unwrap();
        let (with, without) = (mk(Some("rev-test-token-1")), mk(None));
        assert!(validate_token(&with, &profile).is_ok());
        revocation::revoke("rev-test-token-1", u64::MAX).unwrap();
        assert!(matches!(
            validate_token(&with, &profile),
            Err(AuthError::Revoked)
        ));
        assert!(
            validate_token(&without, &profile).is_ok(),
            "a token with no jti cannot be revoked (documented)"
        );
    }

    #[cfg(feature = "auth")]
    #[test]
    fn validate_hmac_token_roundtrip() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test-secret-key-for-zion-padding-padding-padding-padding";
        let claims = Claims {
            sub: Some("user-123".to_string()),
            email: Some("test@zion.dev".to_string()),
            iss: Some("zion-test".to_string()),
            aud: Some("api.zion.dev".into()),
            exp: Some(u64::MAX), // far future
            nbf: Some(0),
            jti: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let config = AuthProfileConfig {
            issuer: Some("zion-test".to_string()),
            audience: Some("api.zion.dev".to_string()),
            secret: Some(secret.into()),
            secret_env: None,
            previous_secret_env: None,
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
            leeway_secs: 30,
            // These tests are about signatures, audiences and revocation, with tokens that
            // expire far out: "no cap", said on purpose (the default cap has its own tests).
            max_token_lifetime_secs: Some(0),
        };

        let profile = resolve_auth_profile(&config).expect("valid test profile");
        let result = validate_token(&token, &profile);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("user-123"));
        assert_eq!(decoded.email.as_deref(), Some("test@zion.dev"));
    }

    #[cfg(feature = "auth")]
    #[test]
    fn validate_wrong_secret_fails() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let claims = Claims {
            sub: Some("user".to_string()),
            email: None,
            iss: None,
            aud: None,
            exp: Some(u64::MAX),
            nbf: Some(0),
            jti: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret-a-padding-padding-padding-padding"),
        )
        .unwrap();

        let config = AuthProfileConfig {
            issuer: None,
            audience: None,
            secret: Some("secret-b-padding-padding-padding-padding".into()), // wrong secret
            secret_env: None,
            previous_secret_env: None,
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
            leeway_secs: 30,
            // These tests are about signatures, audiences and revocation, with tokens that
            // expire far out: "no cap", said on purpose (the default cap has its own tests).
            max_token_lifetime_secs: Some(0),
        };

        let profile = resolve_auth_profile(&config).expect("valid test profile");
        let result = validate_token(&token, &profile);
        assert!(result.is_err());
    }

    #[cfg(feature = "auth")]
    #[test]
    fn validate_expired_token_fails() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let claims = Claims {
            sub: Some("user".to_string()),
            email: None,
            iss: None,
            aud: None,
            exp: Some(1000), // long past
            nbf: Some(0),
            jti: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret-padding-padding-padding-padding"),
        )
        .unwrap();

        let config = AuthProfileConfig {
            issuer: None,
            audience: None,
            secret: Some("secret-padding-padding-padding-padding".into()),
            secret_env: None,
            previous_secret_env: None,
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
            leeway_secs: 30,
            // These tests are about signatures, audiences and revocation, with tokens that
            // expire far out: "no cap", said on purpose (the default cap has its own tests).
            max_token_lifetime_secs: Some(0),
        };

        let profile = resolve_auth_profile(&config).expect("valid test profile");
        let result = validate_token(&token, &profile);
        assert!(matches!(result, Err(AuthError::Expired)));
    }

    #[cfg(feature = "auth")]
    /// Rotation without an outage (ZION-SEC-03): while `previous_secret_env` names the old
    /// key, tokens signed with it still verify; once it is removed they do not. A token
    /// signed with neither key is refused in both states.
    #[tokio::test]
    async fn tokens_signed_with_the_previous_secret_verify_during_a_rotation() {
        const OLD: &str = "old-key-padding-padding-padding-padding-0001";
        const NEW: &str = "new-key-padding-padding-padding-padding-0002";
        let (cur, prev) = ("ZION_TEST_AUTH_CUR_5f22", "ZION_TEST_AUTH_PREV_5f22");
        std::env::set_var(cur, NEW);
        std::env::set_var(prev, OLD);
        let profile = |previous: Option<&str>| AuthProfileConfig {
            issuer: None,
            audience: None,
            secret: None,
            secret_env: Some(cur.to_string()),
            previous_secret_env: previous.map(str::to_string),
            jwks_url: None,
            algorithm: "HS256".into(),
            forward_claims: true,
            leeway_secs: 30,
            // These tests are about signatures, audiences and revocation, with tokens that
            // expire far out: "no cap", said on purpose (the default cap has its own tests).
            max_token_lifetime_secs: Some(0),
        };
        let token = |key: &str, exp_in: i64| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(Algorithm::HS256),
                &serde_json::json!({"sub": "u", "exp": now + exp_in}),
                &jsonwebtoken::EncodingKey::from_secret(key.as_bytes()),
            )
            .unwrap()
        };
        let rotating = resolve_auth_profile(&profile(Some(prev))).expect("resolves");
        assert!(
            validate_token(&token(NEW, 600), &rotating).is_ok(),
            "current key"
        );
        assert!(
            validate_token(&token(OLD, 600), &rotating).is_ok(),
            "previous key, in the window"
        );
        assert!(
            validate_token(
                &token("some-other-key-padding-padding-padding-0003", 600),
                &rotating
            )
            .is_err(),
            "a key that is neither"
        );
        // The previous key does not excuse anything but the signature.
        assert!(
            matches!(
                validate_token(&token(OLD, -600), &rotating),
                Err(AuthError::Expired)
            ),
            "an expired token signed with the previous key is still expired"
        );
        // Rotation over: the setting is removed, the old key stops working.
        let rotated = resolve_auth_profile(&profile(None)).expect("resolves");
        assert!(validate_token(&token(NEW, 600), &rotated).is_ok());
        assert!(
            validate_token(&token(OLD, 600), &rotated).is_err(),
            "old key after the window"
        );
        // A previous secret that is not there, or too short, is a config error.
        std::env::remove_var(prev);
        let e = resolve_auth_profile(&profile(Some(prev))).unwrap_err();
        assert!(e.contains(prev) && e.contains("not set"), "{e}");
        std::env::set_var(prev, "short");
        let e = resolve_auth_profile(&profile(Some(prev))).unwrap_err();
        assert!(e.contains("at least 32") && !e.contains("short\""), "{e}");
        std::env::remove_var(prev);
        std::env::remove_var(cur);
    }

    /// Step 2 of the default lifetime cap (#553): a profile without the setting has a 24 h cap
    /// and refuses beyond it; `0` is "no cap" said on purpose; a configured cap is its own limit;
    /// a token accepted past 24 h is flagged so it is counted.
    #[test]
    fn a_missing_lifetime_cap_means_24_hours_and_zero_means_none() {
        let now = 1_000_000;
        let (hour, day) = (3_600, 86_400);
        let leeway = 30;
        // No setting: the default cap of 24 h (plus leeway) applies, and refuses beyond it.
        assert_eq!(
            lifetime_verdict(None, now + hour, now, leeway),
            Lifetime::Ok
        );
        assert_eq!(
            lifetime_verdict(None, now + day + leeway, now, leeway),
            Lifetime::Ok
        );
        assert_eq!(
            lifetime_verdict(None, now + day + leeway + 1, now, leeway),
            Lifetime::Refused(86_400)
        );
        assert_eq!(
            lifetime_verdict(None, u64::MAX, now, leeway),
            Lifetime::Refused(86_400)
        );
        // 0: no cap, said on purpose. A token past 24 h is accepted, and flagged so it is counted.
        assert_eq!(
            lifetime_verdict(Some(0), now + 400 * day, now, leeway),
            Lifetime::AcceptedBeyondDefault
        );
        assert_eq!(
            lifetime_verdict(Some(0), now + hour, now, leeway),
            Lifetime::Ok
        );
        // A cap above the default: its own limit, and beyond 24 h is flagged.
        assert_eq!(
            lifetime_verdict(Some(7 * day), now + 3 * day, now, leeway),
            Lifetime::AcceptedBeyondDefault
        );
        assert_eq!(
            lifetime_verdict(Some(7 * day), now + 8 * day, now, leeway),
            Lifetime::Refused(7 * day)
        );
        // A cap: refused beyond it, as before.
        assert_eq!(
            lifetime_verdict(Some(900), now + 900 + leeway, now, leeway),
            Lifetime::Ok
        );
        assert_eq!(
            lifetime_verdict(Some(900), now + 900 + leeway + 1, now, leeway),
            Lifetime::Refused(900)
        );
        // An already-expired token is not this check's business (exp validation refuses it).
        assert_eq!(lifetime_verdict(None, now - 10, now, leeway), Lifetime::Ok);
    }

    /// End to end through `validate_token`: a 25-hour token is refused by default (#553), accepted
    /// with `max_token_lifetime_secs = 0` or a cap above it, and counted when it is; a 1-hour one
    /// passes everywhere and is not counted.
    #[cfg(feature = "auth")]
    #[tokio::test]
    async fn a_token_past_24_hours_is_refused_by_default_and_counted_when_allowed() {
        const KEY: &str = "lifetime-key-padding-padding-padding-padding";
        let profile = |cap: Option<u64>| {
            resolve_auth_profile(&AuthProfileConfig {
                issuer: None,
                audience: None,
                secret: Some(KEY.into()),
                secret_env: None,
                previous_secret_env: None,
                jwks_url: None,
                algorithm: "HS256".into(),
                forward_claims: true,
                leeway_secs: 30,
                max_token_lifetime_secs: cap,
            })
            .expect("resolves")
        };
        let token = |secs: u64| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(Algorithm::HS256),
                &serde_json::json!({"sub": "u", "exp": now + secs}),
                &jsonwebtoken::EncodingKey::from_secret(KEY.as_bytes()),
            )
            .unwrap()
        };
        let counted = || {
            crate::metrics::METRICS
                .auth_long_lived_tokens
                .load(std::sync::atomic::Ordering::Relaxed)
        };
        let before = counted();
        let refused = validate_token(&token(25 * 3600), &profile(None)).unwrap_err();
        assert!(
            matches!(&refused, AuthError::InvalidToken(m) if m.contains("86400")),
            "by default a token with 25 h left is refused, and says which cap: {refused:?}"
        );
        assert_eq!(counted(), before, "a refused token is not an accepted one");
        assert!(
            validate_token(&token(3600), &profile(None)).is_ok(),
            "an hour is fine"
        );
        assert_eq!(counted(), before, "and not counted");
        assert!(
            validate_token(&token(25 * 3600), &profile(Some(0))).is_ok(),
            "0 = no cap"
        );
        assert_eq!(counted(), before + 1, "accepted past 24 h: counted");
        assert!(
            validate_token(&token(25 * 3600), &profile(Some(7 * 86_400))).is_ok(),
            "a cap above the default is the operator's choice"
        );
        assert_eq!(counted(), before + 2);
        assert!(
            validate_token(&token(25 * 3600), &profile(Some(3600))).is_err(),
            "a configured cap still refuses"
        );
    }

    /// A revocation recorded on disk is back after a restart (ZION-AUTH-06): `load` is what
    /// the boot runs. Expired entries are dropped and the file is compacted; a line cut
    /// short by a crash is skipped, not fatal; a missing file is an empty list.
    #[test]
    fn a_recorded_revocation_survives_a_restart() {
        use revocation::{append, is_revoked, load};
        let dir = std::env::temp_dir().join(format!("zion-revocations-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked.jsonl");
        assert_eq!(load(&path).unwrap(), (0, 0), "no file yet: nothing revoked");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        append(&path, "persist-live-1", now + 3600).unwrap();
        append(&path, "persist-live \"quoted\" \n 2", now + 3600).unwrap();
        append(&path, "persist-expired", now - 10).unwrap();
        // a write cut short by a crash
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"{\"jti\":\"persist-torn"))
            .unwrap();
        // "Restart": none of these is in memory (append does not touch the list).
        assert!(!is_revoked("persist-live-1"));
        assert_eq!(
            load(&path).unwrap(),
            (2, 1),
            "two live, one unreadable line"
        );
        assert!(is_revoked("persist-live-1"));
        assert!(
            is_revoked("persist-live \"quoted\" \n 2"),
            "any jti round-trips"
        );
        assert!(!is_revoked("persist-expired") && !is_revoked("persist-torn"));
        // Compacted: the expired entry and the torn line are gone from the file.
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(!text.contains("persist-expired") && !text.contains("persist-torn"));
        // And it loads again to the same thing.
        assert_eq!(load(&path).unwrap(), (2, 0));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "the list is readable by the daemon's user only"
            );
        }
        // Unreadable (a directory in its place): an error, not an empty list.
        assert!(load(&dir).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "auth")]
    #[test]
    fn secret_env_is_read_and_preferred_over_literal() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        // Unique var name so parallel tests don't collide.
        let var = format!("ZION_TEST_AUTH_SECRET_{}", std::process::id());
        std::env::set_var(&var, "env-secret-padding-padding-padding-padding");

        let claims = Claims {
            sub: Some("u".to_string()),
            email: None,
            iss: None,
            aud: None,
            exp: Some(u64::MAX),
            nbf: Some(0),
            jti: None,
        };
        // Token signed with the ENV secret; a decoy literal that must be ignored.
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"env-secret-padding-padding-padding-padding"),
        )
        .unwrap();

        let config = AuthProfileConfig {
            issuer: None,
            audience: None,
            secret: Some("decoy-literal-that-must-be-ignored".into()),
            secret_env: Some(var.clone()),
            previous_secret_env: None,
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
            leeway_secs: 30,
            // These tests are about signatures, audiences and revocation, with tokens that
            // expire far out: "no cap", said on purpose (the default cap has its own tests).
            max_token_lifetime_secs: Some(0),
        };
        let profile = resolve_auth_profile(&config).expect("secret_env resolves");
        assert!(
            validate_token(&token, &profile).is_ok(),
            "env secret must win"
        );

        // A named-but-missing env var is a hard error, not a silent fallback.
        std::env::remove_var(&var);
        let missing = AuthProfileConfig {
            issuer: None,
            audience: None,
            secret: None,
            secret_env: Some(var),
            previous_secret_env: None,
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
            leeway_secs: 30,
            // These tests are about signatures, audiences and revocation, with tokens that
            // expire far out: "no cap", said on purpose (the default cap has its own tests).
            max_token_lifetime_secs: Some(0),
        };
        assert!(
            resolve_auth_profile(&missing).is_err(),
            "missing secret_env must fail closed"
        );
    }

    // ── ZION-AUTH-04/05, SEC-05/06 ─────────────────────────────────────────

    #[cfg(feature = "auth")]
    fn hmac_cfg(audience: Option<&str>, leeway: u64, cap: Option<u64>) -> AuthProfileConfig {
        AuthProfileConfig {
            issuer: None,
            audience: audience.map(str::to_string),
            secret: Some("unit-test-secret-padding-padding-padding-padding".into()),
            secret_env: None,
            previous_secret_env: None,
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
            leeway_secs: leeway,
            max_token_lifetime_secs: cap,
        }
    }

    #[cfg(feature = "auth")]
    fn token_with(exp: u64, aud: Option<Audience>) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let claims = Claims {
            sub: Some("u".into()),
            email: None,
            iss: None,
            aud,
            exp: Some(exp),
            nbf: Some(0),
            jti: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"unit-test-secret-padding-padding-padding-padding"),
        )
        .unwrap()
    }

    #[cfg(feature = "auth")]
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[cfg(feature = "auth")]
    #[test]
    fn array_audience_is_accepted_when_it_contains_the_configured_one() {
        // OIDC providers commonly emit `aud` as an array; that used to fail to
        // deserialize and the token was rejected outright.
        // Tokens that expire at u64::MAX: "no cap", said on purpose.
        let p = resolve_auth_profile(&hmac_cfg(Some("api.zion.dev"), 30, Some(0))).unwrap();
        let ok = token_with(
            u64::MAX,
            Some(Audience::Many(vec!["other".into(), "api.zion.dev".into()])),
        );
        assert!(
            validate_token(&ok, &p).is_ok(),
            "array containing our audience"
        );
        // ...and audience scoping still works: an array without it is refused.
        let bad = token_with(u64::MAX, Some(Audience::Many(vec!["other".into()])));
        assert!(
            validate_token(&bad, &p).is_err(),
            "array without our audience"
        );
        // the single-string form is unchanged
        let one = token_with(u64::MAX, Some("api.zion.dev".into()));
        assert!(validate_token(&one, &p).is_ok());
    }

    #[cfg(feature = "auth")]
    #[test]
    fn max_token_lifetime_rejects_tokens_that_outlive_the_policy() {
        let capped = resolve_auth_profile(&hmac_cfg(None, 30, Some(900))).unwrap();
        let short = token_with(now() + 600, None);
        let long = token_with(now() + 86_400, None);
        let forever = token_with(u64::MAX, None);
        assert!(validate_token(&short, &capped).is_ok(), "within the cap");
        for t in [&long, &forever] {
            let e = validate_token(t, &capped).unwrap_err();
            assert!(
                matches!(&e, AuthError::InvalidToken(m) if m.contains("max_token_lifetime_secs")),
                "{e:?}"
            );
        }
        // Nothing configured: the default cap (24 h) applies since 0.10.0 (#553).
        let default = resolve_auth_profile(&hmac_cfg(None, 30, None)).unwrap();
        assert!(validate_token(&short, &default).is_ok());
        assert!(
            validate_token(&forever, &default).is_err(),
            "refused by default"
        );
        // 0 = no cap, said on purpose.
        let open = resolve_auth_profile(&hmac_cfg(None, 30, Some(0))).unwrap();
        assert!(validate_token(&forever, &open).is_ok());
    }

    #[cfg(feature = "auth")]
    #[test]
    fn leeway_is_configurable_and_bounded() {
        let just_expired = token_with(now() - 10, None);
        let strict = resolve_auth_profile(&hmac_cfg(None, 0, None)).unwrap();
        assert!(matches!(
            validate_token(&just_expired, &strict),
            Err(AuthError::Expired)
        ));
        let lenient = resolve_auth_profile(&hmac_cfg(None, 30, None)).unwrap();
        assert!(validate_token(&just_expired, &lenient).is_ok());
        assert!(
            resolve_auth_profile(&hmac_cfg(None, 301, None)).is_err(),
            "an oversized leeway must be refused, not silently extend token lifetimes"
        );
    }

    #[test]
    fn literal_secret_is_redacted_from_debug_and_parses_from_toml() {
        let cfg: AuthProfileConfig =
            toml::from_str("secret = \"super-secret-signing-key\"\naudience = \"a\"").unwrap();
        assert_eq!(
            cfg.secret.as_ref().unwrap().expose(),
            "super-secret-signing-key"
        );
        assert_eq!(cfg.leeway_secs, 30, "default leeway");
        assert_eq!(cfg.max_token_lifetime_secs, None);
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("super-secret-signing-key"),
            "secret leaked into Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
        // the bare wrapper too
        assert_eq!(format!("{:?}", Secret::from("x")), "Secret(<redacted>)");
    }
}
