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
    /// Audience (can be string or array — we accept string here)
    pub aud: Option<String>,
    /// Expiration (Unix timestamp)
    pub exp: Option<u64>,
    /// Not before (Unix timestamp)
    pub nbf: Option<u64>,
}

/// Auth profile configuration (from TOML).
///
/// `AuthProfileConfig` is always deserialized (config.rs references it
/// outside any feature gate so users get clear "unknown auth_profile"
/// validation errors at startup regardless of build flavour). The fields
/// are only consumed by code under `#[cfg(feature = "auth")]`.
#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct AuthProfileConfig {
    /// Expected issuer (validated against token's `iss` claim).
    #[serde(default)]
    pub issuer: Option<String>,
    /// Expected audience (validated against token's `aud` claim).
    #[serde(default)]
    pub audience: Option<String>,
    /// HMAC secret for symmetric validation (base64 or raw string).
    #[serde(default)]
    pub secret: Option<String>,
    /// JWKS URL for asymmetric validation (fetched at startup).
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Algorithm hint: "HS256" (default for secret), "RS256" (default for JWKS).
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Forward decoded claims as X-Auth-Subject, X-Auth-Email headers.
    #[serde(default = "default_true")]
    pub forward_claims: bool,
}

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
    pub jwk_set: Arc<arc_swap::ArcSwapOption<jsonwebtoken::jwk::JwkSet>>,
    pub validation: Arc<Validation>,
    pub forward_claims: bool,
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

    let token_data: TokenData<Claims> = decode(token, decoding_key_ref, &profile.validation)
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("ExpiredSignature") {
                AuthError::Expired
            } else {
                AuthError::InvalidToken(msg)
            }
        })?;

    Ok(token_data.claims)
}

/// Build a resolved auth profile from config.
/// Called once at startup — pre-computes DecodingKey and Validation.
///
/// Returns `Err` if the algorithm is unrecognised or if the profile
/// configures neither `secret` (HMAC) nor `jwks_url` (OIDC). The error
/// is a String so the caller (`config::build_router`) can wrap it with
/// the route/profile name in its own error format.
#[cfg(feature = "auth")]
pub fn resolve_auth_profile(config: &AuthProfileConfig) -> Result<ResolvedAuthProfile, String> {
    let mut alg_str = config.algorithm.clone();
    if alg_str == "HS256" && config.jwks_url.is_some() && config.secret.is_none() {
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

    let mut decoding_key = None;
    let jwk_set_arc = Arc::new(arc_swap::ArcSwapOption::empty());

    if let Some(ref secret) = config.secret {
        decoding_key = Some(Arc::new(DecodingKey::from_secret(secret.as_bytes())));
    } else if let Some(ref jwks_url) = config.jwks_url {
        let url = jwks_url.clone();
        let key_store = jwk_set_arc.clone();

        // Spawn background task to periodically fetch JWKS.
        // Uses exponential backoff on failure (5s → 10s → ... → 3600s).
        tokio::spawn(async move {
            let client = loop {
                match reqwest::Client::builder().build() {
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

    // Allow 30s clock skew for distributed systems
    validation.leeway = 30;

    Ok(ResolvedAuthProfile {
        jwks_url: config.jwks_url.clone(),
        decoding_key,
        jwk_set: jwk_set_arc,
        validation: Arc::new(validation),
        forward_claims: config.forward_claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(feature = "auth")]
    #[test]
    fn validate_hmac_token_roundtrip() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test-secret-key-for-zion";
        let claims = Claims {
            sub: Some("user-123".to_string()),
            email: Some("test@zion.dev".to_string()),
            iss: Some("zion-test".to_string()),
            aud: Some("api.zion.dev".to_string()),
            exp: Some(u64::MAX), // far future
            nbf: Some(0),
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
            secret: Some(secret.to_string()),
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
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
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret-a"),
        )
        .unwrap();

        let config = AuthProfileConfig {
            issuer: None,
            audience: None,
            secret: Some("secret-b".to_string()), // wrong secret
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
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
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let config = AuthProfileConfig {
            issuer: None,
            audience: None,
            secret: Some("secret".to_string()),
            jwks_url: None,
            algorithm: "HS256".to_string(),
            forward_claims: true,
        };

        let profile = resolve_auth_profile(&config).expect("valid test profile");
        let result = validate_token(&token, &profile);
        assert!(matches!(result, Err(AuthError::Expired)));
    }
}
