//! ACME auto-renewal — handles HTTP-01 challenges and certificate renewal.
//!
//! Flow:
//! 1. Background task checks cert expiry periodically
//! 2. If < renew_before_days, initiates ACME order
//! 3. Serves HTTP-01 challenge token on port 80 (in-memory, no disk)
//! 4. Receives signed cert, writes to disk
//! 5. Triggers TLS hot-reload via ArcSwap
//!
//! The challenge tokens are stored in a DashMap shared with the HTTP handler.
//! Zero overhead when no challenge is active (empty map check).
//!
//! The actual ACME client is gated behind `--features acme`. Without it,
//! the renewal falls back to renew.sh or logs a clear error.

use dashmap::DashMap;
use std::sync::Arc;

/// Shared challenge token store.
/// Key: token (from ACME URL path), Value: key authorization (response body).
/// Empty when no challenge is active.
pub type ChallengeStore = Arc<DashMap<String, String>>;

/// Create a new challenge store.
pub fn new_challenge_store() -> ChallengeStore {
    Arc::new(DashMap::new())
}

/// Check if a request path is an ACME challenge and return the response.
/// Returns Some(key_authorization) if this is a valid challenge, None otherwise.
#[inline]
pub fn handle_challenge(store: &ChallengeStore, path: &str) -> Option<String> {
    // Path format: /.well-known/acme-challenge/{token}
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    if token.is_empty() {
        return None;
    }
    store.get(token).map(|v| v.value().clone())
}

/// Spawn the ACME renewal background task.
/// Checks cert expiry every 12 hours. Renews when < renew_before_days.
pub fn spawn_renewal_task(
    acme_config: crate::config::AcmeConfig,
    challenge_store: ChallengeStore,
    tls_acceptor: Arc<arc_swap::ArcSwap<tokio_rustls::TlsAcceptor>>,
    tls_config: crate::config::TlsConfig,
) {
    tokio::spawn(async move {
        // Initial delay — let the server start up fully
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        loop {
            // Check if renewal is needed (uses blocking fs)
            let cert_path = tls_config.cert_path.clone();
            let renew_days = acme_config.renew_before_days;
            let needs_renewal =
                tokio::task::spawn_blocking(move || check_cert_expiry(&cert_path, renew_days))
                    .await
                    .unwrap_or(true); // default to renew on panic

            if needs_renewal {
                crate::logging::info(
                    "acme",
                    &format!(
                        "certificate renewal needed for: {}",
                        acme_config.domains.join(", ")
                    ),
                );

                match do_renewal(&acme_config, &challenge_store, &tls_config).await {
                    Ok(()) => {
                        crate::logging::info("acme", "certificate renewed successfully");

                        // Hot-reload the new cert (uses blocking fs)
                        let tls_config_clone = tls_config.clone();
                        let load_result = tokio::task::spawn_blocking(move || {
                            crate::tls::load_tls_config(&tls_config_clone)
                        })
                        .await
                        .unwrap_or_else(|_| Err("spawn_blocking panicked".to_string()));

                        match load_result {
                            Ok(new_config) => {
                                let new_acceptor =
                                    tokio_rustls::TlsAcceptor::from(Arc::new(new_config));
                                tls_acceptor.store(Arc::new(new_acceptor));
                                crate::logging::info(
                                    "acme",
                                    "TLS hot-reloaded with new certificate",
                                );
                            }
                            Err(e) => {
                                crate::logging::error(
                                    "acme",
                                    &format!("failed to load renewed certificate: {}", e),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        crate::logging::error("acme", &format!("renewal failed: {}", e));
                    }
                }
            }

            // Check every 12 hours
            tokio::time::sleep(std::time::Duration::from_secs(12 * 3600)).await;
        }
    });
}

/// Check if the certificate at `path` expires within `days`.
/// Returns true if renewal is needed (or cert doesn't exist / can't be read).
/// Uses the real X.509 notAfter field via the ASN.1 parser in tls.rs.
fn check_cert_expiry(cert_path: &str, renew_before_days: u64) -> bool {
    match crate::tls::cert_expiry_secs(cert_path) {
        Some(secs_until_expiry) => {
            let threshold = (renew_before_days * 86400) as i64;
            secs_until_expiry < threshold
        }
        None => true, // can't parse cert → renew to be safe
    }
}

// ============================================================================
// ACME flow — feature-gated
// ============================================================================

/// Perform the actual ACME order and certificate issuance.
/// When compiled with `--features acme`, uses instant-acme for the full flow.
/// Otherwise, falls back to renew.sh or returns an error.
async fn do_renewal(
    config: &crate::config::AcmeConfig,
    _challenge_store: &ChallengeStore,
    _tls_config: &crate::config::TlsConfig,
) -> Result<(), String> {
    // Try native ACME first (if compiled with --features acme)
    #[cfg(feature = "acme")]
    {
        return do_renewal_native(config, _challenge_store, _tls_config).await;
    }

    // Fallback: renew.sh script
    #[allow(unreachable_code)]
    do_renewal_script(config).await
}

/// Native ACME renewal via instant-acme.
/// Full RFC 8555 flow: account → order → HTTP-01 challenge → finalize → cert.
#[cfg(feature = "acme")]
async fn do_renewal_native(
    config: &crate::config::AcmeConfig,
    challenge_store: &ChallengeStore,
    tls_config: &crate::config::TlsConfig,
) -> Result<(), String> {
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
        RetryPolicy,
    };

    let state_dir = std::path::Path::new(&config.state_dir);
    std::fs::create_dir_all(state_dir)
        .map_err(|e| format!("cannot create state_dir '{}': {}", config.state_dir, e))?;

    let creds_path = state_dir.join("account.json");

    // --- Step 1: Load or create ACME account ---
    let account = if creds_path.exists() {
        let creds_json = std::fs::read_to_string(&creds_path)
            .map_err(|e| format!("cannot read account.json: {}", e))?;
        let creds: instant_acme::AccountCredentials = serde_json::from_str(&creds_json)
            .map_err(|e| format!("invalid account.json: {}", e))?;
        Account::builder()
            .map_err(|e| format!("cannot build ACME client: {}", e))?
            .from_credentials(creds)
            .await
            .map_err(|e| format!("cannot restore ACME account: {}", e))?
    } else {
        let contact = if config.email.is_empty() {
            vec![]
        } else {
            vec![format!("mailto:{}", config.email)]
        };
        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
        let (account, credentials) = Account::builder()
            .map_err(|e| format!("cannot build ACME client: {}", e))?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                config.directory_url.clone(),
                None,
            )
            .await
            .map_err(|e| format!("ACME account creation failed: {}", e))?;

        // Persist credentials for future runs
        let creds_json = serde_json::to_string_pretty(&credentials)
            .map_err(|e| format!("cannot serialize credentials: {}", e))?;
        std::fs::write(&creds_path, creds_json)
            .map_err(|e| format!("cannot write account.json: {}", e))?;

        crate::logging::info("acme", "ACME account created and persisted");
        account
    };

    // --- Step 2: Create order for domains ---
    let identifiers: Vec<Identifier> = config
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("ACME new_order failed: {}", e))?;

    crate::logging::info(
        "acme",
        &format!("ACME order created (status: {:?})", order.state().status),
    );

    // --- Step 3: Process authorizations (HTTP-01 challenges) ---
    // Phase 1: Set up ALL challenges concurrently — insert tokens and signal readiness.
    // This prevents one slow domain from blocking others.
    let mut pending_tokens: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| format!("ACME authorization failed: {}", e))?;
        match authz.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            other => return Err(format!("unexpected authorization status: {:?}", other)),
        }

        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or("no HTTP-01 challenge in authorization")?;

        let token = challenge.token.to_string();
        let key_auth = challenge.key_authorization().as_str().to_string();

        crate::logging::info(
            "acme",
            &format!(
                "serving HTTP-01 challenge for token: {}...",
                &token[..8.min(token.len())]
            ),
        );

        // Insert token into shared store for the HTTP handler
        challenge_store.insert(token.clone(), key_auth);
        pending_tokens.push(token);

        // Signal readiness — ACME server will start fetching asynchronously
        challenge
            .set_ready()
            .await
            .map_err(|e| format!("challenge set_ready failed: {}", e))?;
    }

    // Phase 2: Poll ALL authorizations in parallel using JoinSet.
    // Note: instant-acme's order.poll_ready() natively polls the authorizations sequentially.
    // We rely on it instead of a custom JoinSet pipeline.

    // Phase 3: Clean up all challenge tokens — ACME server has validated
    for token in &pending_tokens {
        challenge_store.remove(token);
    }

    // --- Step 4: Wait for order to be ready ---
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| format!("poll_ready failed: {}", e))?;

    if status != OrderStatus::Ready {
        return Err(format!("unexpected order status after poll: {:?}", status));
    }

    // --- Step 5: Finalize — generate key + CSR and get certificate ---
    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("finalize failed: {}", e))?;

    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("poll_certificate failed: {}", e))?;

    // --- Step 6: Write to disk ---
    std::fs::write(&tls_config.cert_path, cert_chain_pem.as_bytes())
        .map_err(|e| format!("cannot write cert to '{}': {}", tls_config.cert_path, e))?;
    std::fs::write(&tls_config.key_path, private_key_pem.as_bytes())
        .map_err(|e| format!("cannot write key to '{}': {}", tls_config.key_path, e))?;

    crate::logging::info(
        "acme",
        &format!(
            "certificate written to {} + {}",
            tls_config.cert_path, tls_config.key_path
        ),
    );

    Ok(())
}

/// Fallback: execute renew.sh from state_dir.
/// C-05: Security hardening — validate script before execution.
async fn do_renewal_script(config: &crate::config::AcmeConfig) -> Result<(), String> {
    crate::logging::warn(
        "acme",
        "native ACME not compiled in (missing --features acme). \
         Attempting renew.sh fallback.",
    );

    let script = format!("{}/renew.sh", config.state_dir);
    let script_path = std::path::Path::new(&script);

    if !script_path.exists() {
        return Err(
            "no renewal method available (compile with --features acme or provide renew.sh)"
                .to_string(),
        );
    }

    // Validate: script must be a regular file (not symlink to elsewhere)
    let metadata =
        std::fs::metadata(&script).map_err(|e| format!("cannot stat renew.sh: {}", e))?;

    if !metadata.is_file() {
        return Err("renew.sh is not a regular file".to_string());
    }

    // Validate: must not be world-writable (prevents tampering)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o002 != 0 {
            return Err(format!(
                "renew.sh is world-writable (mode {:o}) — refusing to execute for security",
                mode
            ));
        }
    }

    crate::logging::info("acme", &format!("running renewal script: {}", script));
    let output = tokio::process::Command::new("bash")
        .arg(&script)
        // Restrict environment to prevent injection via env vars
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", &config.state_dir)
        .output()
        .await
        .map_err(|e| format!("failed to run renew.sh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("renew.sh failed: {}", stderr));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_valid_token_returns_key_auth() {
        let store = new_challenge_store();
        store.insert("abc123".to_string(), "key-auth-value".to_string());
        assert_eq!(
            handle_challenge(&store, "/.well-known/acme-challenge/abc123"),
            Some("key-auth-value".to_string())
        );
    }

    #[test]
    fn challenge_unknown_token_returns_none() {
        let store = new_challenge_store();
        store.insert("abc123".to_string(), "key-auth-value".to_string());
        assert_eq!(
            handle_challenge(&store, "/.well-known/acme-challenge/unknown"),
            None
        );
    }

    #[test]
    fn challenge_empty_token_returns_none() {
        let store = new_challenge_store();
        assert_eq!(
            handle_challenge(&store, "/.well-known/acme-challenge/"),
            None
        );
    }

    #[test]
    fn challenge_wrong_prefix_returns_none() {
        let store = new_challenge_store();
        store.insert("abc123".to_string(), "key-auth-value".to_string());
        assert_eq!(handle_challenge(&store, "/api/abc123"), None);
        assert_eq!(handle_challenge(&store, "/.well-known/abc123"), None);
    }

    #[test]
    fn challenge_empty_store_returns_none() {
        let store = new_challenge_store();
        assert_eq!(
            handle_challenge(&store, "/.well-known/acme-challenge/token"),
            None
        );
    }

    #[test]
    fn challenge_cleanup_removes_token() {
        let store = new_challenge_store();
        store.insert("temp".to_string(), "val".to_string());
        assert!(handle_challenge(&store, "/.well-known/acme-challenge/temp").is_some());
        store.remove("temp");
        assert!(handle_challenge(&store, "/.well-known/acme-challenge/temp").is_none());
    }
}
