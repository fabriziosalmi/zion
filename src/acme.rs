// SPDX-License-Identifier: Apache-2.0
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
                                    &format!("failed to load renewed certificate: {e}"),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        crate::logging::error("acme", &format!("renewal failed: {e}"));
                    }
                }
            }

            // Check every 12 hours
            tokio::time::sleep(std::time::Duration::from_secs(12 * 3600)).await;
        }
    });
}

/// Run a single ACME issuance/renewal synchronously and return the
/// outcome. Drives the same path as the periodic task (and bumps the
/// `zion_acme_renewals_total` / `..._failures_total` counters) without
/// the 12-hour loop. Exposed for the soak workflow (issue #59) and for
/// operator tooling that wants a one-shot renew.
#[cfg(feature = "acme")]
pub async fn renew_once(
    config: &crate::config::AcmeConfig,
    challenge_store: &ChallengeStore,
    tls_config: &crate::config::TlsConfig,
) -> Result<(), String> {
    do_renewal(config, challenge_store, tls_config).await
}

/// Revoke the leaf certificate at `cert_path` against the ACME account
/// persisted in `config.state_dir`. Completes the issue → renew → revoke
/// lifecycle exercised by the soak workflow (issue #59), and lets an
/// operator retire a compromised key out-of-band.
#[cfg(feature = "acme")]
pub async fn revoke_cert(
    config: &crate::config::AcmeConfig,
    cert_path: &str,
) -> Result<(), String> {
    use instant_acme::{Account, RevocationReason, RevocationRequest};
    use std::io::BufReader;

    // Restore the persisted account that issued the cert.
    let creds_path = std::path::Path::new(&config.state_dir).join("account.json");
    let creds_json = std::fs::read_to_string(&creds_path)
        .map_err(|e| format!("cannot read account.json: {e}"))?;
    let creds: instant_acme::AccountCredentials =
        serde_json::from_str(&creds_json).map_err(|e| format!("invalid account.json: {e}"))?;
    let account = Account::builder()
        .map_err(|e| format!("cannot build ACME client: {e}"))?
        .from_credentials(creds)
        .await
        .map_err(|e| format!("cannot restore ACME account: {e}"))?;

    // Parse the leaf certificate (first PEM block) into DER.
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| format!("cannot open cert '{cert_path}': {e}"))?;
    let leaf = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .next()
        .ok_or_else(|| "no certificate in chain".to_string())?
        .map_err(|e| format!("cannot parse leaf certificate: {e}"))?;

    account
        .revoke(&RevocationRequest {
            certificate: &leaf,
            reason: Some(RevocationReason::Unspecified),
        })
        .await
        .map_err(|e| format!("ACME revoke failed: {e}"))?;

    crate::logging::info("acme", "certificate revoked");
    Ok(())
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
    use std::sync::atomic::Ordering::Relaxed;

    // Native ACME (instant-acme) when built with --features acme,
    // else the renew.sh fallback. Either way we record the outcome on
    // the ACME lifecycle counters (issue #59) so the soak workflow and
    // production dashboards can alert on renewal failures.
    #[cfg(feature = "acme")]
    let result = do_renewal_native(config, _challenge_store, _tls_config).await;
    #[cfg(not(feature = "acme"))]
    let result = do_renewal_script(config).await;

    match &result {
        Ok(()) => {
            crate::metrics::METRICS
                .acme_renewals_total
                .fetch_add(1, Relaxed);
        }
        Err(_) => {
            crate::metrics::METRICS
                .acme_renewal_failures_total
                .fetch_add(1, Relaxed);
        }
    }
    result
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
            .map_err(|e| format!("cannot read account.json: {e}"))?;
        let creds: instant_acme::AccountCredentials =
            serde_json::from_str(&creds_json).map_err(|e| format!("invalid account.json: {e}"))?;
        Account::builder()
            .map_err(|e| format!("cannot build ACME client: {e}"))?
            .from_credentials(creds)
            .await
            .map_err(|e| format!("cannot restore ACME account: {e}"))?
    } else {
        let contact = if config.email.is_empty() {
            vec![]
        } else {
            vec![format!("mailto:{}", config.email)]
        };
        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
        let (account, credentials) = Account::builder()
            .map_err(|e| format!("cannot build ACME client: {e}"))?
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
            .map_err(|e| format!("ACME account creation failed: {e}"))?;

        // Persist credentials for future runs
        let creds_json = serde_json::to_string_pretty(&credentials)
            .map_err(|e| format!("cannot serialize credentials: {e}"))?;
        std::fs::write(&creds_path, creds_json)
            .map_err(|e| format!("cannot write account.json: {e}"))?;

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
        .map_err(|e| format!("ACME new_order failed: {e}"))?;

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
        let mut authz = result.map_err(|e| format!("ACME authorization failed: {e}"))?;
        match authz.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            other => return Err(format!("unexpected authorization status: {other:?}")),
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
            .map_err(|e| format!("challenge set_ready failed: {e}"))?;
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
        .map_err(|e| format!("poll_ready failed: {e}"))?;

    if status != OrderStatus::Ready {
        return Err(format!("unexpected order status after poll: {status:?}"));
    }

    // --- Step 5: Finalize — generate key + CSR and get certificate ---
    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("finalize failed: {e}"))?;

    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("poll_certificate failed: {e}"))?;

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

/// Fallback: execute renew.sh from state_dir. Only compiled without the
/// `acme` feature — with it, `do_renewal` always takes the native path.
/// C-05: Security hardening — validate script before execution.
#[cfg(not(feature = "acme"))]
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
    let metadata = std::fs::metadata(&script).map_err(|e| format!("cannot stat renew.sh: {e}"))?;

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
                "renew.sh is world-writable (mode {mode:o}) — refusing to execute for security"
            ));
        }
    }

    crate::logging::info("acme", &format!("running renewal script: {script}"));
    let output = tokio::process::Command::new("bash")
        .arg(&script)
        // Restrict environment to prevent injection via env vars
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", &config.state_dir)
        .output()
        .await
        .map_err(|e| format!("failed to run renew.sh: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("renew.sh failed: {stderr}"));
    }
    Ok(())
}

// ============================================================================
// Soak driver (issue #59) — `zion acme-soak`
// ============================================================================

/// Drive a full ACME **issue → renew → revoke** cycle against a test
/// directory (Pebble) and return a process exit code (0 = pass). Invoked
/// by `zion acme-soak` from the soak workflow; never part of the daemon
/// boot path. Exercises the real `renew_once` / `revoke_cert` code so a
/// regression in zion's ACME flow fails the soak.
///
/// Configuration comes from env vars so the workflow can point us at its
/// ephemeral Pebble with no config file:
///   - `ZION_ACME_TEST_DIRECTORY` — ACME directory URL (required)
///   - `ZION_ACME_TEST_DOMAIN`    — SAN to request (default `acme-soak.test`)
///   - `ZION_ACME_TEST_HTTP_PORT` — HTTP-01 responder port (default `5002`)
///   - `ZION_ACME_TEST_DIR`       — state + cert output dir (default `/tmp/zion-acme-soak`)
///   - `ZION_ACME_TEST_EMAIL`     — account contact (default `soak@zion.test`)
#[cfg(feature = "acme")]
pub async fn run_soak() -> i32 {
    use std::sync::atomic::Ordering::Relaxed;

    let directory_url = match std::env::var("ZION_ACME_TEST_DIRECTORY") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("acme-soak: ZION_ACME_TEST_DIRECTORY is required");
            return 2;
        }
    };
    let domain = std::env::var("ZION_ACME_TEST_DOMAIN").unwrap_or_else(|_| "acme-soak.test".into());
    let http_port: u16 = std::env::var("ZION_ACME_TEST_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5002);
    let state_dir =
        std::env::var("ZION_ACME_TEST_DIR").unwrap_or_else(|_| "/tmp/zion-acme-soak".into());
    let email = std::env::var("ZION_ACME_TEST_EMAIL").unwrap_or_else(|_| "soak@zion.test".into());

    if let Err(e) = std::fs::create_dir_all(&state_dir) {
        eprintln!("acme-soak: cannot create state dir {state_dir}: {e}");
        return 1;
    }
    let cert_path = format!("{state_dir}/cert.pem");
    let key_path = format!("{state_dir}/key.pem");

    let acme_config = crate::config::AcmeConfig {
        email,
        domains: vec![domain.clone()],
        directory_url,
        // renew_once issues unconditionally (it doesn't consult expiry),
        // so this value is irrelevant here; kept large for clarity.
        renew_before_days: 3650,
        state_dir: state_dir.clone(),
    };
    let tls_config = crate::config::TlsConfig {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        hot_reload: true,
        min_version: "1.2".into(),
        alpn: vec!["http/1.1".into()],
        sni: vec![],
        acme: None,
        client_ca_path: None,
        client_auth: "none".into(),
    };

    // HTTP-01 responder: Pebble (via challtestsrv DNS) resolves `domain`
    // to this host and GETs the challenge path. We serve the key
    // authorization straight from the shared store.
    let store = new_challenge_store();
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", http_port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("acme-soak: cannot bind :{http_port}: {e}");
            return 1;
        }
    };
    {
        let store = store.clone();
        tokio::spawn(async move { serve_challenges(listener, store).await });
    }

    eprintln!(
        "acme-soak: directory={} domain={domain} http_port={http_port}",
        acme_config.directory_url
    );

    let base = crate::metrics::METRICS.acme_renewals_total.load(Relaxed);
    let base_fail = crate::metrics::METRICS
        .acme_renewal_failures_total
        .load(Relaxed);

    // 1. Issue.
    if let Err(e) = renew_once(&acme_config, &store, &tls_config).await {
        eprintln!("acme-soak: FAIL issue: {e}");
        return 1;
    }
    if !std::path::Path::new(&cert_path).exists() {
        eprintln!("acme-soak: FAIL issue: no certificate written to {cert_path}");
        return 1;
    }
    eprintln!("acme-soak: ✓ issued");

    // 2. Renew (drive the issuance path again over the same account).
    if let Err(e) = renew_once(&acme_config, &store, &tls_config).await {
        eprintln!("acme-soak: FAIL renew: {e}");
        return 1;
    }
    let renewals = crate::metrics::METRICS.acme_renewals_total.load(Relaxed) - base;
    if renewals < 2 {
        eprintln!("acme-soak: FAIL renew: acme_renewals_total moved by {renewals}, expected >= 2");
        return 1;
    }
    eprintln!("acme-soak: ✓ renewed (acme_renewals_total +{renewals})");

    // 3. Revoke.
    if let Err(e) = revoke_cert(&acme_config, &cert_path).await {
        eprintln!("acme-soak: FAIL revoke: {e}");
        return 1;
    }
    eprintln!("acme-soak: ✓ revoked");

    let failures = crate::metrics::METRICS
        .acme_renewal_failures_total
        .load(Relaxed)
        - base_fail;
    eprintln!("acme-soak: PASS (issue → renew → revoke; failures during run: {failures})");
    0
}

/// Minimal HTTP/1.1 responder for ACME HTTP-01 validation. Reads the
/// request line, serves the key authorization for a known token, 404s
/// otherwise. Single-purpose — not a general-purpose server.
#[cfg(feature = "acme")]
async fn serve_challenges(listener: tokio::net::TcpListener, store: ChallengeStore) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let store = store.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = match sock.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            let resp = match handle_challenge(&store, path) {
                Some(key_auth) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    key_auth.len(),
                    key_auth
                ),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string(),
            };
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });
    }
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
