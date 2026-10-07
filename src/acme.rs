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

/// Delay before the next renewal check: 12 hours normally; after `failures` consecutive
/// failed attempts, 5 minutes doubling each time (5, 10, 20, 40 … min), capped at 12 hours.
/// Short enough to save a short-lived certificate, slow enough for the CA's rate limits.
pub fn next_check_delay(failures: u32) -> std::time::Duration {
    const STEADY: u64 = 12 * 3600;
    let secs = match failures {
        0 => STEADY,
        n => (300u64 << (n - 1).min(16)).min(STEADY),
    };
    std::time::Duration::from_secs(secs)
}

/// Spawn the ACME renewal background task.
/// Checks cert expiry every 12 hours (sooner after a failure, see [`next_check_delay`]).
/// Renews when < renew_before_days.
pub fn spawn_renewal_task(
    acme_config: crate::config::AcmeConfig,
    challenge_store: ChallengeStore,
    tls_acceptor: Arc<arc_swap::ArcSwap<tokio_rustls::TlsAcceptor>>,
    tls_config: crate::config::TlsConfig,
) {
    tokio::spawn(async move {
        // Initial delay — let the server start up fully
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let mut consecutive_failures: u32 = 0;
        loop {
            // Liveness heartbeat: advance on every wake-up, *before* the
            // work, so a dead loop is distinguishable from the normal
            // months-long idle steady state (a stopped loop freezes both
            // signals). The renewal counters below only move on an actual
            // attempt, which is silent when the cert is simply still fresh.
            use std::sync::atomic::Ordering::Relaxed;
            crate::metrics::METRICS
                .acme_loop_checks_total
                .fetch_add(1, Relaxed);
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            crate::metrics::METRICS
                .acme_loop_last_check_timestamp_seconds
                .store(now_secs, Relaxed);

            // Did this round leave the certificate unrenewed although it was due?
            let mut failed = false;

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
                                failed = true;
                                crate::logging::error(
                                    "acme",
                                    &format!("failed to load renewed certificate: {e}"),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        failed = true;
                        crate::logging::error("acme", &format!("renewal failed: {e}"));
                    }
                }
            }

            // Every 12 hours when all is well; after a failure retry soon, backing off, so a
            // short-lived certificate (zion init's 1-day bootstrap one) gets more than one
            // more attempt before it expires.
            consecutive_failures = if failed { consecutive_failures + 1 } else { 0 };
            let delay = next_check_delay(consecutive_failures);
            if failed {
                crate::logging::warn(
                    "acme",
                    &format!("retrying the renewal in {} min", delay.as_secs() / 60),
                );
            }
            tokio::time::sleep(delay).await;
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
    use instant_acme::{RevocationReason, RevocationRequest};
    use std::io::BufReader;

    // Restore the persisted account that issued the cert.
    let creds_path = std::path::Path::new(&config.state_dir).join("account.json");
    let creds_json = std::fs::read_to_string(&creds_path)
        .map_err(|e| format!("cannot read account.json: {e}"))?;
    let creds: instant_acme::AccountCredentials =
        serde_json::from_str(&creds_json).map_err(|e| format!("invalid account.json: {e}"))?;
    let account = account_builder()?
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

/// How long one renewal attempt may take, whichever way it is done. A hung CA or a hung
/// script must not hold the renewal loop for good: the attempt fails, is counted, and is
/// retried on the usual backoff.
const RENEWAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// `fut`, or an error once `limit` has passed (and `fut` is dropped, which cancels it).
#[cfg(feature = "acme")]
async fn with_deadline<T>(
    limit: std::time::Duration,
    what: &str,
    fut: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err(format!(
            "{what} did not finish within {} s and was abandoned",
            limit.as_secs()
        )),
    }
}

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
    let result = with_deadline(
        RENEWAL_DEADLINE,
        "the ACME renewal",
        do_renewal_native(config, _challenge_store, _tls_config),
    )
    .await;
    // The script has its own deadline, because it must be killed, not only abandoned.
    #[cfg(not(feature = "acme"))]
    let result = do_renewal_script(config, RENEWAL_DEADLINE).await;

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

/// Build an instant-acme account client. When `ZION_ACME_ROOT_PEM` is
/// set (the soak workflow, issue #59), trust that PEM as the only root
/// so the client can talk to a test CA (Pebble) whose directory TLS is
/// signed by a private root. Unset (production) → the default Mozilla
/// root store, so real Let's Encrypt works unchanged.
#[cfg(feature = "acme")]
fn account_builder() -> Result<instant_acme::AccountBuilder, String> {
    match std::env::var("ZION_ACME_ROOT_PEM") {
        Ok(p) if !p.is_empty() => instant_acme::Account::builder_with_root(&p)
            .map_err(|e| format!("cannot build ACME client with custom root '{p}': {e}")),
        _ => instant_acme::Account::builder().map_err(|e| format!("cannot build ACME client: {e}")),
    }
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
        AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
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
        account_builder()?
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
        let (account, credentials) = account_builder()?
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
        // Atomic + 0600: the ACME account key authorizes issuing/revoking certs
        // for the domain, so it must never be world-readable at rest, and a torn
        // write must not persist a truncated account.json.
        crate::atomic_file::write_atomic_0600(creds_path.as_ref(), creds_json.as_bytes())
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

    // --- Step 4: Wait for order to be ready ---
    // The ACME server fetches the HTTP-01 token *during* this poll, so the
    // tokens MUST stay in the store until it returns. (Cleaning them up
    // before poll_ready — as this did previously — races the validator and
    // yields a 404 / `unauthorized`; surfaced by the #59 Pebble soak.)
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| format!("poll_ready failed: {e}"))?;

    // Validation is done — now it's safe to drop the challenge tokens.
    for token in &pending_tokens {
        challenge_store.remove(token);
    }

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

    // --- Step 6: Write to disk (atomic pair, key before cert, 0600) ---
    // Cert and key are one logical unit: two separate truncate-in-place writes
    // could be interrupted, leaving a new cert beside the old key (or a truncated
    // PEM) that loads but fails every TLS handshake. Stage both, fsync, then
    // rename key-first so a partial state never shows a cert without its key.
    crate::atomic_file::write_cert_key_atomic(
        std::path::Path::new(&tls_config.key_path),
        private_key_pem.as_bytes(),
        std::path::Path::new(&tls_config.cert_path),
        cert_chain_pem.as_bytes(),
    )
    .map_err(|e| {
        format!(
            "cannot write cert/key pair to '{}' + '{}': {e}",
            tls_config.cert_path, tls_config.key_path
        )
    })?;

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
async fn do_renewal_script(
    config: &crate::config::AcmeConfig,
    limit: std::time::Duration,
) -> Result<(), String> {
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
    run_renew_script(&script, &config.state_dir, limit).await
}

/// Run `bash <script>` with a restricted environment, for at most `limit`. Past it the script
/// and everything it started are killed: a renewal script is usually a wrapper
/// (`certbot renew`), and killing only the shell would leave the real work running.
#[cfg(not(feature = "acme"))]
async fn run_renew_script(
    script: &str,
    state_dir: &str,
    limit: std::time::Duration,
) -> Result<(), String> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    let mut cmd = tokio::process::Command::new("bash");
    cmd.arg(script)
        // Restrict environment to prevent injection via env vars
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", state_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Its own process group, so that the whole group can be killed.
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to run renew.sh: {e}"))?;
    let pid = child.id();
    // What the script says on stderr, up to 64 KiB (it only matters when it fails).
    let mut stderr = child.stderr.take();
    let reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(s) = stderr.as_mut() {
            let _ = s.take(64 * 1024).read_to_end(&mut buf).await;
        }
        buf
    });
    match tokio::time::timeout(limit, child.wait()).await {
        Ok(Ok(status)) => {
            let stderr = reader.await.unwrap_or_default();
            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "renew.sh failed: {}",
                    String::from_utf8_lossy(&stderr)
                ))
            }
        }
        Ok(Err(e)) => Err(format!("failed to run renew.sh: {e}")),
        Err(_) => {
            kill_process_group(pid);
            let _ = child.kill().await; // the shell itself, where there is no process group to kill
            reader.abort();
            Err(format!(
                "renew.sh did not finish within {} s and was killed",
                limit.as_secs()
            ))
        }
    }
}

/// SIGKILL the process group led by `pid` (the group `run_renew_script` made).
#[cfg(all(not(feature = "acme"), any(target_os = "linux", target_os = "macos")))]
fn kill_process_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()) {
        // SAFETY: `kill` only sends a signal. `pid` is a child of this process that has not
        // been reaped (its `wait` future was dropped, not completed), so its group id cannot
        // belong to anyone else yet.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}
#[cfg(all(
    not(feature = "acme"),
    not(any(target_os = "linux", target_os = "macos"))
))]
fn kill_process_group(_pid: Option<u32>) {}

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
    // instant-acme drives rustls 0.23, which needs a process-level
    // CryptoProvider. The daemon installs this at boot (main.rs); the
    // acme-soak subcommand bypasses that path, so install it here.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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
        client_crl_path: None,
        client_auth: "none".into(),
        fingerprint: None,
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

    // Fault-injection legs (issue #134). `happy` is the issue→renew→revoke
    // baseline (#59); the adversarial legs share the setup above and branch here.
    let mode = std::env::var("ZION_ACME_SOAK_MODE").unwrap_or_else(|_| "happy".into());
    eprintln!("acme-soak: mode={mode}");
    let _ = &key_path; // reserved for future legs; keeps the binding meaningful
    match mode.as_str() {
        "happy" => soak_happy(&acme_config, &store, &tls_config, &cert_path).await,
        "key-rollover" => {
            soak_key_rollover(&acme_config, &store, &tls_config, &cert_path, &state_dir).await
        }
        "ttl-edge" => soak_ttl_edge(&acme_config, &store, &tls_config, &cert_path).await,
        "nonce-collision" => {
            soak_nonce_collision(&acme_config, &store, &tls_config, &cert_path).await
        }
        other => {
            eprintln!(
                "acme-soak: FAIL unknown mode '{other}' \
                 (expected happy|key-rollover|ttl-edge|nonce-collision)"
            );
            2
        }
    }
}

/// The #59 baseline: issue → renew → revoke over one persisted account.
#[cfg(feature = "acme")]
async fn soak_happy(
    acme_config: &crate::config::AcmeConfig,
    store: &ChallengeStore,
    tls_config: &crate::config::TlsConfig,
    cert_path: &str,
) -> i32 {
    use std::sync::atomic::Ordering::Relaxed;
    let base = crate::metrics::METRICS.acme_renewals_total.load(Relaxed);
    let base_fail = crate::metrics::METRICS
        .acme_renewal_failures_total
        .load(Relaxed);

    // 1. Issue.
    if let Err(e) = renew_once(acme_config, store, tls_config).await {
        eprintln!("acme-soak: FAIL issue: {e}");
        return 1;
    }
    if !std::path::Path::new(cert_path).exists() {
        eprintln!("acme-soak: FAIL issue: no certificate written to {cert_path}");
        return 1;
    }
    eprintln!("acme-soak: ✓ issued");

    // 2. Renew (drive the issuance path again over the same account).
    if let Err(e) = renew_once(acme_config, store, tls_config).await {
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
    if let Err(e) = revoke_cert(acme_config, cert_path).await {
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

/// Key-rollover leg (issue #134): after a first issue, discard the account
/// credentials and re-issue. `do_renewal_native` must create a *fresh* account
/// (a different key) and issuance must still succeed — proving zion recovers
/// from a lost account file instead of wedging.
#[cfg(feature = "acme")]
async fn soak_key_rollover(
    acme_config: &crate::config::AcmeConfig,
    store: &ChallengeStore,
    tls_config: &crate::config::TlsConfig,
    cert_path: &str,
    state_dir: &str,
) -> i32 {
    let creds_path = std::path::Path::new(state_dir).join("account.json");

    // 1. First issue → an account is created and persisted.
    if let Err(e) = renew_once(acme_config, store, tls_config).await {
        eprintln!("acme-soak: FAIL initial issue: {e}");
        return 1;
    }
    let account_before = match std::fs::read_to_string(&creds_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acme-soak: FAIL key-rollover: no account.json after first issue: {e}");
            return 1;
        }
    };
    eprintln!("acme-soak: ✓ issued (account persisted)");

    // 2. Discard the account credentials — simulate a lost/rotated account key.
    if let Err(e) = std::fs::remove_file(&creds_path) {
        eprintln!("acme-soak: FAIL key-rollover: cannot discard account.json: {e}");
        return 1;
    }
    eprintln!("acme-soak: ✓ discarded account.json");

    // 3. Re-issue → a brand-new account must be registered, issuance must work.
    if let Err(e) = renew_once(acme_config, store, tls_config).await {
        eprintln!("acme-soak: FAIL re-issue after rollover: {e}");
        return 1;
    }
    let account_after = match std::fs::read_to_string(&creds_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acme-soak: FAIL key-rollover: no fresh account.json after re-issue: {e}");
            return 1;
        }
    };
    if account_after == account_before {
        eprintln!(
            "acme-soak: FAIL key-rollover: account.json unchanged — expected a fresh account key"
        );
        return 1;
    }
    if !std::path::Path::new(cert_path).exists() {
        eprintln!("acme-soak: FAIL key-rollover: no certificate after re-issue");
        return 1;
    }
    eprintln!("acme-soak: ✓ re-issued with a fresh account (rollover recovered)");

    // 4. Revoke with the new account to complete the lifecycle.
    if let Err(e) = revoke_cert(acme_config, cert_path).await {
        eprintln!("acme-soak: FAIL revoke after rollover: {e}");
        return 1;
    }
    eprintln!("acme-soak: PASS (key-rollover: issue → discard account → re-issue fresh → revoke)");
    0
}

/// TTL-edge leg (issue #134): issue a real cert, then assert the daemon's
/// renewal decision (`check_cert_expiry`, the same one `spawn_renewal_task`
/// consults) fires exactly at the `renew_before_days` edge — a wide window
/// says "renew now", a zero window says "not yet". Proves the real Pebble
/// notAfter parses and drives the renewal trigger end-to-end.
#[cfg(feature = "acme")]
async fn soak_ttl_edge(
    acme_config: &crate::config::AcmeConfig,
    store: &ChallengeStore,
    tls_config: &crate::config::TlsConfig,
    cert_path: &str,
) -> i32 {
    // 1. Issue a real certificate.
    if let Err(e) = renew_once(acme_config, store, tls_config).await {
        eprintln!("acme-soak: FAIL issue: {e}");
        return 1;
    }
    if !std::path::Path::new(cert_path).exists() {
        eprintln!("acme-soak: FAIL ttl-edge: no certificate written");
        return 1;
    }
    eprintln!("acme-soak: ✓ issued");

    // 2. Edge: a window wider than the cert's remaining life ⇒ renew now.
    if !check_cert_expiry(cert_path, 100_000) {
        eprintln!(
            "acme-soak: FAIL ttl-edge: a 100000-day window must trigger renewal on a fresh cert"
        );
        return 1;
    }
    // 3. Edge: a zero-day window on a fresh (non-expired) cert ⇒ not yet.
    if check_cert_expiry(cert_path, 0) {
        eprintln!(
            "acme-soak: FAIL ttl-edge: a 0-day window must NOT trigger renewal on a fresh cert"
        );
        return 1;
    }
    eprintln!("acme-soak: ✓ renewal trigger fires at the renew_before_days edge, not before");

    // 4. Drive the renewal the trigger asked for, to prove the full path.
    if let Err(e) = renew_once(acme_config, store, tls_config).await {
        eprintln!("acme-soak: FAIL ttl-edge renew: {e}");
        return 1;
    }
    if let Err(e) = revoke_cert(acme_config, cert_path).await {
        eprintln!("acme-soak: FAIL ttl-edge revoke: {e}");
        return 1;
    }
    eprintln!("acme-soak: PASS (ttl-edge: issue → edge decision → renew → revoke)");
    0
}

/// Run `op` up to `attempts` times; `Ok(retries_used)` on the first success.
#[cfg(feature = "acme")]
async fn with_retries<F, Fut>(label: &str, attempts: u32, mut op: F) -> Result<u32, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut last = String::new();
    for n in 0..attempts {
        match op().await {
            Ok(()) => return Ok(n),
            Err(e) => {
                eprintln!(
                    "acme-soak: {label}: attempt {} of {attempts} failed: {e}",
                    n + 1
                );
                last = e;
            }
        }
    }
    Err(last)
}

/// Nonce-collision leg (issue #134). Pebble is started with `PEBBLE_WFE_NONCEREJECT` so a
/// share of the anti-replay nonces zion presents are rejected with `badNonce`. instant-acme
/// retries each request on `badNonce` (RFC 8555 §6.5) up to 3 attempts, so a flow almost
/// always completes in one go; the rare request that exhausts its attempts fails the whole
/// operation, and the daemon would retry it on its next cycle. This leg therefore allows
/// each of issue / renew / revoke up to 3 whole-operation attempts and fails only if one
/// never succeeds. That the rejections really were injected is asserted by the workflow,
/// from Pebble's own log: without it a quiet Pebble would make this leg pass for nothing.
#[cfg(feature = "acme")]
async fn soak_nonce_collision(
    acme_config: &crate::config::AcmeConfig,
    store: &ChallengeStore,
    tls_config: &crate::config::TlsConfig,
    cert_path: &str,
) -> i32 {
    const ATTEMPTS: u32 = 3;
    const NONCE_ROUNDS: u32 = 5;
    let mut op_retries = 0;
    let mut stage = |name: &'static str, r: Result<u32, String>| -> bool {
        match r {
            Ok(n) => {
                op_retries += n;
                eprintln!("acme-soak: ✓ {name} (whole-operation retries: {n})");
                true
            }
            Err(e) => {
                eprintln!("acme-soak: FAIL {name}: gave up after {ATTEMPTS} attempts: {e}");
                false
            }
        }
    };
    let issue = with_retries("issue", ATTEMPTS, || async {
        renew_once(acme_config, store, tls_config)
            .await
            .map_err(|e| e.to_string())
    })
    .await;
    if !stage("issue", issue) {
        return 1;
    }
    if !std::path::Path::new(cert_path).exists() {
        eprintln!("acme-soak: FAIL issue: no certificate written to {cert_path}");
        return 1;
    }
    // Several renewals: enough requests that injected rejections are certain to occur
    // (the workflow checks the count against a clean run), at a rate where whole-operation
    // retries still make the leg reliable.
    for round in 1..=NONCE_ROUNDS {
        let renew = with_retries("renew", ATTEMPTS, || async {
            renew_once(acme_config, store, tls_config)
                .await
                .map_err(|e| e.to_string())
        })
        .await;
        let name: &'static str = match round {
            1 => "renew 1",
            2 => "renew 2",
            _ => "renew 3+",
        };
        if !stage(name, renew) {
            return 1;
        }
    }
    let revoke = with_retries("revoke", ATTEMPTS, || async {
        revoke_cert(acme_config, cert_path)
            .await
            .map_err(|e| e.to_string())
    })
    .await;
    if !stage("revoke", revoke) {
        return 1;
    }
    eprintln!(
        "acme-soak: PASS (nonce-collision: issue → renew → revoke under injected badNonce; \
         whole-operation retries: {op_retries})"
    );
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

    #[cfg(feature = "acme")]
    #[tokio::test]
    async fn a_renewal_that_never_finishes_fails_instead_of_blocking_the_loop() {
        let started = std::time::Instant::now();
        let r: Result<(), String> = with_deadline(
            std::time::Duration::from_millis(100),
            "the ACME renewal",
            std::future::pending(),
        )
        .await;
        let e = r.unwrap_err();
        assert!(e.contains("did not finish"), "{e}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // What finishes in time is passed through, success and failure alike.
        let ok = with_deadline(std::time::Duration::from_secs(5), "x", async { Ok(7) }).await;
        assert_eq!(ok, Ok(7));
        let err: Result<(), String> =
            with_deadline(std::time::Duration::from_secs(5), "x", async {
                Err("the CA said no".to_string())
            })
            .await;
        assert_eq!(err, Err("the CA said no".to_string()));
    }

    #[cfg(all(unix, not(feature = "acme")))]
    mod renew_script {
        use super::super::run_renew_script;
        use std::time::Duration;

        fn dir(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("zion-renew-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        fn alive(pid: &str) -> bool {
            std::process::Command::new("kill")
                .args(["-0", pid])
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }

        #[tokio::test]
        async fn a_script_that_succeeds_or_fails_is_reported_as_before() {
            let d = dir("plain");
            let ok = d.join("ok.sh");
            std::fs::write(&ok, "exit 0\n").unwrap();
            assert_eq!(
                run_renew_script(
                    ok.to_str().unwrap(),
                    d.to_str().unwrap(),
                    Duration::from_secs(30)
                )
                .await,
                Ok(())
            );
            let bad = d.join("bad.sh");
            std::fs::write(&bad, "echo 'the CA said no' >&2\nexit 3\n").unwrap();
            let e = run_renew_script(
                bad.to_str().unwrap(),
                d.to_str().unwrap(),
                Duration::from_secs(30),
            )
            .await
            .unwrap_err();
            assert!(
                e.contains("renew.sh failed") && e.contains("the CA said no"),
                "{e}"
            );
            std::fs::remove_dir_all(&d).ok();
        }

        /// A script that hangs is killed together with what it started: a renewal script is
        /// typically a wrapper, and the shell is not the process doing the work.
        #[tokio::test]
        async fn a_script_that_hangs_is_killed_with_its_children() {
            let d = dir("hang");
            let script = d.join("hang.sh");
            std::fs::write(
                &script,
                format!(
                    "echo $$ > {d}/shell.pid\nsleep 300 &\necho $! > {d}/child.pid\nwait\n",
                    d = d.display()
                ),
            )
            .unwrap();
            let started = std::time::Instant::now();
            let e = run_renew_script(
                script.to_str().unwrap(),
                d.to_str().unwrap(),
                Duration::from_millis(700),
            )
            .await
            .unwrap_err();
            assert!(e.contains("was killed"), "{e}");
            assert!(started.elapsed() < Duration::from_secs(20));
            let shell = std::fs::read_to_string(d.join("shell.pid")).unwrap();
            let child = std::fs::read_to_string(d.join("child.pid")).unwrap();
            // Give the kernel a moment to tear the processes down.
            for _ in 0..50 {
                if !alive(shell.trim()) && !alive(child.trim()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(!alive(shell.trim()), "the shell is still running");
            assert!(
                !alive(child.trim()),
                "what the script started is still running"
            );
            std::fs::remove_dir_all(&d).ok();
        }
    }

    #[test]
    fn a_failed_renewal_is_retried_soon_with_backoff() {
        let m = |n| next_check_delay(n).as_secs() / 60;
        assert_eq!(m(0), 720, "12 h when all is well");
        assert_eq!((m(1), m(2), m(3), m(4)), (5, 10, 20, 40));
        assert_eq!(m(8), 640);
        assert_eq!(m(9), 720, "capped at 12 h");
        assert_eq!(m(u32::MAX), 720, "no overflow");
    }

    // ── the soak's whole-operation retry helper ────────────────────────────────
    // The 100% probe never reaches `with_retries` and the 20% run often succeeds without a
    // second attempt, so its control flow is pinned here rather than left to the soak.

    #[cfg(feature = "acme")]
    #[tokio::test]
    async fn with_retries_succeeds_at_once_without_retrying() {
        let calls = std::cell::Cell::new(0u32);
        let r = with_retries("t", 3, || {
            calls.set(calls.get() + 1);
            async { Ok(()) }
        })
        .await;
        assert_eq!(r, Ok(0), "no retries used");
        assert_eq!(calls.get(), 1);
    }

    #[cfg(feature = "acme")]
    #[tokio::test]
    async fn with_retries_reports_how_many_failures_came_before_the_success() {
        for fail_first in [1u32, 2] {
            let calls = std::cell::Cell::new(0u32);
            let r = with_retries("t", 3, || {
                calls.set(calls.get() + 1);
                let n = calls.get();
                async move {
                    if n <= fail_first {
                        Err(format!("boom {n}"))
                    } else {
                        Ok(())
                    }
                }
            })
            .await;
            assert_eq!(r, Ok(fail_first), "{fail_first} failure(s) then success");
            assert_eq!(calls.get(), fail_first + 1, "stops at the first success");
        }
    }

    #[cfg(feature = "acme")]
    #[tokio::test]
    async fn with_retries_gives_up_after_the_attempts_with_the_last_error() {
        let calls = std::cell::Cell::new(0u32);
        let r = with_retries("t", 3, || {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move { Err(format!("boom {n}")) }
        })
        .await;
        assert_eq!(r, Err("boom 3".to_string()), "the LAST error is returned");
        assert_eq!(calls.get(), 3, "exactly the allowed attempts, no more");
    }

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
    #[cfg(feature = "acme")]
    fn expiry_check_fires_for_short_lived_cert_not_long() {
        // Boot-time linchpin of auto-HTTPS: a near-expiry cert (the 1-day ACME
        // bootstrap cert `zion init` stamps) must read as "renewal needed" so
        // first-boot issuance fires; a long-lived cert must not. Same threshold
        // the background renewal task runs.
        let mk = |days: i64| -> String {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut p = rcgen::CertificateParams::new(vec!["t.example.com".to_string()]).unwrap();
            let now = time::OffsetDateTime::now_utc();
            p.not_before = now - time::Duration::hours(1);
            p.not_after = now + time::Duration::days(days);
            p.self_signed(&key).unwrap().pem()
        };
        let dir = std::env::temp_dir();
        let short = dir.join(format!("zion-acme-short-{}.crt", std::process::id()));
        let long = dir.join(format!("zion-acme-long-{}.crt", std::process::id()));
        std::fs::write(&short, mk(1)).unwrap();
        std::fs::write(&long, mk(365)).unwrap();

        assert!(
            check_cert_expiry(short.to_str().unwrap(), 30),
            "1-day bootstrap cert must read as renewal-needed (fires first-boot ACME)"
        );
        assert!(
            !check_cert_expiry(long.to_str().unwrap(), 30),
            "365-day cert must not trigger renewal"
        );
        assert!(
            check_cert_expiry("/nonexistent/zion-no-such.crt", 30),
            "an unreadable cert must renew to be safe"
        );

        let _ = std::fs::remove_file(&short);
        let _ = std::fs::remove_file(&long);
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
