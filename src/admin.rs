// SPDX-License-Identifier: Apache-2.0
//! Admin API — a dedicated, loopback-by-default listener for runtime config
//! inspection, push, and reload. The programmatic counterpart to the file
//! watcher: same reload engine, a different trigger. See `docs/deploy/admin-api.md`.
//!
//! - `GET  /admin/config` → live snapshot JSON (same source as `/_zion/snapshot.json`).
//! - `POST /admin/config` → push a full TOML body → validate + atomic-swap (`reload_now`).
//! - `POST /admin/reload` → re-read `zion.toml` from disk.
//!
//! Gated to internal IPs (`auth = "internal-ip"`, the default), rate-limited,
//! and — writes only — audited. The listener is **physically separate** from
//! the public `:443`, so a routing accident can't expose `/admin/*`. Absent
//! `[admin]` section ⇒ no listener (zero overhead, zero attack surface).
//!
//! Deliberately NOT trusting `X-Forwarded-For` / `X-Client-Cert-*` here: admin
//! authorization is not transitive through a forwarding proxy.
//!
//! Two auth modes (`[admin].auth`):
//! - `internal-ip` (default): plain HTTP; each request is authorized iff the
//!   connection peer is an internal IP.
//! - `mtls`: TLS with a **required** client cert chaining to `tls.client_ca_path`.
//!   A completed handshake IS the authorization — only CA-signed clients ever
//!   reach the HTTP layer, so the peer's IP no longer matters and the listener
//!   can safely bind a routable interface.

use crate::audit::{self, AuditEvent};
use crate::reload::{reload_now, ConfigSource};
use crate::AppState;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

/// A pushed config body is capped — a `zion.toml` is small; anything larger is
/// almost certainly a mistake or an attack, not a config.
const MAX_ADMIN_BODY: usize = 1 << 20; // 1 MiB

/// A tiny global fixed-window rate limiter for the admin listener. Loopback +
/// single-tenant, so a per-IP table would be overkill — one global window
/// bounds the expensive reload path against accidental loops / abuse (defense
/// in depth on top of the internal-ip gate). Approximate by design.
pub(crate) struct AdminRateLimiter {
    limit: u32,
    window_sec: AtomicU64,
    count: AtomicU32,
}

impl AdminRateLimiter {
    pub(crate) fn new(limit: u32) -> Self {
        Self {
            limit,
            window_sec: AtomicU64::new(0),
            count: AtomicU32::new(0),
        }
    }

    /// Consume one token for the current 1 s window; `false` ⇒ over the limit.
    fn allow(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let start = self.window_sec.load(Ordering::Acquire);
        if now > start
            && self
                .window_sec
                .compare_exchange(start, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            // We claimed the new window; this request is its first.
            self.count.store(1, Ordering::Release);
            return true;
        }
        // Same window (or another thread just rolled it): count this request.
        // fetch_add returns the PREVIOUS count `p`; the new count is `p + 1`, so
        // "new count <= limit" is exactly `p < limit`.
        self.count.fetch_add(1, Ordering::AcqRel) < self.limit
    }
}

/// Everything `reload_now` needs that isn't in `AppState`, captured at boot and
/// shared with the admin handler so `POST /admin/config` / `/admin/reload` flow
/// through the EXACT same reload path as the file watcher (atomic swap, health
/// preservation, generation bump, notify). Also carries the listener's rate
/// limiter.
pub(crate) struct AdminReloadCtx {
    pub(crate) conn_limit_max: usize,
    pub(crate) change_notifier: Option<tokio::sync::watch::Sender<u64>>,
    pub(crate) config_path: PathBuf,
    pub(crate) boot_tls_cert: Option<String>,
    pub(crate) boot_tls_key: Option<String>,
    pub(crate) rate_limiter: AdminRateLimiter,
}

/// How the admin listener authorizes connections.
pub(crate) enum AdminAuth {
    /// Plain HTTP; authorize per-request on the peer being an internal IP.
    InternalIp,
    /// TLS with a required client cert — a completed handshake is authorization.
    Mtls(Arc<TlsAcceptor>),
}

/// Spawn the admin listener. Returns immediately; the accept loop runs on a
/// tokio task. A bind failure is logged and the task exits (the data plane is
/// untouched — the admin listener is independent by design).
pub(crate) fn spawn_admin_listener(
    state: Arc<AppState>,
    listen: SocketAddr,
    ctx: Arc<AdminReloadCtx>,
    auth: AdminAuth,
) {
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(listen).await {
            Ok(l) => l,
            Err(e) => {
                crate::logging::error(
                    "admin",
                    &format!("cannot bind admin listener on {listen}: {e} — admin API disabled"),
                );
                return;
            }
        };
        let mode = match auth {
            AdminAuth::InternalIp => "internal-ip auth",
            AdminAuth::Mtls(_) => "mTLS (required client cert)",
        };
        crate::logging::info(
            "admin",
            &format!("admin API on {listen} (GET/POST /admin/config, POST /admin/reload; {mode})"),
        );
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let st = state.clone();
                    let cx = ctx.clone();
                    match &auth {
                        AdminAuth::InternalIp => {
                            tokio::spawn(serve_admin(stream, peer, st, cx, false));
                        }
                        AdminAuth::Mtls(acceptor) => {
                            let acc = acceptor.clone();
                            tokio::spawn(async move {
                                // The handshake performs client-cert verification;
                                // failure (missing / untrusted cert) drops the
                                // connection before any request is served.
                                match acc.accept(stream).await {
                                    Ok(tls) => serve_admin(tls, peer, st, cx, true).await,
                                    Err(e) => crate::logging::warn(
                                        "admin",
                                        &format!("admin mTLS handshake failed from {peer}: {e}"),
                                    ),
                                }
                            });
                        }
                    }
                }
                Err(e) => crate::logging::warn("admin", &format!("admin accept error: {e}")),
            }
        }
    });
}

/// Serve one admin connection over any stream (plain TCP or a TLS stream). The
/// 30 s timeout bounds a stuck client so it can't pin a task forever.
async fn serve_admin<S>(
    stream: S,
    peer: SocketAddr,
    state: Arc<AppState>,
    ctx: Arc<AdminReloadCtx>,
    is_mtls: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        hyper::server::conn::http1::Builder::new().serve_connection(
            io,
            service_fn(move |req| handle(req, peer, state.clone(), ctx.clone(), is_mtls)),
        ),
    )
    .await;
}

/// Service handler. Authorization: in `mtls` mode the completed TLS handshake
/// already verified the client cert, so the connection is authorized regardless
/// of peer IP; otherwise the peer must be an internal IP (never a forwarded
/// header). Infallible — always produces a response.
async fn handle(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    state: Arc<AppState>,
    ctx: Arc<AdminReloadCtx>,
    is_mtls: bool,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let authorized = is_mtls || crate::security::is_internal_ip(&peer.ip());
    // Rate-limit only authorized requests (an unauthorized flood gets the cheap
    // 403 below and shouldn't be able to starve a real operator's tokens).
    if authorized && !ctx.rate_limiter.allow() {
        return Ok(json(
            StatusCode::TOO_MANY_REQUESTS,
            br#"{"error":"rate limited"}"#,
        ));
    }
    // Write endpoints (async + stateful) are handled here; the auth gate, the
    // read (GET /admin/config) and 404 stay in the pure, unit-tested `respond`.
    if authorized && req.method() == Method::POST {
        match req.uri().path() {
            // Push a full new config body → validate + atomic-swap via reload_now.
            "/admin/config" => {
                let result = match read_body_string(req).await {
                    Ok(toml) => reload_via(ConfigSource::Body(toml), &state, &ctx).await,
                    Err(e) => Err(e),
                };
                audit_write(&state, peer, "/admin/config", "config push", &result);
                return Ok(reload_response(result));
            }
            // Re-read zion.toml from disk (skip the watcher's 2s debounce).
            "/admin/reload" => {
                let src = ConfigSource::File(ctx.config_path.clone());
                let result = reload_via(src, &state, &ctx).await;
                audit_write(&state, peer, "/admin/reload", "config reload", &result);
                return Ok(reload_response(result));
            }
            _ => {}
        }
    }
    Ok(respond(req.method(), req.uri().path(), authorized, || {
        snapshot_body(&state)
    }))
}

/// Emit one audit event per admin write — who (connection peer), what (action +
/// endpoint), outcome (new generation, or the rejection reason). This is the
/// tamper-evident record of every config change made through the API.
fn audit_write(
    state: &AppState,
    peer: SocketAddr,
    path: &str,
    action: &str,
    result: &Result<u64, String>,
) {
    let detail = match result {
        Ok(gen) => format!("admin {action} accepted → generation {gen}"),
        Err(e) => format!("admin {action} rejected: {e}"),
    };
    state.audit.emit(AuditEvent {
        seq: 0,
        ts: String::new(),
        kind: audit::kind::CONFIG_RELOAD,
        trace_id: None,
        remote_ip: Some(peer.ip().to_string()),
        method: Some("POST".to_string()),
        path: Some(path.to_string()),
        detail: Some(detail),
    });
}

/// Read the request body as a UTF-8 string, capped at `MAX_ADMIN_BODY`. The Err
/// is a human message routed to a 400.
async fn read_body_string(req: Request<hyper::body::Incoming>) -> Result<String, String> {
    let collected = Limited::new(req.into_body(), MAX_ADMIN_BODY)
        .collect()
        .await
        .map_err(|_| format!("request body exceeds {MAX_ADMIN_BODY} bytes (or stream error)"))?;
    String::from_utf8(collected.to_bytes().to_vec())
        .map_err(|_| "request body is not valid UTF-8".to_string())
}

/// Apply a config (file or body) through the shared `reload_now`, off the async
/// worker (it does a file read + a CPU rebuild).
async fn reload_via(
    source: ConfigSource,
    state: &Arc<AppState>,
    ctx: &Arc<AdminReloadCtx>,
) -> Result<u64, String> {
    let sc = state.config.clone();
    let clm = ctx.conn_limit_max;
    let cn = ctx.change_notifier.clone();
    let bc = ctx.boot_tls_cert.clone();
    let bk = ctx.boot_tls_key.clone();
    tokio::task::spawn_blocking(move || {
        reload_now(source, &sc, clm, cn.as_ref(), bc.as_deref(), bk.as_deref())
    })
    .await
    .unwrap_or_else(|e| Err(format!("reload task panicked: {e}")))
}

/// Turn a reload outcome into the HTTP response: 200 + `{"generation":N}` on
/// success; 400 + `{"error":...}` on rejection (+ bump the reject counter).
fn reload_response(result: Result<u64, String>) -> Response<Full<Bytes>> {
    match result {
        Ok(gen) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Cache-Control", "no-store")
            .body(Full::new(Bytes::from(format!(
                "{{\"generation\":{gen}}}\n"
            ))))
            .unwrap(),
        Err(e) => {
            crate::observability::ADMIN_REJECTS_TOTAL.fetch_add(1, Ordering::Relaxed);
            crate::logging::warn("admin", &format!("config push rejected: {e}"));
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json; charset=utf-8")
                .body(Full::new(Bytes::from(format!(
                    "{{\"error\":{}}}\n",
                    json_string(&e)
                ))))
                .unwrap()
        }
    }
}

/// Minimal JSON string literal (quoted + escaped) for embedding an arbitrary
/// error message (TOML errors carry quotes + newlines) in a JSON body.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The auth + routing decision, pulled out so it's unit-testable without an
/// `AppState`: the snapshot body is supplied lazily by the caller.
fn respond(
    method: &Method,
    path: &str,
    internal: bool,
    snapshot: impl FnOnce() -> Bytes,
) -> Response<Full<Bytes>> {
    if !internal {
        return json(StatusCode::FORBIDDEN, br#"{"error":"forbidden"}"#);
    }
    match (method, path) {
        (&Method::GET, "/admin/config") => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Cache-Control", "no-store")
            .body(Full::new(snapshot()))
            .unwrap(),
        _ => json(StatusCode::NOT_FOUND, br#"{"error":"not found"}"#),
    }
}

/// Build the live snapshot JSON from the current `ResolvedAppConfig` — identical
/// construction to the `/_zion/snapshot.json` handler (same source of truth).
fn snapshot_body(state: &AppState) -> Bytes {
    let cfg = state.config.load();
    let platform = crate::bootstrap::detect();
    let mut rows: Vec<crate::metrics::UpstreamRow<'_>> = cfg
        .health_map
        .iter()
        .map(|(url, h)| crate::metrics::UpstreamRow {
            url: url.as_str(),
            healthy: h.healthy.load(std::sync::atomic::Ordering::Relaxed),
            latency_us: h.latency_us.load(std::sync::atomic::Ordering::Relaxed),
        })
        .collect();
    rows.sort_by(|a, b| a.url.cmp(b.url));
    crate::metrics::snapshot_json(platform, &rows)
}

fn json(status: StatusCode, body: &'static [u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from_static(body)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Bytes {
        Bytes::from_static(b"{\"snapshot\":true}")
    }

    #[test]
    fn non_internal_peer_is_forbidden() {
        let r = respond(&Method::GET, "/admin/config", false, snap);
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn rate_limiter_enforces_limit_within_window() {
        // Three rapid calls land in the same 1 s window (nanoseconds apart):
        // the first two are allowed, the third is over the limit.
        let rl = AdminRateLimiter::new(2);
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(!rl.allow());
    }

    #[test]
    fn reload_response_ok_is_200() {
        let r = reload_response(Ok(7));
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers().get("Cache-Control").unwrap(), "no-store");
    }

    #[test]
    fn reload_response_err_is_400_and_bumps_counter() {
        let before = crate::observability::ADMIN_REJECTS_TOTAL.load(Ordering::Relaxed);
        let r = reload_response(Err("bad config".to_string()));
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(
            crate::observability::ADMIN_REJECTS_TOTAL.load(Ordering::Relaxed) > before,
            "a rejected push must bump zion_admin_rejects_total"
        );
    }

    #[test]
    fn json_string_escapes_quotes_and_newlines() {
        // TOML errors carry quotes + newlines; the JSON body must stay valid.
        assert_eq!(json_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn internal_get_config_returns_snapshot() {
        let r = respond(&Method::GET, "/admin/config", true, snap);
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get("Content-Type").unwrap(),
            "application/json; charset=utf-8"
        );
        assert_eq!(r.headers().get("Cache-Control").unwrap(), "no-store");
    }

    #[test]
    fn internal_unknown_route_is_404() {
        assert_eq!(
            respond(&Method::GET, "/admin/nope", true, snap).status(),
            StatusCode::NOT_FOUND
        );
        // Wrong method on the known path → also 404 (no write endpoints yet).
        assert_eq!(
            respond(&Method::POST, "/admin/config", true, snap).status(),
            StatusCode::NOT_FOUND
        );
    }
}
