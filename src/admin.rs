// SPDX-License-Identifier: Apache-2.0
//! Admin API — a dedicated, loopback-by-default listener for runtime config
//! inspection (and, in later #26 phases, push + reload).
//!
//! Phase 2 is **read-only**: `GET /admin/config` returns the live snapshot JSON
//! — the SAME source of truth as `/_zion/snapshot.json` (`metrics::snapshot_json`)
//! — gated to internal IPs (`auth = "internal-ip"`, the default). The listener
//! is **physically separate** from the public `:443`, so a routing accident
//! can't expose `/admin/*`. Absent `[admin]` section ⇒ no listener (zero
//! overhead, zero attack surface).
//!
//! Deliberately NOT trusting `X-Forwarded-For` / `X-Client-Cert-*` here: admin
//! authorization is not transitive through a forwarding proxy. Plain HTTP on
//! loopback for now; mTLS is Phase 4.

use crate::AppState;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;

/// Spawn the admin listener. Returns immediately; the accept loop runs on a
/// tokio task. A bind failure is logged and the task exits (the data plane is
/// untouched — the admin listener is independent by design).
pub(crate) fn spawn_admin_listener(state: Arc<AppState>, listen: SocketAddr) {
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
        crate::logging::info(
            "admin",
            &format!("admin API on {listen} (read-only; internal-ip auth)"),
        );
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let st = state.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        // Connection-level idle bound so a stuck admin client
                        // can't pin a task forever.
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            hyper::server::conn::http1::Builder::new().serve_connection(
                                io,
                                service_fn(move |req| handle(req, peer, st.clone())),
                            ),
                        )
                        .await;
                    });
                }
                Err(e) => crate::logging::warn("admin", &format!("admin accept error: {e}")),
            }
        }
    });
}

/// Service handler: enforce internal-ip auth on the *connection peer* (never a
/// forwarded header), then route. Infallible — always produces a response.
async fn handle(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let internal = crate::security::is_internal_ip(&peer.ip());
    Ok(respond(req.method(), req.uri().path(), internal, || {
        snapshot_body(&state)
    }))
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
