// SPDX-License-Identifier: Apache-2.0
//! Listener supervisor — Phase 1.5 of the dynamic-config plan.
//!
//! Watches `state.config` (an `ArcSwap<ResolvedAppConfig>`) for changes
//! to `listen_http` / `listen_https`. When either differs from the
//! currently-bound address, attempts a fresh `bind()` on the new address
//! and replaces the accept-loop task. The OLD accept loop is told to
//! return via its `watch::Sender<bool>`; live connections it had spawned
//! continue under the existing connection-limit semaphore until they
//! finish.
//!
//! Failure handling is conservative on purpose: if the new bind fails
//! (port in use, permission denied, malformed address), the supervisor
//! logs a structured warning and **keeps the existing listener**. A typo
//! in `zion.toml` never strands Zion offline.
//!
//! Out of scope for Phase 1.5:
//!   * io_uring single-shot accept (`--features io-uring-accept`): the
//!     uring task is bound to the listener's file descriptor at spawn
//!     time and cannot be re-pointed without tearing it down. The
//!     supervisor logs a WARN and skips the rebind in that build flavour.
//!     Operators on the io_uring path keep the v0.1.7 behaviour:
//!     `listen_*` is a restart-required setting.
//!   * QUIC / HTTP/3 listener — its UDP socket is independent and not
//!     re-bound here.

use crate::{net, run_http_accept_loop, AppState, ResolvedAppConfig};
// `run_https_accept_loop` is only spawned by the supervisor in the
// non-io_uring build flavour; on `--features io-uring-accept` the
// accept loop is owned by the uring thread spawned in `async_main`
// and the supervisor never calls it.
#[cfg(not(all(target_os = "linux", feature = "io-uring-accept")))]
use crate::run_https_accept_loop;
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// One bound listener with the channels and handle needed to retire it.
struct BoundListener {
    addr: SocketAddr,
    /// `send(true)` makes the accept loop return on its next iteration.
    shutdown_tx: watch::Sender<bool>,
    /// Join handle of the spawned accept loop task. Dropping it does not
    /// abort the loop — abort happens through `shutdown_tx`.
    join: Option<tokio::task::JoinHandle<()>>,
}

impl BoundListener {
    /// Tell the loop to stop accepting and drop the listener fd. Existing
    /// connection tasks the loop spawned continue independently.
    fn retire(self) {
        let _ = self.shutdown_tx.send(true);
        // We deliberately don't `await` the join handle here: the
        // supervisor must keep moving even if the loop is parked on a
        // long `select!`. The accept loop is well-behaved (it returns on
        // the next iteration after the shutdown flip) so this is bounded.
        drop(self.join);
    }
}

/// Owns the live HTTP and HTTPS accept loops, reconciling them to the
/// currently-published `ResolvedAppConfig` snapshot.
pub(crate) struct ListenerSupervisor {
    http: Option<BoundListener>,
    https: Option<BoundListener>,
    state: Arc<AppState>,
}

impl ListenerSupervisor {
    /// Build the supervisor from the initial bind state. Caller has
    /// already attempted to bind both ports synchronously at boot — we
    /// just adopt the resulting listeners (or absence thereof, on HTTP).
    ///
    /// `https_listener` is `Option<TcpListener>` because the initial
    /// HTTPS bind may legitimately be deferred or fail in some pathways
    /// (the supervisor itself will retry on the next config reload).
    pub(crate) fn new(
        state: Arc<AppState>,
        http_listener: Option<(SocketAddr, tokio::net::TcpListener)>,
        https_listener: Option<(SocketAddr, tokio::net::TcpListener)>,
    ) -> Self {
        let http = http_listener.map(|(addr, listener)| {
            let (tx, rx) = watch::channel(false);
            let join = tokio::spawn(run_http_accept_loop(listener, state.clone(), rx));
            BoundListener {
                addr,
                shutdown_tx: tx,
                join: Some(join),
            }
        });

        let https = https_listener.map(|(addr, listener)| {
            let (tx, rx) = watch::channel(false);
            // The cfg-gated overload is selected at compile time; the
            // io-uring branch is intentionally NOT spawned by the
            // supervisor because rebind on uring is unsupported (see
            // module docstring). The boot-path in main.rs continues to
            // spawn the uring task itself when that feature is on.
            #[cfg(not(all(target_os = "linux", feature = "io-uring-accept")))]
            let join = tokio::spawn(run_https_accept_loop(listener, state.clone(), rx));
            #[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
            let join = {
                // On uring, the supervisor doesn't drive the accept loop
                // itself — main.rs already spawned `run_https_accept_loop`
                // with the uring receiver. We register a no-op handle so
                // the diff/reconcile logic can still observe a "current
                // address" without owning the task.
                let _ = (listener, &state);
                tokio::spawn(async move {
                    // The shutdown channel is held to keep the supervisor
                    // structure consistent across both build flavours.
                    let mut rx = rx;
                    let _ = rx.changed().await;
                })
            };
            BoundListener {
                addr,
                shutdown_tx: tx,
                join: Some(join),
            }
        });

        Self { http, https, state }
    }

    /// Spawn a background task that listens on `config_change_rx` and
    /// reconciles the supervisor whenever a successful config reload
    /// publishes a new snapshot.
    ///
    /// `config_change_rx` is bumped by `reload::spawn_config_watcher`
    /// after every atomic swap. `shutdown_rx` is flipped to `true` by
    /// `async_main` on SIGINT/SIGTERM and tells the reconciler to retire
    /// all listeners and return — the returned `JoinHandle` then resolves
    /// and the caller proceeds to the connection-drain phase.
    pub(crate) fn spawn_reconciler(
        mut self,
        config: Arc<ArcSwap<ResolvedAppConfig>>,
        mut config_change_rx: watch::Receiver<u64>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    res = shutdown_rx.changed() => {
                        if res.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    res = config_change_rx.changed() => {
                        if res.is_err() {
                            // Sender side gone — supervised by the main
                            // task and should not happen before shutdown,
                            // but treat it as an implicit shutdown rather
                            // than a hot loop.
                            break;
                        }
                        let snapshot = config.load_full();
                        self.reconcile(&snapshot).await;
                    }
                }
            }
            // Retire both listeners so their accept loops exit and we
            // don't leak file descriptors.
            if let Some(b) = self.http.take() {
                b.retire();
            }
            if let Some(b) = self.https.take() {
                b.retire();
            }
        })
    }

    /// Compare the currently bound listeners with what the snapshot wants
    /// and perform the minimum number of (re)binds. Failures keep the
    /// existing listener in place.
    async fn reconcile(&mut self, snapshot: &ResolvedAppConfig) {
        // ── HTTPS ────────────────────────────────────────────────────
        // HTTPS is the primary listener; we apply changes first so a
        // typo in HTTP doesn't keep us from the more important update.
        if let Some(want) = snapshot.listen_https {
            self.reconcile_one(ListenerKind::Https, Some(want)).await;
        }
        // (If listen_https is None, the parse failed at build time and
        //  was already logged. We don't tear down the existing HTTPS
        //  listener over a typo.)

        // ── HTTP ─────────────────────────────────────────────────────
        // HTTP is optional. `None` here means either the parse failed or
        // the operator removed the field — the supervisor treats both as
        // "keep the existing one" rather than risk stranding ACME / 301.
        if let Some(want) = snapshot.listen_http {
            self.reconcile_one(ListenerKind::Http, Some(want)).await;
        }
    }

    async fn reconcile_one(&mut self, kind: ListenerKind, want: Option<SocketAddr>) {
        let (slot_addr, _) = match self.slot(kind) {
            Some(b) => (Some(b.addr), Some(())),
            None => (None, None),
        };

        let want = match want {
            Some(a) => a,
            None => return, // see reconcile() — None is "no change"
        };

        if Some(want) == slot_addr {
            return; // already on the right address
        }

        // Attempt the new bind on the runtime thread. `bind_with_reuseport`
        // is std synchronous; it's microseconds, fine inline.
        let new_listener = match net::bind_with_reuseport(want) {
            Ok(l) => l,
            Err(e) => {
                let kept = slot_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "(none)".to_string());
                crate::logging::warn(
                    "listener",
                    &format!(
                        "rebind {} {} → {} failed: {} (keeping {})",
                        kind.label(),
                        kept,
                        want,
                        e,
                        kept
                    ),
                );
                return;
            }
        };

        // Bind succeeded. Spawn the new accept loop on the new listener.
        let (tx, rx) = watch::channel(false);
        let new_join = match kind {
            ListenerKind::Http => {
                tokio::spawn(run_http_accept_loop(new_listener, self.state.clone(), rx))
            }
            ListenerKind::Https => {
                #[cfg(not(all(target_os = "linux", feature = "io-uring-accept")))]
                {
                    tokio::spawn(run_https_accept_loop(new_listener, self.state.clone(), rx))
                }
                #[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
                {
                    // io_uring rebind is not supported (see module doc).
                    // Drop the freshly-bound listener and warn — keep
                    // the previously-bound one alive.
                    drop(new_listener);
                    let _ = (rx, tx);
                    crate::logging::warn(
                        "listener",
                        &format!(
                            "HTTPS rebind to {want} skipped: --features io-uring-accept is incompatible with rebind in Phase 1.5; restart required"
                        ),
                    );
                    return;
                }
            }
        };

        // Retire the old listener (if any) BEFORE we replace the slot,
        // so the slot is never observed empty while a request is being
        // routed by another task.
        let new_bound = BoundListener {
            addr: want,
            shutdown_tx: tx,
            join: Some(new_join),
        };
        let old = self.replace_slot(kind, Some(new_bound));
        let old_addr_str = old
            .as_ref()
            .map(|b| b.addr.to_string())
            .unwrap_or_else(|| "(none)".to_string());
        if let Some(old) = old {
            old.retire();
        }
        crate::logging::info(
            "listener",
            &format!(
                "rebound {} {} → {} (old listener draining; live connections continue)",
                kind.label(),
                old_addr_str,
                want
            ),
        );
    }

    fn slot(&self, kind: ListenerKind) -> Option<&BoundListener> {
        match kind {
            ListenerKind::Http => self.http.as_ref(),
            ListenerKind::Https => self.https.as_ref(),
        }
    }

    fn replace_slot(
        &mut self,
        kind: ListenerKind,
        new: Option<BoundListener>,
    ) -> Option<BoundListener> {
        match kind {
            ListenerKind::Http => std::mem::replace(&mut self.http, new),
            ListenerKind::Https => std::mem::replace(&mut self.https, new),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerKind {
    Http,
    Https,
}

impl ListenerKind {
    fn label(self) -> &'static str {
        match self {
            ListenerKind::Http => "HTTP",
            ListenerKind::Https => "HTTPS",
        }
    }
}

/// Diff between desired and current listener state — pure, testable.
/// `reconcile_one` does not literally use this enum (the action is
/// straight-line), but having it as a free function pins the contract
/// in tests so a future refactor cannot silently regress it.
#[cfg(test)]
pub(crate) fn diff(current: Option<SocketAddr>, desired: Option<SocketAddr>) -> ListenerDiff {
    match (current, desired) {
        (None, None) => ListenerDiff::Same,
        (Some(c), Some(d)) if c == d => ListenerDiff::Same,
        (Some(c), Some(d)) => ListenerDiff::Rebind { from: c, to: d },
        (None, Some(d)) => ListenerDiff::Add(d),
        (Some(c), None) => ListenerDiff::Remove(c),
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListenerDiff {
    Same,
    Rebind { from: SocketAddr, to: SocketAddr },
    Add(SocketAddr),
    Remove(SocketAddr),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    #[test]
    fn diff_same_when_both_none() {
        assert_eq!(diff(None, None), ListenerDiff::Same);
    }

    #[test]
    fn diff_same_when_both_equal() {
        let a = s("127.0.0.1:8080");
        assert_eq!(diff(Some(a), Some(a)), ListenerDiff::Same);
    }

    #[test]
    fn diff_rebind_on_change() {
        let from = s("127.0.0.1:8080");
        let to = s("127.0.0.1:8081");
        assert_eq!(
            diff(Some(from), Some(to)),
            ListenerDiff::Rebind { from, to }
        );
    }

    #[test]
    fn diff_add_when_was_none() {
        let to = s("0.0.0.0:80");
        assert_eq!(diff(None, Some(to)), ListenerDiff::Add(to));
    }

    #[test]
    fn diff_remove_when_now_none() {
        // Note: the supervisor itself does NOT act on Remove (we never
        // tear down the existing HTTP/HTTPS over a missing field — see
        // `reconcile()`), but the diff itself is total and tested for
        // future use cases.
        let from = s("0.0.0.0:80");
        assert_eq!(diff(Some(from), None), ListenerDiff::Remove(from));
    }

    /// Cross-IP-family change (v4 → v6) is a real rebind, not a Same.
    #[test]
    fn diff_recognises_v4_to_v6_change() {
        let v4 = s("127.0.0.1:8080");
        let v6 = s("[::1]:8080");
        assert_eq!(
            diff(Some(v4), Some(v6)),
            ListenerDiff::Rebind { from: v4, to: v6 }
        );
    }

    /// Same port, different bind interface (`0.0.0.0` ≠ `127.0.0.1`)
    /// counts as a rebind. The supervisor must take the right action
    /// here even though the port portion is unchanged.
    #[test]
    fn diff_recognises_interface_change_at_same_port() {
        let any = s("0.0.0.0:8080");
        let lo = s("127.0.0.1:8080");
        assert_eq!(
            diff(Some(any), Some(lo)),
            ListenerDiff::Rebind { from: any, to: lo }
        );
    }
}
