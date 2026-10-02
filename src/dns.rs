// SPDX-License-Identifier: Apache-2.0
//! DNS resolution for upstream connections, with stale-on-error.
//!
//! The pooled client resolved names with the system resolver (`getaddrinfo`) on every new
//! connection and nothing else: a resolver outage, or a slow one (glibc waits 5 s per attempt,
//! several attempts), turned straight into failed or stalled requests even though the upstream's
//! addresses had not changed. [`resolve_with`] keeps the last successful answer per host and
//! serves it when a fresh lookup fails, returns nothing or exceeds the deadline, for up to
//! `dns_stale_secs`. A fresh lookup is always tried first, so DNS changes still take effect on
//! the next connection; the cache only ever replaces an *error*.
//!
//! Only the system resolver's answer is cached, per host name; an IP literal never reaches it.

use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

/// Fresh lookups that failed, timed out or came back empty (with or without a cached fallback).
pub static LOOKUP_FAILURES: AtomicU64 = AtomicU64::new(0);
/// Lookups answered from the last good result because the fresh one failed.
pub static STALE_SERVED: AtomicU64 = AtomicU64::new(0);

pub const DEFAULT_STALE_SECS: u64 = 3600;
pub const DEFAULT_TIMEOUT_MS: u64 = 2000;
/// Hosts come from the config, so this is generous; it only bounds a pathological case.
const MAX_ENTRIES: usize = 4096;

static STALE_SECS: AtomicU64 = AtomicU64::new(DEFAULT_STALE_SECS);
static TIMEOUT_MS: AtomicU64 = AtomicU64::new(DEFAULT_TIMEOUT_MS);

/// Apply `[server] dns_stale_secs` / `dns_timeout_ms` (`0` = no stale answers / no deadline).
pub fn configure(stale_secs: u64, timeout_ms: u64) {
    STALE_SECS.store(stale_secs, Relaxed);
    TIMEOUT_MS.store(timeout_ms, Relaxed);
}

/// The policy currently in force: (`dns_stale_secs`, `dns_timeout_ms`).
#[cfg(test)]
pub fn current() -> (u64, u64) {
    (STALE_SECS.load(Relaxed), TIMEOUT_MS.load(Relaxed))
}

type Outcome = Result<Vec<SocketAddr>, (io::ErrorKind, String)>;
type Flight = tokio::sync::watch::Receiver<Option<Outcome>>;

struct Inner {
    /// host → (last good answer with its port normalized to 0, when it was observed)
    entries: Mutex<HashMap<String, (Vec<SocketAddr>, u64)>>,
    /// Lookups currently running, one per host (see [`LastGood::join_or_start`]).
    flights: Mutex<HashMap<String, Flight>>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

/// Last good answers by host name, plus the lookups in flight. A cheap shared handle.
#[derive(Clone)]
pub struct LastGood(std::sync::Arc<Inner>);

impl Default for LastGood {
    fn default() -> Self {
        Self::with_clock(now_s)
    }
}

static CACHE: std::sync::LazyLock<LastGood> = std::sync::LazyLock::new(LastGood::default);

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Removes the host's in-flight marker however the lookup task ends (even by panic).
struct EndFlight(LastGood, String);
impl Drop for EndFlight {
    fn drop(&mut self) {
        locked(&self.0 .0.flights).remove(&self.1);
    }
}

impl LastGood {
    pub fn with_clock(clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(Inner {
            entries: Mutex::default(),
            flights: Mutex::default(),
            clock: Box::new(clock),
        }))
    }

    /// Remember an answer. Whole `SocketAddr`s are kept (an IPv6 scope id and flow info are
    /// part of the address), with the port set to 0: the caller restores the one it needs.
    fn put(&self, host: &str, addrs: &[SocketAddr]) {
        let norm: Vec<SocketAddr> = addrs
            .iter()
            .map(|a| {
                let mut a = *a;
                a.set_port(0);
                a
            })
            .collect();
        let mut m = locked(&self.0.entries);
        if m.len() >= MAX_ENTRIES && !m.contains_key(host) {
            m.clear();
        }
        m.insert(host.to_string(), (norm, (self.0.clock)()));
    }

    fn get(&self, host: &str, max_age_s: u64) -> Option<Vec<SocketAddr>> {
        let m = locked(&self.0.entries);
        let (addrs, at) = m.get(host)?;
        ((self.0.clock)().saturating_sub(*at) <= max_age_s && !addrs.is_empty())
            .then(|| addrs.clone())
    }

    /// Join the lookup already running for `host`, or start `lookup` as one. The system
    /// resolver's `getaddrinfo` runs on the blocking pool and cannot be cancelled once started,
    /// so a deadline only stops *waiting*: without this, every connection made during a
    /// resolver outage would leave one more blocked lookup behind and eventually exhaust the
    /// pool. At most one runs per host; it records its answer (even a late one) for later use.
    fn join_or_start<F>(&self, host: &str, lookup: F) -> Flight
    where
        F: Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'static,
    {
        let mut flights = locked(&self.0.flights);
        if let Some(rx) = flights.get(host) {
            return rx.clone();
        }
        let (tx, rx) = tokio::sync::watch::channel(None);
        flights.insert(host.to_string(), rx.clone());
        drop(flights);
        let (cache, host) = (self.clone(), host.to_string());
        tokio::spawn(async move {
            let end = EndFlight(cache.clone(), host.clone());
            let out: Outcome = match lookup.await {
                Ok(a) if a.is_empty() => {
                    Err((io::ErrorKind::NotFound, format!("no addresses for {host}")))
                }
                Ok(a) => {
                    cache.put(&host, &a);
                    Ok(a)
                }
                Err(e) => Err((e.kind(), e.to_string())),
            };
            drop(end); // a caller arriving from here on starts a fresh lookup
            let _ = tx.send(Some(out));
        });
        rx
    }
}

/// Resolve `host` with `lookup`, falling back to the last good answer (see the module docs).
/// Resolvers report port 0; the connector sets the real port.
pub async fn resolve_with<F>(
    cache: &LastGood,
    host: &str,
    stale_secs: u64,
    timeout_ms: u64,
    lookup: F,
) -> io::Result<Vec<SocketAddr>>
where
    F: Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'static,
{
    let mut flight = cache.join_or_start(host, lookup);
    let wait = async {
        match flight.wait_for(Option::is_some).await {
            Ok(v) => v
                .clone()
                .unwrap_or_else(|| Err((io::ErrorKind::Other, "no outcome".into()))),
            Err(_) => Err((io::ErrorKind::Other, "dns lookup task ended".into())),
        }
    };
    let outcome = if timeout_ms == 0 {
        wait.await
    } else {
        tokio::time::timeout(Duration::from_millis(timeout_ms), wait)
            .await
            .unwrap_or_else(|_| {
                Err((
                    io::ErrorKind::TimedOut,
                    format!("dns lookup for {host} exceeded {timeout_ms} ms"),
                ))
            })
    };
    let (kind, msg) = match outcome {
        Ok(addrs) => return Ok(addrs),
        Err(e) => e,
    };
    LOOKUP_FAILURES.fetch_add(1, Relaxed);
    // Fresh answers are always recorded (by the lookup task), so turning serving off and on
    // again can never surface an answer older than one seen meanwhile.
    if stale_secs > 0 {
        if let Some(addrs) = cache.get(host, stale_secs) {
            STALE_SERVED.fetch_add(1, Relaxed);
            return Ok(addrs);
        }
    }
    Err(io::Error::new(kind, msg))
}

fn now_s() -> u64 {
    crate::breaker::now_ms() / 1000
}

/// The connector's resolver: the system resolver behind [`resolve_with`].
#[derive(Clone, Default)]
pub struct StaleOnErrorResolver;

impl tower_service::Service<Name> for StaleOnErrorResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        Box::pin(async move {
            let host = name.as_str().to_string();
            let real = async {
                let mut gai = GaiResolver::new();
                let addrs = tower_service::Service::call(&mut gai, name).await?;
                Ok(addrs.collect::<Vec<_>>())
            };
            resolve_with(
                &CACHE,
                &host,
                STALE_SECS.load(Relaxed),
                TIMEOUT_MS.load(Relaxed),
                real,
            )
            .await
            .map(Vec::into_iter)
        })
    }
}

/// `TcpStream::connect` for a `host:port` string, resolving through the same cache.
pub async fn connect_tcp(target: &str) -> io::Result<tokio::net::TcpStream> {
    let (host, port) = target
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h.trim_matches(['[', ']']), p.parse::<u16>().ok()?)))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected host:port"))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return tokio::net::TcpStream::connect(SocketAddr::new(ip, port)).await;
    }
    let name = host.to_string();
    let real = async move {
        Ok(tokio::net::lookup_host((name.as_str(), port))
            .await?
            .collect::<Vec<_>>())
    };
    let addrs = resolve_with(
        &CACHE,
        host,
        STALE_SECS.load(Relaxed),
        TIMEOUT_MS.load(Relaxed),
        real,
    )
    .await?;
    let mut last = None;
    for mut a in addrs {
        a.set_port(port); // keeps an IPv6 scope id
        match tokio::net::TcpStream::connect(a).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// A cache with a clock the test moves by hand.
    fn cache() -> (LastGood, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(100));
        let t2 = t.clone();
        (LastGood::with_clock(move || t2.load(Relaxed)), t)
    }
    fn addrs(ips: &[&str]) -> Vec<SocketAddr> {
        ips.iter()
            .map(|i| SocketAddr::new(i.parse().unwrap(), 0))
            .collect()
    }
    async fn down() -> io::Result<Vec<SocketAddr>> {
        Err(io::Error::other("SERVFAIL"))
    }
    async fn up(ips: &'static [&'static str]) -> io::Result<Vec<SocketAddr>> {
        Ok(addrs(ips))
    }
    async fn hung() -> io::Result<Vec<SocketAddr>> {
        std::future::pending::<()>().await;
        Ok(Vec::new())
    }

    #[tokio::test]
    async fn a_fresh_answer_wins_and_is_remembered() {
        let (c, _) = cache();
        let r = resolve_with(&c, "a.test", 3600, 1000, up(&["10.0.0.1"])).await;
        assert_eq!(r.unwrap(), addrs(&["10.0.0.1"]));
        // the address changed: the next connection sees the new one, not the cached one
        let r = resolve_with(&c, "a.test", 3600, 1000, up(&["10.0.0.2"])).await;
        assert_eq!(r.unwrap(), addrs(&["10.0.0.2"]));
    }

    #[tokio::test]
    async fn a_failed_lookup_is_answered_from_the_last_good_one() {
        let (c, t) = cache();
        resolve_with(&c, "a.test", 3600, 1000, up(&["10.0.0.1", "10.0.0.2"]))
            .await
            .unwrap();
        t.store(100 + 3000, Relaxed);
        let before = STALE_SERVED.load(Relaxed);
        let r = resolve_with(&c, "a.test", 3600, 1000, down()).await;
        assert_eq!(r.unwrap(), addrs(&["10.0.0.1", "10.0.0.2"]));
        assert!(STALE_SERVED.load(Relaxed) > before);
    }

    #[tokio::test]
    async fn an_empty_answer_counts_as_a_failure() {
        let (c, _) = cache();
        resolve_with(&c, "a.test", 60, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        let empty = async { Ok(Vec::new()) };
        let r = resolve_with(&c, "a.test", 60, 1000, empty).await;
        assert_eq!(r.unwrap(), addrs(&["10.0.0.1"]));
    }

    #[tokio::test]
    async fn the_stale_answer_expires() {
        let (c, t) = cache();
        resolve_with(&c, "a.test", 60, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        t.store(100 + 60, Relaxed);
        assert!(resolve_with(&c, "a.test", 60, 1000, down()).await.is_ok());
        t.store(100 + 61, Relaxed);
        let e = resolve_with(&c, "a.test", 60, 1000, down())
            .await
            .unwrap_err();
        assert!(
            e.to_string().contains("SERVFAIL"),
            "the real error surfaces: {e}"
        );
    }

    #[tokio::test]
    async fn a_host_never_resolved_has_nothing_to_fall_back_to() {
        let (c, _) = cache();
        assert!(resolve_with(&c, "never.test", 3600, 1000, down())
            .await
            .is_err());
        // and one host's answer is never served for another
        resolve_with(&c, "a.test", 3600, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        assert!(resolve_with(&c, "b.test", 3600, 1000, down())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn stale_secs_zero_serves_nothing_stale() {
        let (c, _) = cache();
        resolve_with(&c, "a.test", 0, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        assert!(resolve_with(&c, "a.test", 0, 1000, down()).await.is_err());
    }

    #[tokio::test]
    async fn disabling_then_re_enabling_never_serves_an_answer_older_than_one_seen_meanwhile() {
        let (c, t) = cache();
        resolve_with(&c, "a.test", 3600, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        // serving is turned off; the address changes and the new one is observed
        t.store(200, Relaxed);
        resolve_with(&c, "a.test", 0, 1000, up(&["10.0.0.2"]))
            .await
            .unwrap();
        // serving is turned back on, and the next lookup fails
        let r = resolve_with(&c, "a.test", 3600, 1000, down()).await;
        assert_eq!(
            r.unwrap(),
            addrs(&["10.0.0.2"]),
            "the newest answer, not the pre-disable one"
        );
    }

    #[tokio::test]
    async fn a_hung_lookup_is_cut_off_and_served_from_cache() {
        let (c, _) = cache();
        resolve_with(&c, "a.test", 3600, 50, up(&["10.0.0.1"]))
            .await
            .unwrap();
        let r = resolve_with(&c, "a.test", 3600, 50, hung()).await;
        assert_eq!(
            r.unwrap(),
            addrs(&["10.0.0.1"]),
            "the deadline fires, cache answers"
        );
        // without a cached answer the deadline is the error
        let e = resolve_with(&c, "cold.test", 3600, 50, hung())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_resolver_outage_starts_one_lookup_per_host_not_one_per_connection() {
        let (c, _) = cache();
        resolve_with(&c, "a.test", 3600, 50, up(&["10.0.0.1"]))
            .await
            .unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        // a lookup that takes far longer than the deadline, as a blocked getaddrinfo does
        let slow = |n: Arc<AtomicUsize>| async move {
            n.fetch_add(1, Relaxed);
            tokio::time::sleep(Duration::from_millis(400)).await;
            Ok(addrs(&["10.0.0.9"]))
        };
        let results = futures_like_join((0..20).map(|_| {
            let (c, st) = (c.clone(), started.clone());
            async move { resolve_with(&c, "a.test", 3600, 50, slow(st)).await }
        }))
        .await;
        assert!(results
            .iter()
            .all(|r| r.as_ref().unwrap() == &addrs(&["10.0.0.1"])));
        assert_eq!(started.load(Relaxed), 1, "20 connections, one lookup");
        // the late answer was recorded, and a later connection starts a fresh lookup again
        tokio::time::sleep(Duration::from_millis(450)).await;
        assert_eq!(c.get("a.test", 3600).unwrap(), addrs(&["10.0.0.9"]));
        resolve_with(&c, "a.test", 3600, 50, slow(started.clone()))
            .await
            .unwrap();
        assert_eq!(started.load(Relaxed), 2);
    }

    /// Poll the futures together without pulling in a `futures` dependency.
    async fn futures_like_join<F: Future + Send + 'static>(
        futs: impl Iterator<Item = F>,
    ) -> Vec<F::Output>
    where
        F::Output: Send + 'static,
    {
        let handles: Vec<_> = futs.map(tokio::spawn).collect();
        let mut out = Vec::new();
        for h in handles {
            out.push(h.await.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn an_ipv6_scope_survives_the_stale_fallback() {
        let (c, _) = cache();
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            0,
            7,
            3,
        ));
        let a = async move { Ok(vec![scoped]) };
        resolve_with(&c, "ll.test", 3600, 1000, a).await.unwrap();
        let r = resolve_with(&c, "ll.test", 3600, 1000, down())
            .await
            .unwrap();
        let SocketAddr::V6(v6) = r[0] else {
            panic!("v6 expected")
        };
        assert_eq!(
            (v6.scope_id(), v6.flowinfo()),
            (3, 7),
            "scope id and flow info kept"
        );
    }

    #[tokio::test]
    async fn connect_tcp_resolves_localhost_and_rejects_garbage() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let target = format!("localhost:{port}");
        let (c, _) = tokio::join!(connect_tcp(&target), l.accept());
        assert!(c.is_ok());
        assert!(connect_tcp("no-port").await.is_err());
        let literal = format!("127.0.0.1:{port}");
        let (c, _) = tokio::join!(connect_tcp(&literal), l.accept());
        assert!(c.is_ok(), "an IP literal needs no lookup");
    }

    /// The real pooled client, a name that can never resolve (`.invalid`, RFC 6761), and a
    /// seeded last-good answer: the request must reach the origin through the stale address.
    #[tokio::test]
    async fn the_pooled_client_connects_through_a_stale_answer_when_the_name_does_not_resolve() {
        use http_body_util::{BodyExt, Full};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        let host = "origin.stale-dns-test.invalid";
        let uri = format!("http://{host}:{port}/");
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = crate::proxy::build_http_client(2000, false);
        let req = || {
            hyper::Request::get(&uri)
                .body(
                    Full::new(bytes::Bytes::new())
                        .map_err(|n| match n {})
                        .boxed(),
                )
                .unwrap()
        };
        // nothing cached yet: the failure is real
        assert!(
            client.request(req()).await.is_err(),
            "no stale answer to use yet"
        );
        CACHE.put(host, &addrs(&["127.0.0.1"]));
        let resp = client
            .request(req())
            .await
            .expect("served through the last good answer");
        assert_eq!(resp.status(), 200);
    }
}
