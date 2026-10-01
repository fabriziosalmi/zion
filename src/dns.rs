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

/// Last good answers, by host name.
#[derive(Default)]
pub struct LastGood {
    entries: Mutex<HashMap<String, (Vec<IpAddr>, u64)>>,
}

static CACHE: std::sync::LazyLock<LastGood> = std::sync::LazyLock::new(LastGood::default);

impl LastGood {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Vec<IpAddr>, u64)>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn put(&self, host: &str, addrs: &[SocketAddr], now_s: u64) {
        let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
        let mut m = self.lock();
        if m.len() >= MAX_ENTRIES && !m.contains_key(host) {
            m.clear();
        }
        m.insert(host.to_string(), (ips, now_s));
    }

    fn get(&self, host: &str, now_s: u64, max_age_s: u64) -> Option<Vec<IpAddr>> {
        let m = self.lock();
        let (ips, at) = m.get(host)?;
        (now_s.saturating_sub(*at) <= max_age_s && !ips.is_empty()).then(|| ips.clone())
    }
}

/// Resolve `host` with `lookup`, falling back to the last good answer (see the module docs).
/// Resolvers report port 0; the connector sets the real port.
pub async fn resolve_with<F, N>(
    cache: &LastGood,
    host: &str,
    now_s: N,
    stale_secs: u64,
    timeout_ms: u64,
    lookup: F,
) -> io::Result<Vec<SocketAddr>>
where
    F: Future<Output = io::Result<Vec<SocketAddr>>>,
    N: Fn() -> u64,
{
    let fresh = if timeout_ms == 0 {
        lookup.await
    } else {
        match tokio::time::timeout(Duration::from_millis(timeout_ms), lookup).await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dns lookup for {host} exceeded {timeout_ms} ms"),
            )),
        }
    };
    let err = match fresh {
        Ok(addrs) if !addrs.is_empty() => {
            if stale_secs > 0 {
                cache.put(host, &addrs, now_s());
            }
            return Ok(addrs);
        }
        Ok(_) => io::Error::new(io::ErrorKind::NotFound, format!("no addresses for {host}")),
        Err(e) => e,
    };
    LOOKUP_FAILURES.fetch_add(1, Relaxed);
    if stale_secs > 0 {
        if let Some(ips) = cache.get(host, now_s(), stale_secs) {
            STALE_SERVED.fetch_add(1, Relaxed);
            return Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect());
        }
    }
    Err(err)
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
                &now_s,
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
    let real = async {
        Ok(tokio::net::lookup_host((host, port))
            .await?
            .collect::<Vec<_>>())
    };
    let addrs = resolve_with(
        &CACHE,
        host,
        &now_s,
        STALE_SECS.load(Relaxed),
        TIMEOUT_MS.load(Relaxed),
        real,
    )
    .await?;
    let mut last = None;
    for a in addrs {
        match tokio::net::TcpStream::connect(SocketAddr::new(a.ip(), port)).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

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

    #[tokio::test]
    async fn a_fresh_answer_wins_and_is_remembered() {
        let c = LastGood::default();
        let t = Cell::new(100);
        let now = || t.get();
        let r = resolve_with(&c, "a.test", &now, 3600, 1000, up(&["10.0.0.1"])).await;
        assert_eq!(r.unwrap(), addrs(&["10.0.0.1"]));
        // the address changed: the next connection sees the new one, not the cached one
        let r = resolve_with(&c, "a.test", &now, 3600, 1000, up(&["10.0.0.2"])).await;
        assert_eq!(r.unwrap(), addrs(&["10.0.0.2"]));
    }

    #[tokio::test]
    async fn a_failed_lookup_is_answered_from_the_last_good_one() {
        let c = LastGood::default();
        let t = Cell::new(100);
        let now = || t.get();
        resolve_with(
            &c,
            "a.test",
            &now,
            3600,
            1000,
            up(&["10.0.0.1", "10.0.0.2"]),
        )
        .await
        .unwrap();
        t.set(100 + 3000);
        let before = STALE_SERVED.load(Relaxed);
        let r = resolve_with(&c, "a.test", &now, 3600, 1000, down()).await;
        assert_eq!(r.unwrap(), addrs(&["10.0.0.1", "10.0.0.2"]));
        assert!(STALE_SERVED.load(Relaxed) > before);
    }

    #[tokio::test]
    async fn an_empty_answer_counts_as_a_failure() {
        let c = LastGood::default();
        let t = Cell::new(1);
        let now = || t.get();
        resolve_with(&c, "a.test", &now, 60, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        let empty = async { Ok(Vec::new()) };
        let r = resolve_with(&c, "a.test", &now, 60, 1000, empty).await;
        assert_eq!(r.unwrap(), addrs(&["10.0.0.1"]));
    }

    #[tokio::test]
    async fn the_stale_answer_expires() {
        let c = LastGood::default();
        let t = Cell::new(100);
        let now = || t.get();
        resolve_with(&c, "a.test", &now, 60, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        t.set(100 + 60);
        assert!(resolve_with(&c, "a.test", &now, 60, 1000, down())
            .await
            .is_ok());
        t.set(100 + 61);
        let e = resolve_with(&c, "a.test", &now, 60, 1000, down())
            .await
            .unwrap_err();
        assert!(
            e.to_string().contains("SERVFAIL"),
            "the real error surfaces: {e}"
        );
    }

    #[tokio::test]
    async fn a_host_never_resolved_has_nothing_to_fall_back_to() {
        let c = LastGood::default();
        let now = || 5;
        assert!(resolve_with(&c, "never.test", &now, 3600, 1000, down())
            .await
            .is_err());
        // and one host's answer is never served for another
        resolve_with(&c, "a.test", &now, 3600, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        assert!(resolve_with(&c, "b.test", &now, 3600, 1000, down())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn stale_secs_zero_turns_the_cache_off() {
        let c = LastGood::default();
        let now = || 5;
        resolve_with(&c, "a.test", &now, 0, 1000, up(&["10.0.0.1"]))
            .await
            .unwrap();
        assert!(resolve_with(&c, "a.test", &now, 0, 1000, down())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_hung_lookup_is_cut_off_and_served_from_cache() {
        let c = LastGood::default();
        let now = || 5;
        resolve_with(&c, "a.test", &now, 3600, 50, up(&["10.0.0.1"]))
            .await
            .unwrap();
        let hung = async {
            std::future::pending::<()>().await;
            Ok(Vec::new())
        };
        let r = resolve_with(&c, "a.test", &now, 3600, 50, hung).await;
        assert_eq!(
            r.unwrap(),
            addrs(&["10.0.0.1"]),
            "the deadline fires, cache answers"
        );
        // without a cached answer the deadline is the error
        let hung = async {
            std::future::pending::<()>().await;
            Ok(Vec::new())
        };
        let e = resolve_with(&c, "cold.test", &now, 3600, 50, hung)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
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
        let client = crate::proxy::build_http_client(2000);
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
        CACHE.put(host, &addrs(&["127.0.0.1"]), now_s());
        let resp = client
            .request(req())
            .await
            .expect("served through the last good answer");
        assert_eq!(resp.status(), 200);
    }
}
