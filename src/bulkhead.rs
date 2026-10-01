// SPDX-License-Identifier: Apache-2.0
//! Per-upstream concurrency cap (`[upstream.x] max_in_flight`).
//!
//! A slow or overloaded backend turns every extra request into one more connection, one more
//! buffered body and one more waiting task, until the proxy itself is the thing that falls over.
//! A bulkhead bounds that: at most `max_in_flight` requests are inside one upstream at a time,
//! and the next one is answered at once with `503` + `Retry-After` instead of piling on.
//!
//! The counter is per `[upstream.x]` table (the whole pool, not one member), lives in a
//! process-wide registry keyed by the upstream's name so a reload keeps the true count, and the
//! *limit* is read from the live config snapshot on every request, so a reload takes effect
//! immediately and a rejected reload changes nothing. A request holds its slot until its
//! response body has been sent (or dropped): the upstream is busy until then.

use bytes::Bytes;
use dashmap::DashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

/// One upstream's live state.
#[derive(Debug, Default)]
pub struct Counter {
    in_flight: AtomicU32,
    shed: AtomicU64,
    /// The limit last applied (for the metric only).
    limit: AtomicU32,
}

static REGISTRY: LazyLock<DashMap<Arc<str>, Arc<Counter>>> = LazyLock::new(DashMap::new);

/// The counter for upstream `name`, created on first use.
pub fn counter(name: &str) -> Arc<Counter> {
    if let Some(c) = REGISTRY.get(name) {
        return c.clone();
    }
    REGISTRY.entry(Arc::from(name)).or_default().clone()
}

impl Counter {
    /// Take a slot if fewer than `limit` are in use. Never blocks.
    pub fn try_acquire(self: &Arc<Self>, limit: u32) -> Option<Permit> {
        self.limit.store(limit, Relaxed);
        let mut cur = self.in_flight.load(Relaxed);
        loop {
            if cur >= limit {
                self.shed.fetch_add(1, Relaxed);
                return None;
            }
            match self
                .in_flight
                .compare_exchange_weak(cur, cur + 1, Relaxed, Relaxed)
            {
                Ok(_) => return Some(Permit(self.clone())),
                Err(seen) => cur = seen,
            }
        }
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Relaxed)
    }

    pub fn shed(&self) -> u64 {
        self.shed.load(Relaxed)
    }
}

/// A slot; dropping it frees it.
#[derive(Debug)]
pub struct Permit(Arc<Counter>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Relaxed);
    }
}

/// A response body that keeps its slot until it ends or is dropped.
pub struct PermitBody {
    inner: crate::proxy::ZionBody,
    permit: Option<Permit>,
}

impl hyper::body::Body for PermitBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        let r = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(r, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.permit = None; // done: free the slot now, not when hyper drops the body
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Make `resp` hold `permit` until its body is finished.
pub fn attach(
    resp: hyper::Response<crate::proxy::ZionBody>,
    permit: Permit,
) -> hyper::Response<crate::proxy::ZionBody> {
    use http_body_util::BodyExt as _;
    use hyper::body::Body as _;
    let (parts, inner) = resp.into_parts();
    // an empty body is already finished: nothing to wait for
    if inner.is_end_stream() {
        return hyper::Response::from_parts(parts, inner);
    }
    let body = PermitBody {
        inner,
        permit: Some(permit),
    };
    hyper::Response::from_parts(parts, body.boxed())
}

/// Prometheus series for every upstream that has been used.
pub fn render(out: &mut String, escape: &dyn Fn(&str) -> String) {
    if REGISTRY.is_empty() {
        return;
    }
    let mut rows: Vec<(Arc<str>, Arc<Counter>)> = REGISTRY
        .iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, help, kind, val) in [
        (
            "zion_bulkhead_in_flight",
            "Requests currently inside this upstream (see [upstream.x] max_in_flight).",
            "gauge",
            (|c: &Counter| u64::from(c.in_flight())) as fn(&Counter) -> u64,
        ),
        (
            "zion_bulkhead_limit",
            "The max_in_flight last applied to this upstream (0 = never limited).",
            "gauge",
            |c: &Counter| u64::from(c.limit.load(Relaxed)),
        ),
        (
            "zion_bulkhead_shed_total",
            "Requests refused with 503 because the upstream was at max_in_flight.",
            "counter",
            Counter::shed,
        ),
    ] {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for (upstream, c) in &rows {
            out.push_str(&format!(
                "{name}{{upstream=\"{}\"}} {}\n",
                escape(upstream),
                val(c)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    fn fresh(name: &str) -> Arc<Counter> {
        let c = counter(name);
        c.in_flight.store(0, Relaxed);
        c.shed.store(0, Relaxed);
        c
    }

    #[test]
    fn at_most_limit_permits_and_the_next_is_refused_and_counted() {
        let c = fresh("t-limit");
        let a = c.try_acquire(2).unwrap();
        let _b = c.try_acquire(2).unwrap();
        assert!(c.try_acquire(2).is_none());
        assert_eq!((c.in_flight(), c.shed()), (2, 1));
        drop(a);
        assert_eq!(c.in_flight(), 1);
        assert!(c.try_acquire(2).is_some(), "a freed slot is reusable");
    }

    #[test]
    fn the_limit_is_read_at_every_acquire_so_a_reload_takes_effect_at_once() {
        let c = fresh("t-reload");
        let held: Vec<_> = (0..5).map(|_| c.try_acquire(5).unwrap()).collect();
        assert!(c.try_acquire(5).is_none());
        assert!(c.try_acquire(8).is_some(), "limit raised");
        assert!(
            c.try_acquire(3).is_none(),
            "limit lowered below the current count: no new entry"
        );
        drop(held);
    }

    #[test]
    fn concurrent_acquires_never_exceed_the_limit() {
        let c = fresh("t-race");
        let peak = AtomicU32::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..5_000 {
                        if let Some(p) = c.try_acquire(3) {
                            peak.fetch_max(c.in_flight(), Relaxed);
                            drop(p);
                        }
                    }
                });
            }
        });
        assert!(peak.load(Relaxed) <= 3, "peak {}", peak.load(Relaxed));
        assert_eq!(c.in_flight(), 0, "every permit was returned");
    }

    #[tokio::test]
    async fn the_slot_is_held_until_the_body_is_finished() {
        let c = fresh("t-body");
        let permit = c.try_acquire(1).unwrap();
        let body = Full::new(Bytes::from_static(b"hello"))
            .map_err(|n| match n {})
            .boxed();
        let resp = attach(hyper::Response::new(body), permit);
        assert_eq!(c.in_flight(), 1, "response built, body not read yet");
        let mut body = resp.into_body();
        let _ = body.frame().await; // data frame
        assert_eq!(c.in_flight(), 1, "still streaming");
        assert!(body.frame().await.is_none()); // end
        assert_eq!(c.in_flight(), 0, "freed when the body ends");
    }

    #[tokio::test]
    async fn a_body_dropped_early_frees_its_slot() {
        let c = fresh("t-drop");
        let permit = c.try_acquire(1).unwrap();
        let body = Full::new(Bytes::from_static(b"hello"))
            .map_err(|n| match n {})
            .boxed();
        let resp = attach(hyper::Response::new(body), permit);
        assert_eq!(c.in_flight(), 1);
        drop(resp); // the client went away
        assert_eq!(c.in_flight(), 0);
    }

    #[test]
    fn the_metrics_list_every_used_upstream() {
        let c = fresh("t-metrics");
        let _p = c.try_acquire(4).unwrap();
        let mut out = String::new();
        render(&mut out, &|s| s.to_string());
        assert!(
            out.contains("zion_bulkhead_in_flight{upstream=\"t-metrics\"} 1"),
            "{out}"
        );
        assert!(out.contains("zion_bulkhead_limit{upstream=\"t-metrics\"} 4"));
        assert!(out.contains("# TYPE zion_bulkhead_shed_total counter"));
    }
}
