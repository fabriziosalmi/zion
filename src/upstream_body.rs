// SPDX-License-Identifier: Apache-2.0
//! The request body as it is sent to the upstream, with the route's `max_body_mb` applied to a
//! body of unknown length (#693).
//!
//! A body that declares its length is checked against the cap before it is read (see
//! `dispatch::body_gate`), and hyper already holds it to the length it declared. A chunked
//! HTTP/1.1 body, or an HTTP/2 or HTTP/3 one without `Content-Length`, is only known by
//! counting. It is streamed to the upstream as it arrives, and the frame that would take it
//! past the cap ends it with an error: the upstream sees an aborted request, never a short body
//! that looks complete. Ending it cleanly instead would close the chunked framing and hand the
//! upstream a truncated body as a whole one.
//!
//! The error is a [`BodyTooLarge`], which a request body can carry because its error type is
//! zion's (`http_util::ReqBody`), not hyper's.
//!
//! A body the client breaks on the way (it goes away mid-upload) is the client's fault too.
//! [`BodyFault`] tells either case apart from a failed upstream once the upstream client has
//! turned the body's error into its own, so neither becomes a `502` that the circuit breaker
//! counts against a healthy upstream.

use crate::http_util::{BoxError, ReqBody};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

/// The route's body cap, in bytes, for a request whose body has no declared length. The
/// request carries it as an extension from the body gate to the proxy, which applies it when
/// it hands the body to the upstream client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyCap(pub u64);

/// The request body went past the route's `max_body_mb`.
#[derive(Debug)]
pub struct BodyTooLarge;

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body larger than the route's max_body_mb")
    }
}

impl std::error::Error for BodyTooLarge {}

/// What went wrong with a request body on its way to the upstream, if anything, so the caller
/// of the upstream client can tell whose fault a failed request was after the client has turned
/// the body's error into its own: a body past its cap is refused (`413`), a body the client
/// broke is the client's (`400`), and only otherwise did the upstream fail (`502`).
#[derive(Clone, Debug, Default)]
pub struct BodyFault(Arc<AtomicU8>);

// 0, the default, is no fault.
const TOO_LARGE: u8 = 1;
const BROKEN: u8 = 2;

impl BodyFault {
    /// The body went past the route's cap.
    pub fn too_large(&self) -> bool {
        self.0.load(Ordering::Acquire) == TOO_LARGE
    }

    /// The client's body ended with an error of its own: the client reset the stream or the
    /// connection, or stopped mid-body.
    pub fn broken(&self) -> bool {
        self.0.load(Ordering::Acquire) == BROKEN
    }

    fn set(&self, fault: u8) {
        self.0.store(fault, Ordering::Release);
    }
}

/// A request body on its way to the upstream: the body as it came, or the same body watched
/// for a [`BodyFault`] and, given a cap, counted against it.
pub struct UpstreamBody {
    inner: ReqBody,
    /// Bytes still allowed, when the body is capped.
    left: Option<u64>,
    fault: Option<BodyFault>,
}

impl UpstreamBody {
    /// The body as it is, nothing watched: a body zion made itself (a health probe, a cache
    /// refresh).
    pub fn plain(inner: ReqBody) -> Self {
        Self {
            inner,
            left: None,
            fault: None,
        }
    }

    /// The client's body, counted against `cap` bytes when there is one. The returned
    /// [`BodyFault`] reports whether it went past them or the client broke it.
    pub fn watched(inner: ReqBody, cap: Option<u64>) -> (Self, BodyFault) {
        let fault = BodyFault::default();
        let body = Self {
            inner,
            left: cap,
            fault: Some(fault.clone()),
        };
        (body, fault)
    }

    /// The body counted against `limit` bytes.
    pub fn capped(inner: ReqBody, limit: u64) -> (Self, BodyFault) {
        Self::watched(inner, Some(limit))
    }
}

/// Read a request body whole, at most `limit` bytes; past them the error is [`BodyTooLarge`].
///
/// `http_body_util::Limited` does the same, but over a body whose error is already a boxed
/// `dyn Error` rustc cannot prove its `collect` future `Send` (a limit of its higher-ranked
/// lifetime inference), and every future of the request pipeline must be `Send`.
pub async fn read_capped(body: ReqBody, limit: u64) -> Result<Bytes, BoxError> {
    let (body, _) = UpstreamBody::capped(body, limit);
    Ok(body.collect().await?.to_bytes())
}

impl From<ReqBody> for UpstreamBody {
    fn from(inner: ReqBody) -> Self {
        Self::plain(inner)
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => {
                if let Some(fault) = &this.fault {
                    fault.set(BROKEN);
                }
                return Poll::Ready(Some(Err(e)));
            }
            Poll::Ready(Some(Ok(frame))) => frame,
        };
        if let (Some(left), Some(data)) = (this.left.as_mut(), frame.data_ref()) {
            let len = data.len() as u64;
            if len > *left {
                if let Some(fault) = &this.fault {
                    fault.set(TOO_LARGE);
                }
                return Poll::Ready(Some(Err(Box::new(BodyTooLarge))));
            }
            *left -= len;
        }
        Poll::Ready(Some(Ok(frame)))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full, StreamBody};

    /// A body of unknown length made of these frames, like a chunked upload.
    fn chunked(frames: &[&'static [u8]]) -> ReqBody {
        let frames: Vec<Result<Frame<Bytes>, BoxError>> = frames
            .iter()
            .map(|f| Ok(Frame::data(Bytes::from_static(f))))
            .collect();
        StreamBody::new(tokio_stream::iter(frames)).boxed()
    }

    #[tokio::test]
    async fn a_body_at_the_cap_goes_through_whole() {
        let (body, fault) = UpstreamBody::capped(chunked(&[b"abcd", b"efgh"]), 8);
        let got = body.collect().await.expect("within the cap").to_bytes();
        assert_eq!(&got[..], b"abcdefgh");
        assert!(!fault.too_large());
    }

    #[tokio::test]
    async fn the_frame_past_the_cap_ends_the_body_with_an_error() {
        let (mut body, fault) = UpstreamBody::capped(chunked(&[b"abcd", b"efgh", b"i"]), 8);
        let mut sent = 0;
        let err = loop {
            match body.frame().await {
                Some(Ok(f)) => sent += f.into_data().map(|d| d.len()).unwrap_or(0),
                Some(Err(e)) => break e,
                None => panic!("a body past its cap must not end cleanly"),
            }
        };
        assert_eq!(sent, 8, "no byte past the cap is handed on");
        assert!(err.is::<BodyTooLarge>());
        assert!(fault.too_large());
    }

    #[tokio::test]
    async fn one_frame_larger_than_the_cap_is_refused_whole() {
        let (mut body, fault) = UpstreamBody::capped(chunked(&[b"0123456789"]), 4);
        assert!(body.frame().await.unwrap().is_err());
        assert!(fault.too_large());
    }

    /// A body that ends with an error of its own, after one frame: what the client's body looks
    /// like when the client resets mid-upload.
    fn broken_after(frame: &'static [u8]) -> ReqBody {
        let frames: Vec<Result<Frame<Bytes>, BoxError>> = vec![
            Ok(Frame::data(Bytes::from_static(frame))),
            Err("connection reset".into()),
        ];
        StreamBody::new(tokio_stream::iter(frames)).boxed()
    }

    #[tokio::test]
    async fn a_body_the_client_breaks_is_reported_broken_not_too_large() {
        for cap in [None, Some(1024)] {
            let (body, fault) = UpstreamBody::watched(broken_after(b"abcd"), cap);
            assert!(body.collect().await.is_err());
            assert!(fault.broken(), "cap {cap:?}");
            assert!(!fault.too_large(), "cap {cap:?}");
        }
    }

    #[tokio::test]
    async fn a_body_that_ends_well_has_no_fault() {
        let (body, fault) = UpstreamBody::watched(chunked(&[b"abcd", b"efgh"]), None);
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 8);
        assert!(!fault.broken() && !fault.too_large());
    }

    #[tokio::test]
    async fn a_body_past_its_cap_is_too_large_not_broken() {
        let (body, fault) = UpstreamBody::capped(chunked(&[b"0123456789"]), 4);
        assert!(body.collect().await.is_err());
        assert!(fault.too_large() && !fault.broken());
    }

    #[tokio::test]
    async fn a_plain_body_has_no_cap() {
        let body = UpstreamBody::plain(chunked(&[b"0123456789"]));
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 10);
    }

    #[test]
    fn the_length_and_the_end_of_the_inner_body_are_kept() {
        let full: ReqBody = Full::new(Bytes::from_static(b"abc"))
            .map_err(|never| match never {})
            .boxed();
        let (body, _) = UpstreamBody::capped(full, 10);
        assert_eq!(body.size_hint().exact(), Some(3));
        let empty: ReqBody = Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed();
        assert!(UpstreamBody::plain(empty).is_end_stream());
    }
}
