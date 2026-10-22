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
//! The error needs a type of its own, since a `hyper::Error` cannot be built outside hyper; that
//! is why the upstream client takes an [`UpstreamBody`] and not a `ZionBody`.

use crate::http_util::ZionBody;
use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

/// The error type of [`UpstreamBody`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

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

/// Set once a capped body has gone past its cap, so the caller of the upstream client can tell
/// a refused body (413) from a failed upstream (502) after the client has turned the body's
/// error into its own.
#[derive(Clone, Debug, Default)]
pub struct Overflow(Arc<AtomicBool>);

impl Overflow {
    pub fn happened(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// A request body on its way to the upstream: the body as it came, or the same body counted
/// against a cap.
pub struct UpstreamBody {
    inner: ZionBody,
    cap: Option<Cap>,
}

struct Cap {
    /// Bytes still allowed.
    left: u64,
    overflow: Overflow,
}

impl UpstreamBody {
    /// The body with no cap: every route without `max_body_mb`, and every body of known length.
    pub fn plain(inner: ZionBody) -> Self {
        Self { inner, cap: None }
    }

    /// The body counted against `limit` bytes. The returned [`Overflow`] reports whether it went
    /// past them.
    pub fn capped(inner: ZionBody, limit: u64) -> (Self, Overflow) {
        let overflow = Overflow::default();
        let body = Self {
            inner,
            cap: Some(Cap {
                left: limit,
                overflow: overflow.clone(),
            }),
        };
        (body, overflow)
    }
}

impl From<ZionBody> for UpstreamBody {
    fn from(inner: ZionBody) -> Self {
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
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(Some(Ok(frame))) => frame,
        };
        if let (Some(cap), Some(data)) = (this.cap.as_mut(), frame.data_ref()) {
            let len = data.len() as u64;
            if len > cap.left {
                cap.overflow.0.store(true, Ordering::Release);
                return Poll::Ready(Some(Err(Box::new(BodyTooLarge))));
            }
            cap.left -= len;
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
    fn chunked(frames: &[&'static [u8]]) -> ZionBody {
        let frames: Vec<Result<Frame<Bytes>, hyper::Error>> = frames
            .iter()
            .map(|f| Ok(Frame::data(Bytes::from_static(f))))
            .collect();
        StreamBody::new(tokio_stream::iter(frames)).boxed()
    }

    #[tokio::test]
    async fn a_body_at_the_cap_goes_through_whole() {
        let (body, overflow) = UpstreamBody::capped(chunked(&[b"abcd", b"efgh"]), 8);
        let got = body.collect().await.expect("within the cap").to_bytes();
        assert_eq!(&got[..], b"abcdefgh");
        assert!(!overflow.happened());
    }

    #[tokio::test]
    async fn the_frame_past_the_cap_ends_the_body_with_an_error() {
        let (mut body, overflow) = UpstreamBody::capped(chunked(&[b"abcd", b"efgh", b"i"]), 8);
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
        assert!(overflow.happened());
    }

    #[tokio::test]
    async fn one_frame_larger_than_the_cap_is_refused_whole() {
        let (mut body, overflow) = UpstreamBody::capped(chunked(&[b"0123456789"]), 4);
        assert!(body.frame().await.unwrap().is_err());
        assert!(overflow.happened());
    }

    #[tokio::test]
    async fn a_plain_body_has_no_cap() {
        let body = UpstreamBody::plain(chunked(&[b"0123456789"]));
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 10);
    }

    #[test]
    fn the_length_and_the_end_of_the_inner_body_are_kept() {
        let full: ZionBody = Full::new(Bytes::from_static(b"abc"))
            .map_err(|never| match never {})
            .boxed();
        let (body, _) = UpstreamBody::capped(full, 10);
        assert_eq!(body.size_hint().exact(), Some(3));
        let empty: ZionBody = Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed();
        assert!(UpstreamBody::plain(empty).is_end_stream());
    }
}
