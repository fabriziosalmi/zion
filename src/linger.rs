// SPDX-License-Identifier: Apache-2.0
//! Lingering close for HTTP/1.1: a client still sending a body when zion answers gets the answer.
//!
//! When zion answers before reading the whole request body (a `413` past `max_body_mb`, a `401`
//! to an upload), hyper stops reading and closes the connection once the response is written. The
//! client is still sending; the bytes it sends after the close meet a closed socket, the kernel
//! answers with a reset, and the reset can reach the client before it has read the response: it
//! sees a broken pipe instead of the `413`. nginx (`lingering_close`) and Go's server avoid this
//! by reading, and dropping, what the client still sends for a while after the response.
//!
//! Two parts:
//!
//! * [`ArmOnUnreadBody`] wraps each request body and arms the connection's [`Linger`] when the
//!   body is dropped before its end, which is the only case where unread bytes are on the way.
//! * [`Linger`] wraps the connection. When hyper shuts it down and it is armed, it completes the
//!   shutdown (the response and the end of the stream reach the client), then reads and drops
//!   whatever the client sends until the client closes, [`IDLE`] passes with no byte, or
//!   [`TOTAL`] in all. A connection that was not armed closes as before, at once, so an idle
//!   keep-alive close or a graceful shutdown is not delayed.

use hyper::body::{Body, Frame, SizeHint};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// With no byte from the client for this long, the lingering ends.
pub const IDLE: Duration = Duration::from_secs(2);
/// The lingering ends after this long in any case.
pub const TOTAL: Duration = Duration::from_secs(10);

/// Shared by a connection's [`Linger`] and the [`ArmOnUnreadBody`] of each of its requests.
#[derive(Clone, Debug, Default)]
pub struct Armed(Arc<AtomicBool>);

impl Armed {
    fn arm(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_armed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// A request body that arms its connection's lingering close if it is dropped before its end.
pub struct ArmOnUnreadBody<B> {
    inner: B,
    armed: Armed,
    ended: bool,
}

impl<B: Body> ArmOnUnreadBody<B> {
    pub fn new(inner: B, armed: Armed) -> Self {
        let ended = inner.is_end_stream();
        Self {
            inner,
            armed,
            ended,
        }
    }
}

impl<B> Drop for ArmOnUnreadBody<B> {
    fn drop(&mut self) {
        if !self.ended {
            self.armed.arm();
        }
    }
}

impl<B: Body + Unpin> Body for ArmOnUnreadBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            // The body broke: hyper is done with the connection's reading either way.
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => this.ended = true,
            Poll::Ready(Some(Ok(_))) => this.ended = this.inner.is_end_stream(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A connection that, armed, reads and drops what the client still sends after hyper shuts it
/// down (see the module docs).
pub struct Linger<IO> {
    inner: IO,
    armed: Armed,
    state: State,
}

enum State {
    Open,
    Draining {
        idle: Pin<Box<tokio::time::Sleep>>,
        total: Pin<Box<tokio::time::Sleep>>,
    },
    Closed,
}

impl<IO> Linger<IO> {
    pub fn new(inner: IO, armed: Armed) -> Self {
        Self {
            inner,
            armed,
            state: State::Open,
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Linger<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Linger<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.state {
                State::Open => {
                    match Pin::new(&mut this.inner).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {}
                        other => return other,
                    }
                    if !this.armed.is_armed() {
                        this.state = State::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    this.state = State::Draining {
                        idle: Box::pin(tokio::time::sleep(IDLE)),
                        total: Box::pin(tokio::time::sleep(TOTAL)),
                    };
                }
                State::Draining { idle, total } => {
                    if total.as_mut().poll(cx).is_ready() {
                        this.state = State::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    let mut scratch = [0u8; 8192];
                    let mut buf = ReadBuf::new(&mut scratch);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                        // a byte arrived: wait for the next one
                        Poll::Ready(Ok(())) if !buf.filled().is_empty() => {
                            idle.as_mut().reset(tokio::time::Instant::now() + IDLE);
                        }
                        // the client closed, or the connection broke: nothing left to wait for
                        Poll::Ready(_) => {
                            this.state = State::Closed;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Pending => {
                            if idle.as_mut().poll(cx).is_ready() {
                                this.state = State::Closed;
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Pending;
                        }
                    }
                }
                State::Closed => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full, StreamBody};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn unread_body() -> impl Body<Data = Bytes, Error = std::convert::Infallible> + Unpin {
        StreamBody::new(tokio_stream::iter(vec![
            Ok(Frame::data(Bytes::from_static(b"ab"))),
            Ok(Frame::data(Bytes::from_static(b"cd"))),
        ]))
    }

    #[tokio::test]
    async fn a_body_dropped_before_its_end_arms_the_connection() {
        let armed = Armed::default();
        let mut body = ArmOnUnreadBody::new(unread_body(), armed.clone());
        let _ = body.frame().await;
        drop(body);
        assert!(armed.is_armed());
    }

    #[tokio::test]
    async fn a_body_read_to_its_end_or_empty_does_not() {
        let armed = Armed::default();
        let body = ArmOnUnreadBody::new(unread_body(), armed.clone());
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 4);
        assert!(!armed.is_armed());
        // a GET: nothing to read, nothing unread
        drop(ArmOnUnreadBody::new(Full::new(Bytes::new()), armed.clone()));
        assert!(!armed.is_armed());
    }

    /// The server side of a socket pair wrapped in `Linger`, and the client side.
    async fn pair(armed: &Armed) -> (Linger<tokio::net::TcpStream>, tokio::net::TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(l.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = l.accept().await.unwrap();
        (Linger::new(server, armed.clone()), client)
    }

    #[tokio::test]
    async fn not_armed_it_closes_at_once() {
        let (mut server, _client) = pair(&Armed::default()).await;
        let t = std::time::Instant::now();
        server.shutdown().await.unwrap();
        assert!(t.elapsed() < Duration::from_millis(500));
    }

    #[tokio::test]
    async fn armed_it_reads_until_the_client_closes() {
        let armed = Armed::default();
        armed.arm();
        let (mut server, mut client) = pair(&armed).await;
        server.write_all(b"HTTP/1.1 413\r\n\r\n").await.unwrap();
        let shut = tokio::spawn(async move {
            let t = std::time::Instant::now();
            server.shutdown().await.unwrap();
            t.elapsed()
        });
        // the client is still sending, then reads the answer and closes
        client.write_all(&[0u8; 65536]).await.unwrap();
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.unwrap();
        assert_eq!(answer, b"HTTP/1.1 413\r\n\r\n");
        drop(client);
        let took = shut.await.unwrap();
        assert!(took < IDLE, "it waited {took:?} after the client closed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_keeps_sending_is_cut_off_at_the_total_time() {
        let armed = Armed::default();
        armed.arm();
        let (mut server, mut client) = pair(&armed).await;
        tokio::spawn(async move {
            // a byte a second: never idle for IDLE, never done
            while client.write_all(b"x").await.is_ok() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let t = tokio::time::Instant::now();
        server.shutdown().await.unwrap();
        let took = t.elapsed();
        assert!(took >= TOTAL && took < TOTAL + IDLE, "{took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn armed_it_gives_up_after_the_idle_time() {
        let armed = Armed::default();
        armed.arm();
        let (mut server, _client) = pair(&armed).await;
        let t = tokio::time::Instant::now();
        server.shutdown().await.unwrap();
        assert_eq!(t.elapsed(), IDLE);
    }
}
