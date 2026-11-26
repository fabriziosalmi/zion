// SPDX-License-Identifier: Apache-2.0
//! What one HTTP/2 stream may hold while its client does not read.
//!
//! HTTP/2 flow control lets a client stop a response wherever it likes: a stream whose window
//! is zero is sent no more `DATA`, and hyper waits for the window with the next chunk of the
//! body in hand. Nothing in hyper or h2 puts a deadline on that wait. The keep-alive `PING`
//! only asks whether the client is alive, and a client that answers it is. So whatever the
//! response held stayed held for as long as the client kept the connection (up to an hour):
//! on a static route the open file and its read-ahead, on a proxied route an upstream
//! connection. One connection carries 128 streams, so a client that opened them and never
//! their windows held 128 open files on one connection, where the descriptor ceiling is sized
//! for about two (`bootstrap::fd_conn_budget`).
//!
//! Two bounds, both per HTTP/2 connection:
//!
//! - [`Executor`] runs every stream hyper spawns under a deadline. When the response has had a
//!   piece ready for `[server] send_stall_secs` and the client has not opened its window to
//!   take it, the stream is dropped: h2 sends `RST_STREAM(CANCEL)`, and the file, the
//!   read-ahead, the upstream connection and the piece go with it. The time counts from the
//!   last piece the client took, not from the start of the response, so a slow reader is
//!   never cut, only one that takes nothing at all for that long. A body is handed to hyper in
//!   pieces of at most [`SEND_PIECE`] ([`Watched`]): hyper hands a piece to h2 once the window
//!   has room for one byte of it, so a larger chunk (a proxied one, a static file read whole)
//!   would have to be taken whole within the deadline, and its last one would leave the
//!   stream's task with no deadline at all. A static response also ends its stream only once
//!   its last piece has left h2's buffer, so the deadline covers the whole of it.
//! - A static `GET` takes a slot of its connection before its file is opened
//!   (`static_budget::Admission`): one of [`STATIC_FILES_PER_CONN`] when the file is streamed
//!   (it stays open while it is sent), or its length out of [`STATIC_WHOLE_BYTES_PER_CONN`]
//!   when it is read whole. The two are apart so that small files are never kept waiting by
//!   large ones being sent. The slot is held until the file is closed and the last byte of the
//!   response is gone: every piece of the body keeps it ([`Watched`]), and the bytes a body
//!   sends need not be the file's (a compressed body sends bytes of its own). A request that
//!   finds no slot waits for one, holding no file and no buffer. A connection from a
//!   `trusted_proxies` peer carries many clients' requests and has no such slots; every static
//!   response, on every connection, also takes from its client's share of a budget for the
//!   whole process (`static_budget`).
//!
//! hyper polls the service future inside the stream task the executor spawned, so a request
//! handler finds its stream in a task-local ([`enter`]). The QUIC listener runs each HTTP/3
//! request in the same way ([`scope`]), so a QUIC connection has the same slots, and applies
//! the same deadline to its sends itself ([`send_stall`]). HTTP/1.1 requests run in no such
//! task and take no connection slots (an HTTP/1.1 connection sends one response at a time). The
//! requests of one HTTP/1.1 connection share a [`Stream`] of their own ([`http1_stream`]), their
//! bodies are watched the same way, and the connection runs under the same deadline
//! ([`serve_http1`]): HTTP/1.1 cannot reset one response, so the connection is closed.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::Response;
use tokio::sync::Semaphore;
use tokio::time::{Instant, Sleep};

use crate::http_util::ZionBody;
use crate::static_budget::{Need, StaticSlot};

/// The streamed static responses one HTTP/2 connection may hold at once: each keeps its file
/// open while it is sent, so this is the most descriptors a connection holds to files. Each
/// also holds up to `static_budget::STREAMED_HOLD` (768 KiB) of the file in memory while its
/// client does not read. Eight is more than the six connections a browser opens to one host
/// over HTTP/1.1.
pub(crate) const STATIC_FILES_PER_CONN: usize = 8;

/// The bytes of static files read whole (576 KiB or less) that one connection may hold at
/// once: eight of the largest. A small file takes little of it, so the many small files of a
/// page share it, and they never wait for a slot of [`STATIC_FILES_PER_CONN`] (which a larger
/// file takes, whatever range of it is asked for).
pub(crate) const STATIC_WHOLE_BYTES_PER_CONN: u64 = 8 * 576 * 1024;

/// The unit [`STATIC_WHOLE_BYTES_PER_CONN`] is counted in.
const WHOLE_UNIT: u64 = 1024;

/// `[server] send_stall_secs` when it is not set: five minutes, the example the
/// `tcp_user_timeout_secs` documentation gives for the longest pause to accept from a client
/// that stops reading (a paused player with a full buffer).
pub(crate) const DEFAULT_SEND_STALL_SECS: u64 = 300;

/// The most of a response body handed to hyper at once on HTTP/2, so that the send deadline
/// counts per 64 KiB the client takes: what a static file is streamed in, and what HTTP/3 sends
/// at a time.
pub(crate) const SEND_PIECE: usize = 64 * 1024;

/// What the streams of one HTTP/2 connection share.
pub(crate) struct Conn {
    /// How long a piece may wait for the client's window; `None` = no deadline.
    send_stall: Option<Duration>,
    /// Slots for static responses streamed from their open file.
    static_files: Arc<Semaphore>,
    /// The budget for static responses read whole, in [`WHOLE_UNIT`]s.
    static_whole: Arc<Semaphore>,
}

impl Conn {
    /// `send_stall_secs` is the value of `[server] send_stall_secs` (`0` = no deadline).
    pub(crate) fn new(send_stall_secs: u64) -> Arc<Conn> {
        Arc::new(Conn {
            send_stall: (send_stall_secs > 0).then(|| Duration::from_secs(send_stall_secs)),
            static_files: Arc::new(Semaphore::new(STATIC_FILES_PER_CONN)),
            static_whole: Arc::new(Semaphore::new(whole_units(STATIC_WHOLE_BYTES_PER_CONN))),
        })
    }

    /// The pool a static response that needs `need` takes from, and how much of it.
    pub(crate) fn pool(&self, need: Need) -> (Arc<Semaphore>, u32) {
        let (pool, units) = match need {
            Need::File => (&self.static_files, 1),
            Need::Whole(len) => (&self.static_whole, whole_units(len)),
        };
        (pool.clone(), u32::try_from(units).unwrap_or(u32::MAX))
    }

    /// The streamed-file slots and whole-read units free now.
    #[cfg(test)]
    pub(crate) fn free(&self) -> (usize, usize) {
        (
            self.static_files.available_permits(),
            self.static_whole.available_permits(),
        )
    }
}

/// `len` bytes in [`WHOLE_UNIT`]s, rounded up, and never more than the whole budget (a
/// request for more than a semaphore holds would wait forever).
pub(crate) fn whole_units(len: u64) -> usize {
    let budget = STATIC_WHOLE_BYTES_PER_CONN.div_ceil(WHOLE_UNIT);
    usize::try_from(len.div_ceil(WHOLE_UNIT).min(budget)).unwrap_or(usize::MAX)
}

/// One HTTP/2 stream, shared by the task that runs it, its request handler and its body.
pub(crate) struct Stream {
    started: Instant,
    /// When the body last handed hyper a piece that hyper has not passed on yet (it is waiting
    /// for the client's window): milliseconds after `started`, plus one; `0` = no piece waits.
    waiting_since: AtomicU64,
    /// The connection, set by its service when the request starts ([`enter`]).
    conn: OnceLock<Arc<Conn>>,
}

impl Stream {
    fn new() -> Stream {
        Stream {
            started: Instant::now(),
            waiting_since: AtomicU64::new(0),
            conn: OnceLock::new(),
        }
    }

    fn start_waiting(&self) {
        let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.waiting_since.store(ms + 1, Relaxed);
    }

    fn stop_waiting(&self) {
        self.waiting_since.store(0, Relaxed);
    }

    fn has_deadline(&self) -> bool {
        self.conn.get().is_some_and(|c| c.send_stall.is_some())
    }

    /// When the piece now waiting for the client has waited too long; `None` when no piece
    /// waits or the connection sets no deadline.
    fn stall_deadline(&self) -> Option<Instant> {
        let since = self.waiting_since.load(Relaxed);
        if since == 0 {
            return None;
        }
        let stall = self.conn.get()?.send_stall?;
        self.started
            .checked_add(Duration::from_millis(since - 1))?
            .checked_add(stall)
    }
}

tokio::task_local! {
    static STREAM: Arc<Stream>;
}

/// The executor of the HTTP/1 and HTTP/2 server builder: hyper spawns one task per HTTP/2
/// stream with it (HTTP/1 spawns nothing), and each runs under the send deadline.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Executor;

impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(run(fut));
    }
}

/// Run one task hyper spawned for an HTTP/2 stream, inside its [`Stream`]; dropped, with
/// everything its response holds, when the client leaves a piece waiting past the deadline.
async fn run<F: Future<Output = ()>>(fut: F) {
    let stream = Arc::new(Stream::new());
    if unless_stalled(STREAM.scope(stream.clone(), fut), &stream)
        .await
        .is_none()
    {
        crate::metrics::METRICS
            .streams_stalled
            .fetch_add(1, Relaxed);
    }
}

/// The [`Stream`] the HTTP/1.1 requests of one connection share, under the deadline of
/// `send_stall_secs` (`0` = none): an HTTP/1.1 connection sends one response at a time, so its
/// responses take turns in it. Pass it to [`watch`] for each HTTP/1.1 response and run the
/// connection under [`serve_http1`].
pub(crate) fn http1_stream(send_stall_secs: u64) -> Arc<Stream> {
    let stream = Arc::new(Stream::new());
    let _ = stream.conn.set(Conn::new(send_stall_secs));
    stream
}

/// Serve the connection `conn` to its end, or close it (by dropping it) when an HTTP/1.1
/// response on it has had a piece waiting for the client past the deadline of `stream`
/// ([`http1_stream`]): what the response held (a file, a slot, an upstream connection) goes
/// with it, and the close is counted in `zion_streams_stalled_total`. HTTP/1.1 has no way to
/// cancel one response and keep the connection. The HTTP/2 streams of a connection have
/// deadlines of their own and never mark this one.
pub(crate) async fn serve_http1<F: Future>(conn: F, stream: &Stream) -> Option<F::Output> {
    let out = unless_stalled(conn, stream).await;
    if out.is_none() {
        crate::metrics::METRICS
            .streams_stalled
            .fetch_add(1, Relaxed);
    }
    out
}

/// Drive `fut` to its end, or until `stream` has a piece that waited for the client past its
/// deadline: `true` then, and `fut` is dropped on return.
///
/// The timer exists only while a piece waits, and is moved only when it fires: a response
/// that keeps moving costs one wake-up per deadline, not one timer per piece.
#[cfg(test)]
async fn until_stalled<F: Future<Output = ()>>(fut: F, stream: &Stream) -> bool {
    unless_stalled(fut, stream).await.is_none()
}

/// [`until_stalled`]: `fut`'s output, or `None` when a piece waited past the deadline.
async fn unless_stalled<F: Future>(fut: F, stream: &Stream) -> Option<F::Output> {
    tokio::pin!(fut);
    let mut timer: Option<Pin<Box<Sleep>>> = None;
    std::future::poll_fn(|cx| {
        // A deadline that has passed with nothing taken ends it before `fut` is polled again:
        // polled, an HTTP/1.1 connection can find room the kernel made in its socket buffer
        // without waking it (macOS grows the buffer of a connection whose peer reads nothing),
        // hand over one more piece, and so push the deadline back with no byte taken.
        if let (Some(t), Some(deadline)) = (timer.as_mut(), stream.stall_deadline()) {
            if t.deadline() >= deadline && t.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
        }
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        // Everything that starts or ends a wait runs inside the poll above (hyper polls the
        // body there), so the state read here is the state the stream is left in.
        let Some(deadline) = stream.stall_deadline() else {
            return Poll::Pending;
        };
        let timer = timer.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        loop {
            if timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            if timer.deadline() >= deadline {
                return Poll::Ready(None); // the piece now waiting is the one it was set for
            }
            // It fired for an earlier piece, which the client took: wait for this one.
            timer.as_mut().reset(deadline);
        }
    })
    .await
}

/// Run `request`, an HTTP/3 request of the QUIC connection `conn`, as a stream of it: a static
/// response takes the connection's slots as on HTTP/2. The QUIC listener spawns its request
/// tasks itself, so this stands in for [`Executor`] and [`enter`]. The send deadline is the
/// listener's to apply ([`send_stall`]): dropping a QUIC send stream finishes it, where an
/// HTTP/2 stream dropped is reset.
#[cfg(feature = "http3")]
pub(crate) async fn scope<F: Future>(conn: Arc<Conn>, request: F) -> F::Output {
    let stream = Arc::new(Stream::new());
    let _ = stream.conn.set(conn);
    STREAM.scope(stream, request).await
}

/// How long a piece of the current request's response may wait for the client to take it
/// (`[server] send_stall_secs`); `None` without a deadline or off HTTP/2 and HTTP/3.
#[cfg(feature = "http3")]
pub(crate) fn send_stall() -> Option<Duration> {
    STREAM
        .try_with(|s| s.conn.get().and_then(|c| c.send_stall))
        .ok()
        .flatten()
}

/// The HTTP/2 stream the current request arrived on, joined to `conn`; `None` off HTTP/2.
pub(crate) fn enter(conn: Arc<Conn>) -> Option<Arc<Stream>> {
    STREAM
        .try_with(|s| {
            let _ = s.conn.set(conn);
            s.clone()
        })
        .ok()
}

/// The HTTP/2 or HTTP/3 connection the current request arrived on, whose static-response slots
/// it takes from; `None` on HTTP/1.
pub(crate) fn current_conn() -> Option<Arc<Conn>> {
    STREAM.try_with(|s| s.conn.get().cloned()).ok().flatten()
}

/// `resp`, sent on the HTTP/2 `stream` (`None` on HTTP/1), with its body watched: for the
/// send deadline, cut into pieces of at most [`SEND_PIECE`], and, when it is a static response
/// that holds a slot (`static_files` puts it in the extensions), so that every piece keeps that
/// slot and, on HTTP/2, the stream ends only once the last piece has left. Unchanged for a
/// response with no body, and when there is neither a deadline nor a slot.
pub(crate) fn watch(
    mut resp: Response<ZionBody>,
    stream: Option<&Arc<Stream>>,
) -> Response<ZionBody> {
    let slot = resp.extensions_mut().remove::<StaticSlot>();
    if resp.body().is_end_stream() {
        return resp; // nothing waits for the client: the slot goes now
    }
    let stream = stream
        .filter(|s| slot.is_some() || s.has_deadline())
        .cloned();
    if stream.is_none() && slot.is_none() {
        return resp;
    }
    // On HTTP/2, a static response's end waits for its pieces to leave h2's buffer, under the
    // deadline: a piece hyper hands over ends the stream's task when it is the last.
    let drain = (stream.is_some() && slot.is_some()).then(|| {
        Arc::new(Drain {
            left: AtomicUsize::new(0),
            waker: Mutex::new(None),
            body_gone: std::sync::atomic::AtomicBool::new(false),
            stream: stream.clone(),
        })
    });
    resp.map(|inner| {
        Watched {
            inner,
            stream,
            slot,
            drain,
            rest: Bytes::new(),
            ended: false,
            seen: None,
        }
        .boxed()
    })
}

/// The pieces of a static response still in hyper's or h2's hands, and who to wake when one
/// leaves.
struct Drain {
    left: AtomicUsize,
    waker: Mutex<Option<Waker>>,
    /// The body was dropped with pieces still out (hyper ends an HTTP/1.1 body itself once
    /// its `Content-Length` is written): each piece that leaves then moves the deadline, and
    /// the last one ends the wait, as the end of the body would have.
    body_gone: std::sync::atomic::AtomicBool,
    stream: Option<Arc<Stream>>,
}

/// The owner of a piece of a watched body: the bytes, the slot they keep, and the [`Drain`]
/// told when they are gone (h2 has written them, or dropped them with the stream).
struct Piece {
    data: Bytes,
    _slot: Option<StaticSlot>,
    drain: Option<Arc<Drain>>,
}

impl AsRef<[u8]> for Piece {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for Piece {
    fn drop(&mut self) {
        if let Some(drain) = &self.drain {
            let left = drain.left.fetch_sub(1, Relaxed) - 1;
            if drain.body_gone.load(Relaxed) {
                if let Some(s) = &drain.stream {
                    match left {
                        0 => s.stop_waiting(),
                        _ => s.start_waiting(),
                    }
                }
            }
            let waker = drain.waker.lock().ok().and_then(|mut w| w.take());
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

/// A response body that hands hyper pieces of at most [`SEND_PIECE`] on HTTP/2, tells its
/// [`Stream`] when a piece is waiting for the client, and makes each piece keep the static
/// response's slot.
///
/// hyper takes a piece, waits until the client's window has room for it (one byte of it is
/// enough), passes it to h2, and only then asks for the next one (`PipeToSendStream` in hyper
/// 1.12). So a piece is waiting from the moment it is handed over until the next call. When a
/// static response's own body has ended, the end is held back (on HTTP/2) until every piece
/// has left h2's buffer, and the wait is counted as a piece waiting: hyper would otherwise
/// hand the last piece over with the end of the stream, and the stream's task, which the
/// deadline covers, would end with those bytes still unsent.
struct Watched {
    inner: ZionBody,
    /// The HTTP/2 stream; `None` on HTTP/1, which has no deadline and is not cut into pieces.
    stream: Option<Arc<Stream>>,
    slot: Option<StaticSlot>,
    /// HTTP/2 with a slot: the pieces the end waits for.
    drain: Option<Arc<Drain>>,
    /// What is left of the chunk the body last gave.
    rest: Bytes,
    /// The body has given its last chunk.
    ended: bool,
    /// How many pieces were left the last time the end was waited for.
    seen: Option<usize>,
}

impl Watched {
    /// The next piece of [`Self::rest`], marked waiting.
    fn next_piece(&mut self) -> Bytes {
        let n = match self.stream {
            Some(_) => self.rest.len().min(SEND_PIECE),
            None => self.rest.len(),
        };
        let data = self.rest.split_to(n);
        if let Some(s) = &self.stream {
            s.start_waiting();
        }
        if self.slot.is_none() {
            return data;
        }
        if let Some(drain) = &self.drain {
            drain.left.fetch_add(1, Relaxed);
        }
        Bytes::from_owner(Piece {
            data,
            _slot: self.slot.clone(),
            drain: self.drain.clone(),
        })
    }

    /// `Ready(None)` once every piece has left; until then the end waits, as a piece would.
    fn poll_end(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let Some(drain) = &self.drain else {
            return Poll::Ready(None);
        };
        if let Ok(mut w) = drain.waker.lock() {
            *w = Some(cx.waker().clone());
        }
        let left = drain.left.load(Relaxed);
        if left == 0 {
            return Poll::Ready(None);
        }
        // A piece that left is the client taking more: the deadline counts from then.
        if self.seen != Some(left) {
            self.seen = Some(left);
            if let Some(s) = &self.stream {
                s.start_waiting();
            }
        }
        Poll::Pending
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        // A body dropped before its end (the stream was reset, hyper wrote all of an HTTP/1.1
        // `Content-Length`): nothing of it waits for the client any more, unless pieces of it
        // are still in the library's buffer, which then tell the stream as they leave.
        let Some(s) = &self.stream else { return };
        match &self.drain {
            Some(d) if d.left.load(Relaxed) > 0 => {
                d.body_gone.store(true, Relaxed);
                if d.left.load(Relaxed) == 0 {
                    s.stop_waiting(); // the last left in between
                }
            }
            _ => s.stop_waiting(),
        }
    }
}

impl Body for Watched {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = &mut *self;
        if this.ended {
            return this.poll_end(cx);
        }
        // hyper asks for the next piece: it has passed the last one on.
        if let Some(s) = &this.stream {
            s.stop_waiting();
        }
        if !this.rest.is_empty() {
            return Poll::Ready(Some(Ok(Frame::data(this.next_piece()))));
        }
        let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => frame,
            Poll::Ready(None) => {
                this.ended = true;
                return this.poll_end(cx);
            }
            other => return other,
        };
        // An empty chunk and trailers need no window: hyper sends them at once.
        let frame = match frame.into_data() {
            Ok(data) if !data.is_empty() => {
                this.rest = data;
                Frame::data(this.next_piece())
            }
            Ok(data) => Frame::data(data),
            Err(frame) => frame,
        };
        Poll::Ready(Some(Ok(frame)))
    }

    fn is_end_stream(&self) -> bool {
        // A body whose end waits for its pieces ends with an empty frame of its own, once
        // they are gone.
        self.drain.is_none() && self.rest.is_empty() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{Full, StreamBody};

    /// A stream joined to a connection whose deadline is `secs`.
    fn stream(secs: u64) -> Arc<Stream> {
        let s = Arc::new(Stream::new());
        let _ = s.conn.set(Conn::new(secs));
        s
    }

    fn body_of(frames: Vec<Bytes>) -> ZionBody {
        let frames: Vec<Result<Frame<Bytes>, hyper::Error>> =
            frames.into_iter().map(|b| Ok(Frame::data(b))).collect();
        StreamBody::new(tokio_stream::iter(frames)).boxed()
    }

    /// A slot from a budget of its own, for a response to keep.
    fn slot() -> (StaticSlot, crate::static_budget::Admission) {
        let adm = crate::static_budget::test_admission(None, 64 << 20);
        (adm.try_take(Need::File).expect("a free slot"), adm)
    }

    fn with_slot(body: ZionBody, slot: &StaticSlot) -> Response<ZionBody> {
        let mut resp = Response::new(body);
        resp.extensions_mut().insert(slot.clone());
        resp
    }

    #[tokio::test(start_paused = true)]
    async fn a_piece_left_waiting_past_the_deadline_stops_the_stream() {
        let s = stream(10);
        let t0 = Instant::now();
        let stalled = until_stalled(
            {
                let s = s.clone();
                async move {
                    s.start_waiting(); // a piece handed over, the window never opens
                    std::future::pending::<()>().await
                }
            },
            &s,
        )
        .await;
        assert!(stalled);
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_secs(10) && took < Duration::from_secs(11),
            "{took:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_counts_from_the_last_piece_the_client_took() {
        let s = stream(10);
        let t0 = Instant::now();
        let stalled = until_stalled(
            {
                let s = s.clone();
                async move {
                    s.start_waiting();
                    tokio::time::sleep(Duration::from_secs(6)).await;
                    s.stop_waiting(); // taken: hyper asked for the next piece
                    s.start_waiting(); // ... which now waits in turn
                    std::future::pending::<()>().await
                }
            },
            &s,
        )
        .await;
        assert!(stalled);
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_secs(16) && took < Duration::from_secs(17),
            "the timer set for the first piece fired at 10 s and must have moved to 16 s: {took:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_waiting_on_its_own_source_is_never_stopped() {
        // A slow upstream or an idle event stream: hyper is waiting on the body, not on the
        // client. And a stream on a connection with no deadline.
        for (secs, waiting) in [(10, false), (0, true)] {
            let s = stream(secs);
            let fut = {
                let s = s.clone();
                async move {
                    if waiting {
                        s.start_waiting();
                    }
                    std::future::pending::<()>().await
                }
            };
            let r = tokio::time::timeout(Duration::from_secs(3600), until_stalled(fut, &s)).await;
            assert!(r.is_err(), "deadline {secs}, waiting {waiting}: stopped");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_ends_is_not_counted_as_stalled() {
        let s = stream(10);
        assert!(!until_stalled(async {}, &s).await);
    }

    #[tokio::test]
    async fn the_body_marks_a_piece_waiting_until_hyper_asks_for_the_next() {
        let s = stream(10);
        let frames: Vec<Result<Frame<Bytes>, hyper::Error>> = vec![
            Ok(Frame::data(Bytes::from_static(b"chunk"))),
            Ok(Frame::data(Bytes::new())),
            Ok(Frame::trailers(hyper::HeaderMap::new())),
        ];
        let inner = StreamBody::new(tokio_stream::iter(frames)).boxed();
        let mut body = watch(Response::new(inner), Some(&s)).into_body();
        assert_eq!(s.waiting_since.load(Relaxed), 0);
        body.frame().await.unwrap().unwrap();
        assert_ne!(s.waiting_since.load(Relaxed), 0, "a data piece waits");
        body.frame().await.unwrap().unwrap();
        assert_eq!(s.waiting_since.load(Relaxed), 0, "an empty chunk does not");
        body.frame().await.unwrap().unwrap();
        assert_eq!(s.waiting_since.load(Relaxed), 0, "trailers do not");
        assert!(body.frame().await.is_none());
        assert_eq!(s.waiting_since.load(Relaxed), 0);
    }

    #[tokio::test]
    async fn on_http2_a_chunk_is_handed_over_in_pieces_of_at_most_64_kib() {
        // A proxied chunk of 400 KiB: the deadline would otherwise count per 400 KiB.
        let s = stream(10);
        let chunk = Bytes::from(vec![3u8; 400 * 1024 + 5]);
        let mut body = watch(Response::new(body_of(vec![chunk.clone()])), Some(&s)).into_body();
        let mut sizes = Vec::new();
        let mut got = Vec::new();
        while let Some(f) = body.frame().await {
            let data = f.unwrap().into_data().unwrap();
            sizes.push(data.len());
            got.extend_from_slice(&data);
        }
        assert_eq!(got, chunk, "the bytes are the chunk's, in order");
        assert!(sizes.iter().all(|&n| n <= SEND_PIECE), "{sizes:?}");
        assert_eq!(sizes.len(), 7, "{sizes:?}");
        // HTTP/1 is not cut.
        let mut body = watch(with_slot(body_of(vec![chunk.clone()]), &slot().0), None).into_body();
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap()
                .len(),
            chunk.len()
        );
    }

    #[tokio::test]
    async fn every_piece_of_a_static_response_keeps_its_slot_until_the_last_slice_is_gone() {
        let (slot, adm) = slot();
        let free = || adm.free_bytes();
        let before = free();
        // A body whose bytes are not the file's, as a compressed one sends.
        let resp = watch(
            with_slot(body_of(vec![Bytes::from(vec![7u8; 1024])]), &slot),
            None,
        );
        drop(slot);
        let mut body = resp.into_body();
        let chunk = body.frame().await.unwrap().unwrap().into_data().unwrap();
        drop(body);
        assert_eq!(free(), before, "the piece keeps the slot");
        let tail = chunk.slice(512..); // what h2 has not written yet
        drop(chunk);
        assert_eq!(free(), before, "a slice of it keeps it");
        assert_eq!(&tail[..], &[7u8; 512][..]);
        drop(tail); // written
        assert!(free() > before, "released with the last slice");
    }

    #[tokio::test]
    async fn on_http2_a_static_response_ends_only_once_its_last_piece_has_left() {
        let s = stream(10);
        let (slot, _adm) = slot();
        let mut body = watch(
            with_slot(body_of(vec![Bytes::from(vec![1u8; 100])]), &slot),
            Some(&s),
        )
        .into_body();
        assert!(!body.is_end_stream());
        let piece = body.frame().await.unwrap().unwrap().into_data().unwrap();
        // hyper asks for more with the piece still in h2's buffer: the end waits, and counts
        // as a piece waiting for the client, under the deadline.
        let mut next = Box::pin(body.frame());
        assert!(futures_poll_once(&mut next).await.is_none(), "ended early");
        assert_ne!(
            s.waiting_since.load(Relaxed),
            0,
            "the end is not under the deadline"
        );
        drop(piece); // h2 wrote it
        let end = tokio::time::timeout(Duration::from_secs(5), next)
            .await
            .unwrap();
        assert!(end.is_none(), "the body ends once its piece has gone");
    }

    /// Poll `fut` once: `Some` with its output if it is ready.
    async fn futures_poll_once<F: Future + Unpin>(fut: &mut F) -> Option<F::Output> {
        std::future::poll_fn(|cx| {
            Poll::Ready(match Pin::new(&mut *fut).poll(cx) {
                Poll::Ready(v) => Some(v),
                Poll::Pending => None,
            })
        })
        .await
    }

    #[tokio::test]
    async fn off_http2_nothing_is_watched_or_held() {
        let conn = Conn::new(10);
        assert!(enter(conn.clone()).is_none(), "no HTTP/2 stream task here");
        assert!(current_conn().is_none());
        let resp = Response::new(
            Full::new(Bytes::from_static(b"x"))
                .map_err(|n| match n {})
                .boxed(),
        );
        let resp = watch(resp, None);
        assert_eq!(resp.body().size_hint().exact(), Some(1));
    }

    #[test]
    fn a_body_over_the_whole_budget_is_counted_as_the_budget() {
        // ... so it can be served at all.
        assert_eq!(
            whole_units(u64::MAX),
            whole_units(STATIC_WHOLE_BYTES_PER_CONN)
        );
    }
}
