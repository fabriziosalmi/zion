// SPDX-License-Identifier: Apache-2.0
//! A per-connection bound on HTTP/2 control frames (#475).
//!
//! `h2` bounds stream resets (Rapid Reset) but nothing else: one connection can send `PING`,
//! `SETTINGS` or `WINDOW_UPDATE` frames at wire speed, each is answered or processed, and the
//! connection is never closed. `h2` has no hook for it, so the bound sits at the transport:
//! [`H2Guard`] wraps the accepted stream, reads the 9-byte frame headers as the bytes go by,
//! and closes the connection when a client sends more control frames in one second than a
//! real client does.
//!
//! Whether a connection is HTTP/2 is read from its first bytes (the client preface), not
//! from ALPN: hyper serves HTTP/2 to any connection that opens with the preface, on the
//! plaintext listener and on a TLS connection that negotiated nothing, so a guard keyed on
//! ALPN is skipped by not offering `h2`.
//!
//! Two parts, kept apart on purpose:
//!
//! * [`FrameCounter`]: a pure state machine over the client's byte stream. It is fed whatever
//!   chunks the transport produces and must give the same counts for every chunking: a bug
//!   here desynchronises from the frame boundaries and miscounts, so it has no I/O and is
//!   property-tested.
//! * [`Budget`]: what is too much, per second.
//!
//! The guard never alters the bytes. It can only refuse to read more.

use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering::Relaxed};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What a client sends before its first frame (RFC 9113 §3.4).
const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;

// Frame types (RFC 9113 §6).
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;
const FLAG_END_STREAM: u8 = 0x1;

/// `GOAWAY(ENHANCE_YOUR_CALM)` (RFC 9113 §6.8): 8 bytes of payload, type 7, stream 0, then
/// the last stream id and the error code. The last stream id is the largest there is: the
/// guard does not know which requests hyper acted on, and a lower value would tell the
/// client that the later ones are safe to send again.
const GOAWAY_ENHANCE_YOUR_CALM: [u8; 17] = [
    0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0x0b,
];

/// Frames seen in some bytes, by what they cost the server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Frames that carry no part of a request: every type but `HEADERS`, `CONTINUATION`,
    /// `DATA`, `RST_STREAM` and `WINDOW_UPDATE` (so `PING`, `SETTINGS`, `PRIORITY`, `GOAWAY`
    /// and the types the server skips unread), and `DATA` with no payload that does not end
    /// its stream.
    pub control: u32,
    /// `HEADERS` frames: streams the client opened (or trailers).
    pub headers: u32,
    /// `RST_STREAM` frames. Counted apart: a client cancels the streams it opened, a
    /// hundred at once when a browser leaves a page that is still loading, and that is not
    /// a flood. One that resets more streams than it opened is.
    pub resets: u32,
    /// `WINDOW_UPDATE` frames. Counted apart: a client that is receiving a large response
    /// legitimately sends many, in proportion to the bytes it was sent.
    pub window_updates: u32,
}

impl Tally {
    fn is_empty(self) -> bool {
        self == Tally::default()
    }

    fn add(&mut self, other: Tally) {
        self.control = self.control.saturating_add(other.control);
        self.headers = self.headers.saturating_add(other.headers);
        self.resets = self.resets.saturating_add(other.resets);
        self.window_updates = self.window_updates.saturating_add(other.window_updates);
    }
}

#[derive(Clone, Copy, Debug)]
enum State {
    /// Matching the client preface; the value is how many bytes matched so far.
    Preface(usize),
    /// Collecting a frame header.
    Header {
        buf: [u8; FRAME_HEADER_LEN],
        have: usize,
    },
    /// Skipping a frame's payload.
    Payload { remaining: u32 },
    /// The stream is not HTTP/2 as far as this parser can tell: stop counting (hyper will
    /// refuse the connection on its own terms).
    NotHttp2,
}

/// Counts the frames in the bytes a client sends, across any chunking.
#[derive(Clone, Debug)]
pub struct FrameCounter {
    state: State,
}

impl Default for FrameCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameCounter {
    pub fn new() -> Self {
        Self {
            state: State::Preface(0),
        }
    }

    /// For the server's own bytes, which start with a frame and no preface.
    fn after_preface() -> Self {
        Self {
            state: State::Header {
                buf: [0; FRAME_HEADER_LEN],
                have: 0,
            },
        }
    }

    /// The bytes so far did not open with the HTTP/2 preface.
    fn not_http2(&self) -> bool {
        matches!(self.state, State::NotHttp2)
    }

    /// The bytes so far end where a frame ends.
    fn at_frame_boundary(&self) -> bool {
        matches!(self.state, State::Header { have: 0, .. })
    }

    /// Feed the next bytes the client sent; returns the frames whose header completed in
    /// them. A frame is counted when its 9-byte header is complete, not when its payload is.
    pub fn feed(&mut self, mut chunk: &[u8]) -> Tally {
        let mut tally = Tally::default();
        while !chunk.is_empty() {
            match &mut self.state {
                State::NotHttp2 => break,
                State::Preface(matched) => {
                    let n = (PREFACE.len() - *matched).min(chunk.len());
                    if chunk[..n] != PREFACE[*matched..*matched + n] {
                        self.state = State::NotHttp2;
                        break;
                    }
                    *matched += n;
                    chunk = &chunk[n..];
                    if *matched == PREFACE.len() {
                        self.state = State::Header {
                            buf: [0; FRAME_HEADER_LEN],
                            have: 0,
                        };
                    }
                }
                State::Header { buf, have } => {
                    let n = (FRAME_HEADER_LEN - *have).min(chunk.len());
                    buf[*have..*have + n].copy_from_slice(&chunk[..n]);
                    *have += n;
                    chunk = &chunk[n..];
                    if *have == FRAME_HEADER_LEN {
                        let length = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
                        let (kind, flags) = (buf[3], buf[4]);
                        tally.add(classify(kind, flags, length));
                        self.state = if length == 0 {
                            State::Header {
                                buf: [0; FRAME_HEADER_LEN],
                                have: 0,
                            }
                        } else {
                            State::Payload { remaining: length }
                        };
                    }
                }
                State::Payload { remaining } => {
                    let n = (*remaining as usize).min(chunk.len());
                    *remaining -= n as u32;
                    chunk = &chunk[n..];
                    if *remaining == 0 {
                        self.state = State::Header {
                            buf: [0; FRAME_HEADER_LEN],
                            have: 0,
                        };
                    }
                }
            }
        }
        tally
    }
}

fn classify(kind: u8, flags: u8, length: u32) -> Tally {
    let control = Tally {
        control: 1,
        ..Tally::default()
    };
    match kind {
        // A request and its body. `h2` bounds these itself: concurrent streams, header
        // size, and the resets it sends for frames on a stream that is gone.
        HEADERS => Tally {
            headers: 1,
            ..Tally::default()
        },
        CONTINUATION => Tally::default(),
        // ... except a DATA frame that carries nothing and does not end its stream.
        DATA if length == 0 && flags & FLAG_END_STREAM == 0 => control,
        DATA => Tally::default(),
        RST_STREAM => Tally {
            resets: 1,
            ..Tally::default()
        },
        WINDOW_UPDATE => Tally {
            window_updates: 1,
            ..Tally::default()
        },
        // Everything else, the types this server does not know included: `h2` reads and
        // drops those, so a flood of them costs what a flood of PINGs costs. Counting only
        // the named types would leave the unnamed ones as the way around the limit.
        _ => control,
    }
}

/// How many control frames a connection may send per second (`[server]
/// h2_control_frames_per_sec`), and how `WINDOW_UPDATE`s are allowed on top of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Control frames per second; `0` = no limit (frames are still counted, for the
    /// `zion_h2_control_frames_peak` gauge an operator reads before choosing a limit).
    pub control_per_sec: u32,
}

/// `WINDOW_UPDATE`s a client may send per second without having been sent anything.
const WINDOW_UPDATE_FLOOR_PER_SEC: u64 = 1_000;
/// ... plus one for this many response bytes written to it in the same second: a client
/// receiving a large body acknowledges it with window updates. Measured on 300 MB
/// downloads, the bytes a client is sent per update: nghttp 18 KB (the chattiest, with its
/// default windows and with 64 KiB ones), Chrome 2.2 MB, curl 5 MB. One update per DATA
/// frame for the stream and one for the connection, the most a conforming client has a
/// reason to send, is one per 8 KiB. So a download stays 30 times or more under the
/// allowance, at any speed.
const BYTES_PER_WINDOW_UPDATE: u64 = 256;

/// Why a connection was closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flood {
    Control,
    WindowUpdate,
}

impl Flood {
    pub fn as_str(self) -> &'static str {
        match self {
            Flood::Control => "HTTP/2 control-frame flood",
            Flood::WindowUpdate => "HTTP/2 WINDOW_UPDATE flood",
        }
    }
}

/// Counts per one-second window. The window is opened and closed by the frames the client
/// sends: the bytes written to it are added as they go, with no clock read on the write
/// path, and are dropped with the counts when the window rolls.
#[derive(Debug)]
struct Budget {
    limits: Limits,
    window_started: Instant,
    control: u64,
    window_updates: u64,
    bytes_written: u64,
    /// Over the life of the connection: `HEADERS` seen that no `RST_STREAM` has used up.
    /// A reset within it cancels a stream the client opened and costs nothing here (`h2`
    /// bounds a client that opens streams only to reset them); one beyond it is a control
    /// frame like any other.
    resets_earned: u64,
}

impl Budget {
    fn new(limits: Limits, now: Instant) -> Self {
        Self {
            limits,
            window_started: now,
            control: 0,
            window_updates: 0,
            bytes_written: 0,
            resets_earned: 0,
        }
    }

    fn wrote(&mut self, bytes: usize) {
        self.bytes_written = self.bytes_written.saturating_add(bytes as u64);
    }

    fn saw(&mut self, tally: Tally, now: Instant) -> Option<Flood> {
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.control = 0;
            self.window_updates = 0;
            self.bytes_written = 0;
        }
        self.resets_earned += u64::from(tally.headers);
        let resets = u64::from(tally.resets);
        let unearned = resets.saturating_sub(self.resets_earned);
        self.resets_earned -= resets - unearned;
        let control = u64::from(tally.control) + unearned;
        self.control += control;
        self.window_updates += u64::from(tally.window_updates);
        if control > 0 {
            crate::metrics::METRICS
                .h2_control_frames_peak
                .fetch_max(self.control, Relaxed);
        }
        if self.limits.control_per_sec == 0 {
            return None; // counting only
        }
        if self.control > u64::from(self.limits.control_per_sec) {
            return Some(Flood::Control);
        }
        let allowed = WINDOW_UPDATE_FLOOR_PER_SEC
            .max(u64::from(self.limits.control_per_sec))
            .saturating_add(self.bytes_written / BYTES_PER_WINDOW_UPDATE);
        if self.window_updates > allowed {
            return Some(Flood::WindowUpdate);
        }
        None
    }
}

/// Whether the guard closed its connection, for the task that served it to log: the guard
/// sees bytes and has no client address to name.
#[derive(Clone, Debug, Default)]
pub struct Verdict(Arc<AtomicU8>);

impl Verdict {
    fn set(&self, flood: Flood) {
        self.0.store(
            match flood {
                Flood::Control => 1,
                Flood::WindowUpdate => 2,
            },
            Relaxed,
        );
    }

    pub fn get(&self) -> Option<Flood> {
        match self.0.load(Relaxed) {
            1 => Some(Flood::Control),
            2 => Some(Flood::WindowUpdate),
            _ => None,
        }
    }
}

/// The accepted stream, with the control-frame bound on what it reads. It passes every byte
/// through unchanged; on a connection that is not HTTP/2 it stops looking after the first
/// read, and with a limit of `0` it counts and never closes.
pub struct H2Guard<S> {
    inner: S,
    /// The client's frames.
    reads: FrameCounter,
    /// The server's frames, followed only to know where one ends: a `GOAWAY` written in the
    /// middle of another frame would be read as part of it.
    writes: FrameCounter,
    budget: Budget,
    verdict: Verdict,
    /// The guard closed the connection: nothing more is read from it.
    closed: Option<Flood>,
    /// `Instant::now`, except in tests that must not depend on how fast they run.
    clock: fn() -> Instant,
}

impl<S> H2Guard<S> {
    pub fn new(inner: S, limits: Limits) -> Self {
        Self::with_clock(inner, limits, Instant::now)
    }

    fn with_clock(inner: S, limits: Limits, clock: fn() -> Instant) -> Self {
        Self {
            inner,
            reads: FrameCounter::new(),
            writes: FrameCounter::after_preface(),
            budget: Budget::new(limits, clock()),
            verdict: Verdict::default(),
            closed: None,
            clock,
        }
    }

    /// A handle that says, once the connection is over, whether the guard closed it.
    pub fn verdict(&self) -> Verdict {
        self.verdict.clone()
    }

    /// The server wrote the first `n` bytes of `bufs`.
    fn note_written<'a>(&mut self, bufs: impl Iterator<Item = &'a [u8]>, mut n: usize) {
        if self.reads.not_http2() {
            return;
        }
        self.budget.wrote(n);
        for buf in bufs {
            if n == 0 {
                break;
            }
            let take = n.min(buf.len());
            let _ = self.writes.feed(&buf[..take]);
            n -= take;
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for H2Guard<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if let Some(flood) = this.closed {
            return Poll::Ready(Err(std::io::Error::other(flood.as_str())));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        let tally = this.reads.feed(&buf.filled()[before..]);
        if tally.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let Some(flood) = this.budget.saw(tally, (this.clock)()) else {
            return Poll::Ready(Ok(()));
        };
        this.closed = Some(flood);
        this.verdict.set(flood);
        let metrics = &crate::metrics::METRICS;
        match flood {
            Flood::Control => metrics.h2_flood_closed_control.fetch_add(1, Relaxed),
            Flood::WindowUpdate => metrics.h2_flood_closed_window_update.fetch_add(1, Relaxed),
        };
        // Tell the client why, if the connection takes the frame at once and whole: a
        // client that is flooding is not waited for. One that is still sending when the
        // socket closes may see a reset in its place.
        if this.writes.at_frame_boundary() {
            let goaway = &GOAWAY_ENHANCE_YOUR_CALM;
            if let Poll::Ready(Ok(n)) = Pin::new(&mut this.inner).poll_write(cx, goaway) {
                let _ = this.writes.feed(&goaway[..n]);
                let _ = Pin::new(&mut this.inner).poll_flush(cx);
            }
        }
        Poll::Ready(Err(std::io::Error::other(flood.as_str())))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for H2Guard<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            this.note_written(std::iter::once(buf), n);
        }
        res
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = res {
            this.note_written(bufs.iter().map(|b| &**b), n);
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIORITY: u8 = 0x2;
    const SETTINGS: u8 = 0x4;
    const PING: u8 = 0x6;
    const GOAWAY: u8 = 0x7;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// A client's bytes: the preface, then the frames.
    fn stream_of(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut s = PREFACE.to_vec();
        for f in frames {
            s.extend_from_slice(f);
        }
        s
    }

    fn count(bytes: &[u8], chunk: usize) -> Tally {
        let mut c = FrameCounter::new();
        let mut t = Tally::default();
        for piece in bytes.chunks(chunk.max(1)) {
            t.add(c.feed(piece));
        }
        t
    }

    #[test]
    fn frames_are_classified_by_what_they_cost() {
        let frames = vec![
            frame(SETTINGS, 0, 0, &[0; 6]),          // control
            frame(SETTINGS, 0x1, 0, &[]),            // SETTINGS ack: control
            frame(HEADERS, 0x4, 1, &[0x82, 0x84]),   // a request, not counted
            frame(PING, 0, 0, &[0; 8]),              // control
            frame(WINDOW_UPDATE, 0, 0, &[0; 4]),     // window update
            frame(WINDOW_UPDATE, 0, 1, &[0; 4]),     // window update
            frame(PRIORITY, 0, 3, &[0; 5]),          // control
            frame(RST_STREAM, 0, 1, &[0; 4]),        // a reset
            frame(DATA, 0, 3, &[]),                  // empty DATA, stream stays open: control
            frame(DATA, FLAG_END_STREAM, 3, &[]), // empty DATA that ends the stream: a request ending
            frame(DATA, 0, 5, b"body"),           // DATA with a payload
            frame(CONTINUATION, 0x4, 1, &[1, 2, 3]), // the rest of a request's headers
            frame(GOAWAY, 0, 0, &[0; 8]),         // control
            // Types the server skips unread (0x10 is PRIORITY_UPDATE, 0xfa is nothing) cost
            // a frame each: control, or they would be the way around the limit.
            frame(0x10, 0, 0, &[0, 0, 0, 1, b'u']),
            frame(0xfa, 0, 0, &[9; 10]),
            frame(0xfa, 0, 0, &[]),
        ];
        let bytes = stream_of(&frames);
        let expected = Tally {
            control: 9,
            window_updates: 2,
            headers: 1,
            resets: 1,
        };
        // Same answer whole, byte by byte, and at every chunk size in between.
        for chunk in 1..=bytes.len() {
            assert_eq!(count(&bytes, chunk), expected, "chunk size {chunk}");
        }
    }

    #[test]
    fn a_large_frame_is_skipped_without_losing_the_boundary() {
        // The largest frame a peer may send by default (16 KiB) and the largest possible
        // length field, each followed by a PING that must still be seen.
        for len in [16_384usize, 100_000] {
            let bytes = stream_of(&[
                frame(DATA, 0, 1, &vec![0x06; len]),
                frame(PING, 0, 0, &[0; 8]),
            ]);
            for chunk in [1, 7, 9, 10, 4096, bytes.len()] {
                assert_eq!(
                    count(&bytes, chunk),
                    Tally {
                        control: 1,
                        ..Tally::default()
                    },
                    "len {len}, chunk {chunk}"
                );
            }
        }
        // A payload full of bytes that look like PING headers is payload, not frames.
        let decoy = frame(PING, 0, 0, &[0; 8]).repeat(50);
        let bytes = stream_of(&[frame(DATA, 0, 1, &decoy)]);
        assert_eq!(count(&bytes, 13), Tally::default());
    }

    #[test]
    fn bytes_that_are_not_http2_are_not_counted() {
        // HTTP/1.1 on a connection that negotiated h2, or garbage: stop, never panic.
        for bytes in [
            &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n\x00\x00\x08\x06\x00\x00\x00\x00\x00"[..],
            &[0xff; 64][..],
            &[][..],
        ] {
            for chunk in [1, 3, 64] {
                assert_eq!(count(bytes, chunk), Tally::default());
            }
        }
        // An incomplete preface or header counts nothing yet.
        assert_eq!(count(&PREFACE[..10], 4), Tally::default());
        let partial = stream_of(&[frame(PING, 0, 0, &[0; 8])]);
        assert_eq!(count(&partial[..PREFACE.len() + 8], 5), Tally::default());
    }

    #[test]
    fn the_budget_is_per_second_and_window_updates_follow_the_bytes_written() {
        let t0 = Instant::now();
        let control = |n| Tally {
            control: n,
            ..Tally::default()
        };
        let updates = |n| Tally {
            window_updates: n,
            ..Tally::default()
        };
        let limits = Limits {
            control_per_sec: 100,
        };
        let mut b = Budget::new(limits, t0);
        assert_eq!(b.saw(control(100), t0), None, "at the limit");
        assert_eq!(b.saw(control(1), t0), Some(Flood::Control), "one more");
        // A new second starts a new count.
        let mut b = Budget::new(limits, t0);
        assert_eq!(b.saw(control(100), t0), None);
        assert_eq!(b.saw(control(100), t0 + Duration::from_millis(1001)), None);
        assert_eq!(
            b.saw(control(1), t0 + Duration::from_millis(1500)),
            Some(Flood::Control)
        );
        // Window updates: a floor without any response...
        let mut b = Budget::new(limits, t0);
        assert_eq!(b.saw(updates(1_000), t0), None);
        assert_eq!(b.saw(updates(1), t0), Some(Flood::WindowUpdate));
        // ... and one more per 256 bytes written in the same second: 100 MB of response
        // allow 390,625 updates on top of the floor.
        let mut b = Budget::new(limits, t0);
        b.wrote(100_000_000);
        assert_eq!(b.saw(updates(391_000), t0), None);
        assert_eq!(b.saw(updates(1_000), t0), Some(Flood::WindowUpdate));
        // The bytes are those of the current second: an old download buys nothing later.
        let mut b = Budget::new(limits, t0);
        b.wrote(100_000_000);
        let later = t0 + Duration::from_secs(2);
        assert_eq!(b.saw(updates(1_000), later), None);
        assert_eq!(b.saw(updates(1), later), Some(Flood::WindowUpdate));
        // With no limit set nothing is closed, whatever arrives.
        let mut b = Budget::new(Limits { control_per_sec: 0 }, t0);
        assert_eq!(b.saw(control(u32::MAX), t0), None);
        assert_eq!(b.saw(updates(u32::MAX), t0), None);
        // Window updates do not use up the control budget, nor the reverse.
        let mut b = Budget::new(limits, t0);
        assert_eq!(b.saw(updates(900), t0), None);
        assert_eq!(b.saw(control(100), t0), None);
    }

    #[test]
    fn a_reset_is_free_for_a_stream_the_client_opened_and_no_other() {
        let t0 = Instant::now();
        let limits = Limits {
            control_per_sec: 100,
        };
        let opened = |n| Tally {
            headers: n,
            ..Tally::default()
        };
        let resets = |n| Tally {
            resets: n,
            ..Tally::default()
        };
        // A browser leaving a page: 128 streams opened, all cancelled in one burst, and
        // again, and again in the same second (measured with Chrome: 302 resets in a second).
        let mut b = Budget::new(limits, t0);
        for _ in 0..3 {
            assert_eq!(b.saw(opened(128), t0), None);
            assert_eq!(b.saw(resets(128), t0), None);
        }
        assert_eq!(b.control, 0, "none of them counted");
        // The streams were opened long before they are cancelled: still free.
        let mut b = Budget::new(limits, t0);
        assert_eq!(b.saw(opened(128), t0), None);
        assert_eq!(b.saw(resets(128), t0 + Duration::from_secs(600)), None);
        assert_eq!(b.control, 0);
        // Opened and reset in the same read.
        let mut b = Budget::new(limits, t0);
        let both = Tally {
            headers: 500,
            resets: 500,
            ..Tally::default()
        };
        assert_eq!(b.saw(both, t0), None);
        assert_eq!(b.control, 0);
        // A stream is reset once: a second reset of each is a control frame, and so is
        // every reset from a client that opened nothing.
        let mut b = Budget::new(limits, t0);
        assert_eq!(b.saw(opened(10), t0), None);
        assert_eq!(
            b.saw(resets(110), t0),
            None,
            "10 earned, 100 within the limit"
        );
        assert_eq!(b.control, 100);
        assert_eq!(b.saw(resets(1), t0), Some(Flood::Control));
        let mut b = Budget::new(limits, t0);
        assert_eq!(b.saw(resets(100), t0), None);
        assert_eq!(b.saw(resets(1), t0), Some(Flood::Control));
    }

    mod stream {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const LIMIT: Limits = Limits {
            control_per_sec: 10,
        };

        /// A clock that stands still: everything in a test falls in one second, however
        /// slowly the test runs. (The roll of the second is tested on `Budget`.)
        fn frozen() -> Instant {
            static T: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
            *T.get_or_init(Instant::now)
        }

        fn guarded<S>(inner: S, limits: Limits) -> H2Guard<S> {
            H2Guard::with_clock(inner, limits, frozen)
        }

        /// Read `expect` bytes from the guard, or the error with which it refuses. A guard
        /// that does neither fails the test instead of hanging it.
        async fn read_all<S: AsyncRead + AsyncWrite + Unpin>(
            guard: &mut H2Guard<S>,
            expect: usize,
        ) -> Result<Vec<u8>, std::io::Error> {
            let (mut got, mut buf) = (Vec::new(), [0u8; 4096]);
            while got.len() < expect {
                let read = tokio::time::timeout(Duration::from_secs(10), guard.read(&mut buf));
                let n = read.await.expect("the guard neither read nor refused")?;
                assert_ne!(n, 0, "unexpected end of stream");
                got.extend_from_slice(&buf[..n]);
            }
            Ok(got)
        }

        #[tokio::test]
        async fn a_flood_is_refused_with_goaway_enhance_your_calm() {
            let (mut client, server) = tokio::io::duplex(1 << 20);
            let mut guard = guarded(server, LIMIT);
            let verdict = guard.verdict();
            // The server's own SETTINGS, whole, so its side is at a frame boundary; written
            // as hyper writes, header and payload in two slices of one vectored write.
            let settings = frame(SETTINGS, 0, 0, &[0; 6]);
            let (header, payload) = settings.split_at(FRAME_HEADER_LEN);
            let n = std::future::poll_fn(|cx| {
                Pin::new(&mut guard).poll_write_vectored(
                    cx,
                    &[
                        std::io::IoSlice::new(header),
                        std::io::IoSlice::new(payload),
                    ],
                )
            })
            .await
            .unwrap();
            assert_eq!(n, settings.len());

            // Ten PINGs are within the limit and reach the server untouched.
            let within = stream_of(&vec![frame(PING, 0, 0, &[7; 8]); 10]);
            client.write_all(&within).await.unwrap();
            assert_eq!(read_all(&mut guard, within.len()).await.unwrap(), within);
            assert_eq!(verdict.get(), None);

            // The eleventh in the same second is not.
            client.write_all(&frame(PING, 0, 0, &[7; 8])).await.unwrap();
            let err = read_all(&mut guard, 1).await.unwrap_err();
            assert_eq!(err.to_string(), "HTTP/2 control-frame flood");
            assert_eq!(verdict.get(), Some(Flood::Control));
            // Nothing more is read from it, however the caller insists.
            client.write_all(&[0; 64]).await.unwrap();
            assert!(read_all(&mut guard, 1).await.is_err());

            // The client was told why: the server's SETTINGS, then GOAWAY with last stream
            // id 2^31-1 and error code 0xb (ENHANCE_YOUR_CALM), and nothing else.
            drop(guard);
            let mut seen = Vec::new();
            client.read_to_end(&mut seen).await.unwrap();
            let goaway = frame(GOAWAY, 0, 0, &[0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0x0b]);
            assert_eq!(seen[..settings.len()], settings[..]);
            assert_eq!(seen[settings.len()..], goaway[..]);
        }

        #[tokio::test]
        async fn no_goaway_is_written_into_the_middle_of_a_frame() {
            // The server got half of a frame out (a short write) when the flood is seen: a
            // GOAWAY now would be read as that frame's payload. The connection just closes.
            let (mut client, server) = tokio::io::duplex(1 << 20);
            let mut guard = guarded(server, LIMIT);
            let data = frame(DATA, 0, 1, &[1; 100]);
            // Vectored, and cut inside the payload, as a short write leaves it.
            let (a, b) = data.split_at(4);
            let n = std::future::poll_fn(|cx| {
                Pin::new(&mut guard).poll_write_vectored(
                    cx,
                    &[std::io::IoSlice::new(a), std::io::IoSlice::new(&b[..56])],
                )
            })
            .await
            .unwrap();
            assert_eq!(n, 60);
            client
                .write_all(&stream_of(&vec![frame(PING, 0, 0, &[0; 8]); 11]))
                .await
                .unwrap();
            assert!(read_all(&mut guard, usize::MAX).await.is_err());
            drop(guard);
            let mut seen = Vec::new();
            client.read_to_end(&mut seen).await.unwrap();
            assert_eq!(seen, data[..60], "only what the server itself wrote");
        }

        #[tokio::test]
        async fn a_window_update_flood_is_refused_and_a_download_is_not() {
            // 1,001 WINDOW_UPDATEs with nothing sent to the client: over the floor.
            let (mut client, server) = tokio::io::duplex(1 << 20);
            let mut guard = guarded(server, LIMIT);
            let verdict = guard.verdict();
            let updates = vec![frame(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1]); 1_001];
            client.write_all(&stream_of(&updates)).await.unwrap();
            let err = read_all(&mut guard, usize::MAX).await.unwrap_err();
            assert_eq!(err.to_string(), "HTTP/2 WINDOW_UPDATE flood");
            assert_eq!(verdict.get(), Some(Flood::WindowUpdate));

            // The same and ten times more from a client that was sent 4 MiB meanwhile (one
            // update per 363 bytes; a real client sends one per 16 KiB or more).
            let (mut client, server) = tokio::io::duplex(8 << 20);
            let mut guard = guarded(server, LIMIT);
            for _ in 0..256 {
                guard
                    .write_all(&frame(DATA, 0, 1, &[0; 16_384]))
                    .await
                    .unwrap();
            }
            let updates = stream_of(&vec![frame(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1]); 11_550]);
            client.write_all(&updates).await.unwrap();
            assert_eq!(read_all(&mut guard, updates.len()).await.unwrap(), updates);
            assert_eq!(guard.verdict().get(), None);
        }

        #[tokio::test]
        async fn a_connection_that_is_not_http2_is_left_alone() {
            // HTTP/1.1, then a WebSocket-like stream whose bytes happen to look like frames.
            let (mut client, server) = tokio::io::duplex(1 << 20);
            let mut guard = guarded(server, LIMIT);
            let mut sent = b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n".to_vec();
            sent.extend(frame(PING, 0, 0, &[0; 8]).repeat(5_000));
            sent.extend(frame(WINDOW_UPDATE, 0, 0, &[0; 4]).repeat(5_000));
            client.write_all(&sent).await.unwrap();
            assert_eq!(read_all(&mut guard, sent.len()).await.unwrap(), sent);
            assert_eq!(guard.verdict().get(), None);
            // And what the server writes is not followed as frames.
            guard
                .write_all(b"HTTP/1.1 101 Switching\r\n\r\n")
                .await
                .unwrap();
            assert!(guard.writes.at_frame_boundary());
            assert_eq!(guard.budget.bytes_written, 0);
        }

        #[tokio::test]
        async fn with_no_limit_frames_are_counted_and_nothing_is_closed() {
            let (mut client, server) = tokio::io::duplex(1 << 20);
            let mut guard = guarded(server, Limits { control_per_sec: 0 });
            let flood = stream_of(&vec![frame(SETTINGS, 0, 0, &[]); 30_000]);
            client.write_all(&flood).await.unwrap();
            assert_eq!(read_all(&mut guard, flood.len()).await.unwrap(), flood);
            assert_eq!(guard.verdict().get(), None);
            // The gauge an operator reads before choosing a limit saw it (it is process-wide:
            // another test may have pushed it higher).
            let peak = crate::metrics::METRICS.h2_control_frames_peak.load(Relaxed);
            assert!(peak >= 30_000, "peak {peak}");
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        fn any_frame() -> impl Strategy<Value = Vec<u8>> {
            (
                prop_oneof![
                    Just(DATA),
                    Just(HEADERS),
                    Just(PRIORITY),
                    Just(RST_STREAM),
                    Just(SETTINGS),
                    Just(PING),
                    Just(GOAWAY),
                    Just(WINDOW_UPDATE),
                    Just(CONTINUATION),
                    any::<u8>(),
                ],
                any::<u8>(),
                any::<u32>(),
                proptest::collection::vec(any::<u8>(), 0..300),
            )
                .prop_map(|(kind, flags, stream, payload)| frame(kind, flags, stream, &payload))
        }

        proptest! {
            /// However the transport cuts a valid stream of frames, the counts are those of
            /// the uncut stream: the parser never loses a frame boundary.
            #[test]
            fn any_chunking_gives_the_same_counts(
                frames in proptest::collection::vec(any_frame(), 0..40),
                cuts in proptest::collection::vec(1usize..64, 1..200),
            ) {
                let bytes = stream_of(&frames);
                let whole = count(&bytes, bytes.len().max(1));
                let mut c = FrameCounter::new();
                let mut got = Tally::default();
                let (mut at, mut i) = (0, 0);
                while at < bytes.len() {
                    let n = cuts[i % cuts.len()].min(bytes.len() - at);
                    got.add(c.feed(&bytes[at..at + n]));
                    at += n;
                    i += 1;
                }
                prop_assert_eq!(got, whole);
                // And the whole agrees with counting the frames one by one.
                let mut by_frame = Tally::default();
                for f in &frames {
                    let length = u32::from_be_bytes([0, f[0], f[1], f[2]]);
                    by_frame.add(classify(f[3], f[4], length));
                }
                prop_assert_eq!(whole, by_frame);
            }

            /// Arbitrary bytes never panic the parser, whatever the chunking.
            #[test]
            fn arbitrary_bytes_never_panic(
                bytes in proptest::collection::vec(any::<u8>(), 0..2000),
                chunk in 1usize..97,
                with_preface in any::<bool>(),
            ) {
                let mut input = if with_preface { PREFACE.to_vec() } else { Vec::new() };
                input.extend_from_slice(&bytes);
                let _ = count(&input, chunk);
            }
        }
    }
}
