// SPDX-License-Identifier: Apache-2.0
//! io_uring read/write data path — `IoUringStream` (issue #51, ADR-0009).
//!
//! Increment 1 (skeleton): a single dedicated driver thread owns ONE
//! `io_uring` plus a slab of per-connection slots; `IoUringStream` is a
//! `Send + Unpin + 'static` handle that implements tokio's
//! `AsyncRead`/`AsyncWrite` by talking to that driver. This is the
//! completion→poll bridge `uring.rs:211` deferred.
//!
//! ## Why this shape
//! io_uring is completion-based (the kernel owns the buffer from SQE-submit
//! until the CQE), tokio's traits are poll-based with a *borrowed* buffer
//! that hyper may drop the instant `poll_read` returns `Pending`. So the
//! kernel never sees a caller buffer: each slot owns a `read_buf`/`write_buf`
//! and we `memcpy` across the poll boundary.
//!
//! ## v1 soundness model (writable without a local Linux compiler)
//! Each slot's mutable state lives behind a `Mutex<SlotInner>`. The kernel
//! writes into `read_buf` only while a `Recv` is in flight — a window during
//! which NO Rust reference to that `Box<[u8]>` is live (we handed the raw
//! pointer to the SQE and don't touch it; the `Box` heap address is stable
//! and the slot is kept alive until every in-flight CQE is reaped). The lock
//! only guards state transitions and the copy-out at `Ready`. The zero-lock
//! atomic/`UnsafeCell` optimisation is a later increment, once this is proven
//! correct (ADR-0009).
//!
//! ## Safety net on Drop
//! `IoUringStream::drop` sends a non-blocking `Orphan` command and returns
//! immediately. The driver frees the slot (and closes the fd) ONLY when its
//! in-flight-op count reaches 0, so a dropped stream with a `Recv`/`Send`
//! still in flight can never use-after-free.

use std::io;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures_util::task::AtomicWaker;
use io_uring::{opcode, squeue, types, IoUring};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// io_uring submission/completion ring depth for the rw driver.
const RING_DEPTH: u32 = 4096;
/// Per-direction buffer size (one TLS-record-ish granularity). Tunable.
const BUF_SIZE: usize = 16 * 1024;
/// Max concurrently-registered connections on this single ring. Reconciled
/// with `conn_limit` in a later increment (ADR-0009 §memory bound).
const MAX_SLOTS: usize = 8192;

// `user_data` layout: (slot:u32) << 32 | (gen:u16) << 16 | op_kind:u16.
const OP_READ: u64 = 0;
const OP_WRITE: u64 = 1;
/// Reserved `user_data` for the self-eventfd interrupt poll.
const UD_INTERRUPT: u64 = u64::MAX;

#[inline]
fn pack_ud(slot: u32, gen: u16, op: u64) -> u64 {
    ((slot as u64) << 32) | ((gen as u64) << 16) | op
}
#[inline]
fn unpack_ud(ud: u64) -> (u32, u16, u64) {
    (
        ((ud >> 32) & 0xFFFF_FFFF) as u32,
        ((ud >> 16) & 0xFFFF) as u16,
        ud & 0xFFFF,
    )
}

/// Driver command from a handle (or its `Drop`) to the driver thread.
enum DriverCmd {
    /// Arm a `Recv` into the slot's read buffer.
    ArmRead { slot: u32, gen: u16 },
    /// Submit the bytes already staged in the slot's write buffer.
    Write { slot: u32, gen: u16 },
    /// The handle was dropped — orphan + reclaim the slot when safe.
    Orphan { slot: u32, gen: u16 },
}

#[derive(Clone, Copy)]
enum ReadState {
    /// No read armed; a `poll_read` will request one.
    Idle,
    /// A `poll_read` requested an arm; the driver hasn't pushed the SQE yet.
    Arming,
    /// A `Recv` SQE is in flight; the kernel owns `read_buf`.
    Submitted,
    /// Data available in `read_buf[pos..filled]` to copy to the caller.
    Ready { filled: usize, pos: usize },
    /// Peer half-closed (Recv returned 0).
    Eof,
    /// Recv failed with this errno.
    Err(i32),
}

#[derive(Clone, Copy)]
enum WriteState {
    /// No write in flight; `poll_write` may stage one.
    Idle,
    /// `write_buf[off..len]` still to be sent (a `Send` SQE is/will be in flight).
    Submitted { off: usize, len: usize },
    /// Send failed with this errno.
    Err(i32),
}

/// Driver-owned per-slot state, guarded by the slot mutex.
struct SlotInner {
    fd: RawFd,
    gen: u16,
    /// Occupancy flag; written on register/reclaim. Read via `/metrics` later.
    #[allow(dead_code)]
    in_use: bool,
    orphaned: bool,
    /// Count of in-flight SQEs (read + write) referencing this slot's buffers.
    /// The slot is reclaimed only when this reaches 0.
    inflight: u32,
    read_buf: Box<[u8]>,
    write_buf: Box<[u8]>,
    read_state: ReadState,
    write_state: WriteState,
}

impl SlotInner {
    fn empty() -> Self {
        Self {
            fd: -1,
            gen: 0,
            in_use: false,
            orphaned: false,
            inflight: 0,
            read_buf: Box::new([]),
            write_buf: Box::new([]),
            read_state: ReadState::Idle,
            write_state: WriteState::Idle,
        }
    }
}

struct SlotShared {
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
    inner: Mutex<SlotInner>,
}

/// Shared driver handle: connection registry + command channel. Cloned into
/// every `IoUringStream`. `Send + Sync` (all fields are).
pub struct Shared {
    cmd_tx: UnboundedSender<DriverCmd>,
    eventfd: RawFd,
    slots: Box<[SlotShared]>,
    free: Mutex<Vec<u32>>,
}

impl Shared {
    #[inline]
    fn kick(&self) {
        // Wake the driver out of `submit_and_wait` by posting to the eventfd.
        let one: u64 = 1;
        // SAFETY: write 8 bytes of a u64 to a valid eventfd; EAGAIN is fine.
        unsafe {
            libc::write(self.eventfd, &one as *const u64 as *const libc::c_void, 8);
        }
    }

    fn send(&self, cmd: DriverCmd) {
        // Unbounded send never blocks; if the driver is gone the process is
        // already aborting (driver death = abort, ADR-0009).
        let _ = self.cmd_tx.send(cmd);
        self.kick();
    }

    /// Register an accepted socket `fd` and return a stream handle, or `None`
    /// if the slab is full (caller falls back to the tokio path). The handle
    /// takes ownership of `fd` (closed by the driver on reclaim).
    pub fn register(self: &Arc<Self>, fd: RawFd) -> Option<IoUringStream> {
        let slot = self.free.lock().unwrap().pop()?;
        let s = &self.slots[slot as usize];
        let mut inner = s.inner.lock().unwrap();
        inner.gen = inner.gen.wrapping_add(1);
        inner.fd = fd;
        inner.in_use = true;
        inner.orphaned = false;
        inner.inflight = 0;
        inner.read_buf = vec![0u8; BUF_SIZE].into_boxed_slice();
        inner.write_buf = vec![0u8; BUF_SIZE].into_boxed_slice();
        inner.read_state = ReadState::Idle;
        inner.write_state = WriteState::Idle;
        let gen = inner.gen;
        // Clear any stale waker registrations from the previous tenant.
        s.read_waker.take();
        s.write_waker.take();
        drop(inner);
        Some(IoUringStream {
            shared: self.clone(),
            slot,
            gen,
        })
    }

    /// Introspection (tests today, `/metrics` later): slots currently
    /// registered and not yet reclaimed.
    #[allow(dead_code)]
    pub(crate) fn active_slots(&self) -> usize {
        MAX_SLOTS - self.free.lock().unwrap().len()
    }
}

/// Start the rw driver: create the ring + eventfd + slab, spawn the driver
/// thread, and return the shared handle. The driver runs for the process
/// lifetime (ADR-0009: a driver panic aborts the process).
pub fn start() -> io::Result<Arc<Shared>> {
    let ring = IoUring::new(RING_DEPTH)?;
    // SAFETY: eventfd(2) with valid flags; returns -1 on error.
    let eventfd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if eventfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let slots: Vec<SlotShared> = (0..MAX_SLOTS)
        .map(|_| SlotShared {
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
            inner: Mutex::new(SlotInner::empty()),
        })
        .collect();
    let free: Vec<u32> = (0..MAX_SLOTS as u32).collect();
    let (cmd_tx, cmd_rx) = unbounded_channel();
    let shared = Arc::new(Shared {
        cmd_tx,
        eventfd,
        slots: slots.into_boxed_slice(),
        free: Mutex::new(free),
    });
    let driver_shared = shared.clone();
    std::thread::Builder::new()
        .name("io_uring-rw".into())
        .spawn(move || driver_loop(ring, driver_shared, cmd_rx, eventfd))
        .map_err(io::Error::other)?;
    Ok(shared)
}

fn interrupt_entry(eventfd: RawFd) -> squeue::Entry {
    opcode::PollAdd::new(types::Fd(eventfd), libc::POLLIN as u32)
        .build()
        .user_data(UD_INTERRUPT)
}

fn push_all(ring: &mut IoUring, entries: &[squeue::Entry]) {
    for e in entries {
        loop {
            // SAFETY: each entry's referenced buffer/fd is kept valid until
            // its CQE is reaped (slot keep-alive); push copies the SQE.
            let pushed = unsafe { ring.submission().push(e) };
            if pushed.is_ok() {
                break;
            }
            // SQ full: flush to the kernel to free ring space, then retry.
            if ring.submit().is_err() {
                // Best effort; a failed submit here will surface on the next
                // submit_and_wait. Drop out to avoid a busy loop.
                break;
            }
        }
    }
}

fn driver_loop(
    mut ring: IoUring,
    shared: Arc<Shared>,
    mut rx: UnboundedReceiver<DriverCmd>,
    eventfd: RawFd,
) {
    let mut intr_buf = [0u8; 8];
    push_all(&mut ring, &[interrupt_entry(eventfd)]);
    let _ = ring.submit();

    loop {
        match ring.submit_and_wait(1) {
            Ok(_) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => {
                eprintln!("io_uring-rw driver fatal submit_and_wait: {e}");
                std::process::abort();
            }
        }

        // 1) Drain completions (collect first so we don't hold the CQ borrow
        // while locking slots).
        let mut comps: Vec<(u64, i32)> = Vec::new();
        {
            let cq = ring.completion();
            for cqe in cq {
                comps.push((cqe.user_data(), cqe.result()));
            }
        }
        let mut followups: Vec<squeue::Entry> = Vec::new();
        let mut rearm_intr = false;
        for (ud, res) in comps {
            if ud == UD_INTERRUPT {
                rearm_intr = true;
                continue;
            }
            if let Some(e) = process_cqe(&shared, ud, res) {
                followups.push(e);
            }
        }
        if rearm_intr {
            // Drain the eventfd counter and re-arm the poll.
            // SAFETY: read up to 8 bytes into a valid stack buffer.
            unsafe {
                libc::read(eventfd, intr_buf.as_mut_ptr() as *mut libc::c_void, 8);
            }
            followups.push(interrupt_entry(eventfd));
        }

        // 2) Drain commands → SQEs.
        while let Ok(cmd) = rx.try_recv() {
            if let Some(e) = process_cmd(&shared, cmd) {
                followups.push(e);
            }
        }

        // 3) Submit everything.
        push_all(&mut ring, &followups);
        let _ = ring.submit();
    }
}

/// Handle a completion. Returns an optional follow-up SQE (e.g. a partial
/// `Send` remainder).
fn process_cqe(shared: &Arc<Shared>, ud: u64, res: i32) -> Option<squeue::Entry> {
    let (slot, gen, op) = unpack_ud(ud);
    let s = &shared.slots[slot as usize];
    let mut inner = s.inner.lock().unwrap();
    if inner.gen != gen {
        // Stale CQE for a previous tenant — should not happen (reclaim waits
        // for inflight==0) but discard defensively without touching the new
        // tenant's state.
        return None;
    }
    inner.inflight = inner.inflight.saturating_sub(1);

    let mut followup = None;
    match op {
        OP_READ => {
            inner.read_state = if res < 0 {
                ReadState::Err(-res)
            } else if res == 0 {
                ReadState::Eof
            } else {
                ReadState::Ready {
                    filled: res as usize,
                    pos: 0,
                }
            };
        }
        OP_WRITE => {
            if res < 0 {
                inner.write_state = WriteState::Err(-res);
            } else if let WriteState::Submitted { off, len } = inner.write_state {
                let new_off = off + res as usize;
                if new_off >= len {
                    inner.write_state = WriteState::Idle;
                } else {
                    // Partial send: resubmit the remainder.
                    inner.write_state = WriteState::Submitted { off: new_off, len };
                    let fd = inner.fd;
                    // SAFETY: write_buf is alive (slot kept alive) and new_off < len.
                    let ptr = unsafe { inner.write_buf.as_ptr().add(new_off) };
                    inner.inflight += 1;
                    followup = Some(
                        opcode::Send::new(types::Fd(fd), ptr, (len - new_off) as u32)
                            .build()
                            .user_data(pack_ud(slot, gen, OP_WRITE)),
                    );
                }
            }
        }
        _ => {}
    }

    // Reclaim if orphaned and fully drained.
    if inner.orphaned && inner.inflight == 0 {
        let fd = inner.fd;
        inner.in_use = false;
        inner.read_buf = Box::new([]);
        inner.write_buf = Box::new([]);
        drop(inner);
        // SAFETY: fd was owned by this slot and has no more in-flight ops.
        unsafe {
            libc::close(fd);
        }
        shared.free.lock().unwrap().push(slot);
        return followup;
    }

    let read_done = matches!(op, OP_READ);
    let write_idle_or_err = matches!(inner.write_state, WriteState::Idle | WriteState::Err(_));
    drop(inner);
    if read_done {
        s.read_waker.wake();
    } else if write_idle_or_err {
        // Only wake the writer when the whole staged buffer drained (or errored).
        s.write_waker.wake();
    }
    followup
}

/// Handle a command. Returns an optional SQE to submit.
fn process_cmd(shared: &Arc<Shared>, cmd: DriverCmd) -> Option<squeue::Entry> {
    match cmd {
        DriverCmd::ArmRead { slot, gen } => {
            let s = &shared.slots[slot as usize];
            let mut inner = s.inner.lock().unwrap();
            if inner.gen != gen || inner.orphaned {
                return None;
            }
            if !matches!(inner.read_state, ReadState::Arming) {
                return None;
            }
            let fd = inner.fd;
            let len = inner.read_buf.len() as u32;
            let ptr = inner.read_buf.as_mut_ptr();
            inner.read_state = ReadState::Submitted;
            inner.inflight += 1;
            Some(
                opcode::Recv::new(types::Fd(fd), ptr, len)
                    .build()
                    .user_data(pack_ud(slot, gen, OP_READ)),
            )
        }
        DriverCmd::Write { slot, gen } => {
            let s = &shared.slots[slot as usize];
            let mut inner = s.inner.lock().unwrap();
            if inner.gen != gen || inner.orphaned {
                return None;
            }
            if let WriteState::Submitted { off, len } = inner.write_state {
                let fd = inner.fd;
                // SAFETY: off < len <= write_buf.len(); buffer alive.
                let ptr = unsafe { inner.write_buf.as_ptr().add(off) };
                inner.inflight += 1;
                Some(
                    opcode::Send::new(types::Fd(fd), ptr, (len - off) as u32)
                        .build()
                        .user_data(pack_ud(slot, gen, OP_WRITE)),
                )
            } else {
                None
            }
        }
        DriverCmd::Orphan { slot, gen } => {
            let s = &shared.slots[slot as usize];
            let mut inner = s.inner.lock().unwrap();
            if inner.gen != gen {
                return None;
            }
            inner.orphaned = true;
            if inner.inflight == 0 {
                let fd = inner.fd;
                inner.in_use = false;
                inner.read_buf = Box::new([]);
                inner.write_buf = Box::new([]);
                drop(inner);
                // SAFETY: no in-flight ops reference this fd's buffers.
                unsafe {
                    libc::close(fd);
                }
                shared.free.lock().unwrap().push(slot);
            }
            // else: reclaimed by process_cqe when the last CQE lands. (A
            // parked Recv with no data stays pinned until peer activity; a
            // best-effort AsyncCancel is a later increment.)
            None
        }
    }
}

/// `Send + Unpin + 'static` stream handle backed by the io_uring rw driver.
pub struct IoUringStream {
    shared: Arc<Shared>,
    slot: u32,
    gen: u16,
}

impl AsyncRead for IoUringStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let s = &self.shared.slots[self.slot as usize];
        let mut inner = s.inner.lock().unwrap();
        match inner.read_state {
            ReadState::Idle => {
                inner.read_state = ReadState::Arming;
                s.read_waker.register(cx.waker());
                drop(inner);
                self.shared.send(DriverCmd::ArmRead {
                    slot: self.slot,
                    gen: self.gen,
                });
                Poll::Pending
            }
            ReadState::Arming | ReadState::Submitted => {
                s.read_waker.register(cx.waker());
                Poll::Pending
            }
            ReadState::Ready { filled, pos } => {
                let n = std::cmp::min(buf.remaining(), filled - pos);
                buf.put_slice(&inner.read_buf[pos..pos + n]);
                let new_pos = pos + n;
                if new_pos >= filled {
                    inner.read_state = ReadState::Idle;
                    drop(inner);
                    // Re-arm the next Recv eagerly so the pipeline stays full.
                    self.shared.send(DriverCmd::ArmRead {
                        slot: self.slot,
                        gen: self.gen,
                    });
                } else {
                    inner.read_state = ReadState::Ready {
                        filled,
                        pos: new_pos,
                    };
                }
                Poll::Ready(Ok(()))
            }
            ReadState::Eof => Poll::Ready(Ok(())),
            ReadState::Err(e) => Poll::Ready(Err(io::Error::from_raw_os_error(e))),
        }
    }
}

impl AsyncWrite for IoUringStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let s = &self.shared.slots[self.slot as usize];
        let mut inner = s.inner.lock().unwrap();
        match inner.write_state {
            WriteState::Idle => {
                let n = std::cmp::min(data.len(), inner.write_buf.len());
                inner.write_buf[..n].copy_from_slice(&data[..n]);
                inner.write_state = WriteState::Submitted { off: 0, len: n };
                drop(inner);
                self.shared.send(DriverCmd::Write {
                    slot: self.slot,
                    gen: self.gen,
                });
                Poll::Ready(Ok(n))
            }
            WriteState::Submitted { .. } => {
                // One staged write at a time (v1 backpressure).
                s.write_waker.register(cx.waker());
                Poll::Pending
            }
            WriteState::Err(e) => Poll::Ready(Err(io::Error::from_raw_os_error(e))),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let s = &self.shared.slots[self.slot as usize];
        let mut inner = s.inner.lock().unwrap();
        match inner.write_state {
            WriteState::Idle => {
                // Gather as many slices as fit into the one staged buffer and
                // submit a SINGLE Send — rustls drives bulk writes vectored
                // (up to 64 slices), so this avoids one Send per slice and the
                // per-flush serialization that would otherwise kill throughput.
                let cap = inner.write_buf.len();
                let mut n = 0;
                for b in bufs {
                    if n >= cap {
                        break;
                    }
                    let take = std::cmp::min(b.len(), cap - n);
                    inner.write_buf[n..n + take].copy_from_slice(&b[..take]);
                    n += take;
                }
                if n == 0 {
                    return Poll::Ready(Ok(0));
                }
                inner.write_state = WriteState::Submitted { off: 0, len: n };
                drop(inner);
                self.shared.send(DriverCmd::Write {
                    slot: self.slot,
                    gen: self.gen,
                });
                Poll::Ready(Ok(n))
            }
            WriteState::Submitted { .. } => {
                s.write_waker.register(cx.waker());
                Poll::Pending
            }
            WriteState::Err(e) => Poll::Ready(Err(io::Error::from_raw_os_error(e))),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = &self.shared.slots[self.slot as usize];
        let inner = s.inner.lock().unwrap();
        match inner.write_state {
            WriteState::Idle => Poll::Ready(Ok(())),
            WriteState::Submitted { .. } => {
                s.write_waker.register(cx.waker());
                Poll::Pending
            }
            WriteState::Err(e) => Poll::Ready(Err(io::Error::from_raw_os_error(e))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any staged write first.
        let fd = {
            let s = &self.shared.slots[self.slot as usize];
            let inner = s.inner.lock().unwrap();
            match inner.write_state {
                WriteState::Submitted { .. } => {
                    s.write_waker.register(cx.waker());
                    return Poll::Pending;
                }
                WriteState::Err(e) => return Poll::Ready(Err(io::Error::from_raw_os_error(e))),
                WriteState::Idle => inner.fd,
            }
        };
        // Half-close the write side so the peer observes EOF.
        // SAFETY: fd is valid for the lifetime of this handle.
        unsafe {
            libc::shutdown(fd, libc::SHUT_WR);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for IoUringStream {
    fn drop(&mut self) {
        // Non-blocking: the driver reclaims the slot + closes the fd once all
        // in-flight ops are reaped (UAF-proof, ADR-0009).
        self.shared.send(DriverCmd::Orphan {
            slot: self.slot,
            gen: self.gen,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// AF_UNIX SOCK_STREAM socketpair → (a, b) raw fds.
    fn socketpair() -> (RawFd, RawFd) {
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        (fds[0], fds[1])
    }

    fn tokio_peer(fd: RawFd) -> tokio::net::UnixStream {
        // SAFETY: fd is a freshly-created connected SOCK_STREAM end.
        let std = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std.set_nonblocking(true).unwrap();
        tokio::net::UnixStream::from_std(std).unwrap()
    }

    fn payload() -> Vec<u8> {
        (0..1024 * 1024).map(|i| (i % 251) as u8).collect()
    }

    // peer -> IoUringStream: exercises poll_read (the Recv path) end to end.
    #[tokio::test]
    async fn echo_read_1mib_byte_exact() {
        let shared = start().expect("driver start");
        let (fa, fb) = socketpair();
        let mut a = shared.register(fa).expect("register");
        let mut peer = tokio_peer(fb);
        let data = payload();

        let d2 = data.clone();
        let writer = tokio::spawn(async move {
            peer.write_all(&d2).await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        a.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), data.len());
        assert!(got == data, "read payload mismatch");
        writer.await.unwrap();
    }

    // IoUringStream -> peer: exercises poll_write + poll_shutdown (Send path).
    #[tokio::test]
    async fn echo_write_1mib_byte_exact() {
        let shared = start().expect("driver start");
        let (fa, fb) = socketpair();
        let mut a = shared.register(fa).expect("register");
        let mut peer = tokio_peer(fb);
        let data = payload();

        let d2 = data.clone();
        let writer = tokio::spawn(async move {
            a.write_all(&d2).await.unwrap();
            a.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), data.len());
        assert!(got == data, "write payload mismatch");
        writer.await.unwrap();
    }

    // EOF: peer half-closes; reader gets the full payload then a clean 0, and
    // EOF is sticky (a second read also yields 0).
    #[tokio::test]
    async fn eof_is_clean_and_sticky() {
        let shared = start().unwrap();
        let (fa, fb) = socketpair();
        let mut a = shared.register(fa).unwrap();
        let mut peer = tokio_peer(fb);
        peer.write_all(b"hello uring").await.unwrap();
        peer.shutdown().await.unwrap();
        drop(peer);
        let mut got = Vec::new();
        a.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got, b"hello uring");
        // Sticky EOF.
        let n = a.read(&mut [0u8; 8]).await.unwrap();
        assert_eq!(n, 0);
    }

    // RST mid-read must surface as an Err, not a silent EOF. TCP loopback +
    // SO_LINGER 0 forces a reset.
    #[tokio::test]
    async fn reset_surfaces_as_error() {
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::{AsRawFd, IntoRawFd};
        let shared = start().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut a = shared.register(server.into_raw_fd()).unwrap();
        // Arm a Recv with no data available (times out → stays in flight).
        let read = tokio::time::timeout(Duration::from_millis(100), a.read(&mut [0u8; 64])).await;
        assert!(read.is_err(), "expected a pending read");
        // Force a RST on close: SO_LINGER {on, 0} (std::net::set_linger is
        // unstable on stable Rust, so set the sockopt via libc).
        let lin = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: setsockopt on a valid TCP fd with a correctly-sized linger.
        unsafe {
            libc::setsockopt(
                peer.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &lin as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
        drop(peer);
        let r = tokio::time::timeout(Duration::from_secs(2), a.read(&mut [0u8; 64]))
            .await
            .expect("read should resolve after RST");
        assert!(r.is_err(), "RST must surface as Err, got {r:?}");
    }

    // Drop while a Recv is in flight: the slot must NOT be reclaimed until the
    // CQE lands (slot keep-alive is the UAF-proof mechanism), then it must.
    #[tokio::test]
    async fn drop_with_inflight_recv_reclaims_only_after_cqe() {
        let shared = start().unwrap();
        let (fa, fb) = socketpair();
        let mut a = shared.register(fa).unwrap();
        let peer = tokio_peer(fb);
        assert_eq!(shared.active_slots(), 1);
        // Arm a Recv (no data → in flight).
        let read = tokio::time::timeout(Duration::from_millis(100), a.read(&mut [0u8; 64])).await;
        assert!(read.is_err());
        drop(a); // Orphan — but the Recv is still in flight.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            shared.active_slots(),
            1,
            "slot freed while Recv in flight (UAF risk)"
        );
        // Close the peer → the Recv completes (EOF) → driver reclaims.
        drop(peer);
        let mut reclaimed = false;
        for _ in 0..200 {
            if shared.active_slots() == 0 {
                reclaimed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            reclaimed,
            "slot not reclaimed after the in-flight Recv completed"
        );
    }

    // Many concurrent connections through the single driver ring: no lost
    // wakeups / hangs, all byte-exact, and every slot reclaims at the end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_connections_echo() {
        let shared = start().unwrap();
        const N: usize = 64;
        const SZ: usize = 64 * 1024;
        let mut tasks = Vec::new();
        for k in 0..N {
            let (fa, fb) = socketpair();
            let mut a = shared.register(fa).unwrap();
            let mut peer = tokio_peer(fb);
            tasks.push(tokio::spawn(async move {
                let data: Vec<u8> = (0..SZ).map(|i| ((i + k) % 251) as u8).collect();
                let d2 = data.clone();
                let w = tokio::spawn(async move {
                    peer.write_all(&d2).await.unwrap();
                    peer.shutdown().await.unwrap();
                });
                let mut got = Vec::new();
                a.read_to_end(&mut got).await.unwrap();
                w.await.unwrap();
                assert!(got == data, "conn {k} mismatch");
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let mut ok = false;
        for _ in 0..200 {
            if shared.active_slots() == 0 {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ok, "slots not reclaimed after all conns done");
    }

    // Increment 6: backpressure. A slow consumer must throttle the writer
    // (poll_write returns Pending while a Send is in flight — the one-staged-
    // buffer high-water) WITHOUT deadlocking, with memory bounded to that one
    // buffer, and the payload arrives byte-exact.
    #[tokio::test]
    async fn backpressure_slow_consumer_no_deadlock() {
        let shared = start().unwrap();
        let (fa, fb) = socketpair();
        let mut a = shared.register(fa).unwrap();
        let mut peer = tokio_peer(fb);
        let data = payload(); // 1 MiB
        let total = data.len();

        let d2 = data.clone();
        // Writer: push the whole payload through the io_uring stream. If
        // backpressure deadlocked, this never completes and the test times out.
        let w = tokio::spawn(async move {
            a.write_all(&d2).await.unwrap();
            a.shutdown().await.unwrap();
        });

        // Slow reader: drain in small chunks with periodic pauses so the socket
        // buffer fills and the writer is forced to wait on backpressure.
        let mut got = Vec::with_capacity(total);
        let mut chunk = [0u8; 4096];
        loop {
            let n = peer.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
            if got.len() % (64 * 1024) < 4096 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        w.await.unwrap();
        assert_eq!(got.len(), total);
        assert!(got == data, "backpressure payload mismatch");
    }
}
