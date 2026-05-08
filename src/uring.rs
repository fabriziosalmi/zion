// SPDX-License-Identifier: Apache-2.0
//! io_uring-accelerated accept loop for Linux.
//!
//! Uses multishot accept: one SQE yields multiple CQEs, so the kernel batches
//! many accepted connections per syscall. Falls back to standard tokio accept
//! on other platforms or when the feature is disabled.
//!
//! Enabled with: `cargo build --features io-uring-accept`
//!
//! ## Known issue (v0.2.0 — under investigation)
//!
//! Under load on Proxmox 9.1 LXC + kernel 6.17, AcceptMulti CQEs start
//! returning `res = -88 (ENOTSOCK)` continuously after the first burst
//! of connections. The same kernel + container privilege bracket is
//! independently verified to handle:
//!   * raw-syscall `IORING_OP_ACCEPT` with the multishot bit (works);
//!   * `io-uring` 0.7.11's `AcceptMulti` against a plain TCP listener
//!     (works, sustained);
//!   * the same crate against a listener tuned with the same flags
//!     zion sets (TCP_DEFER_ACCEPT / TCP_FASTOPEN / TCP_NODELAY,
//!     non-blocking — works, sustained).
//!
//! The error only surfaces under real bench load against zion. The
//! likely root cause is a race between TCP_FASTOPEN / TCP_DEFER_ACCEPT
//! and multishot's persistent SQE — consumed connections appear to
//! transition the listener fd into a state io_uring rejects, after
//! which every subsequent CQE on that SQE re-emits ENOTSOCK.
//!
//! Workaround: switch to single-shot `opcode::Accept` and resubmit on
//! each CQE. Costs a few hundred nanoseconds per accept (one extra
//! SQE push) but is robust. Defer until a load-faithful reproducer
//! lands; current production deployments stay on the tokio accept
//! loop until then.

#[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
mod inner {
    use io_uring::{opcode, types, IoUring};
    use std::net::SocketAddr;
    use std::os::unix::io::{FromRawFd, RawFd};
    use tokio::net::TcpStream;
    use tokio::sync::mpsc;

    /// Accepted connection ready for TLS handshake.
    pub struct AcceptedConn {
        pub stream: TcpStream,
        pub addr: SocketAddr,
    }

    /// Run io_uring multishot accept in a dedicated thread.
    /// Sends accepted connections to the returned channel.
    ///
    /// The listener_fd must be a bound, listening, non-blocking TCP socket.
    /// The channel buffer is sized to absorb bursts without back-pressure.
    pub fn spawn_uring_accept(listener_fd: RawFd, capacity: usize) -> mpsc::Receiver<AcceptedConn> {
        let (tx, rx) = mpsc::channel(capacity);

        std::thread::Builder::new()
            .name("io_uring-accept".into())
            .spawn(move || {
                uring_accept_loop(listener_fd, tx);
            })
            .expect("failed to spawn io_uring accept thread");

        rx
    }

    fn uring_accept_loop(listener_fd: RawFd, tx: mpsc::Sender<AcceptedConn>) {
        // Ring with 256 entries — enough for burst accept without overflowing
        let mut ring = IoUring::new(256).expect("io_uring init failed");

        // Submit initial multishot accept
        let accept_e = opcode::AcceptMulti::new(types::Fd(listener_fd))
            .build()
            .user_data(0x01);

        // SAFETY: Pushing to the SQ is memory safe as the `accept_e` entry is fully constructed
        // and its referenced memory (the file descriptor) remains valid.
        unsafe { ring.submission().push(&accept_e).expect("SQ full") };
        ring.submit().expect("io_uring submit failed");

        loop {
            // Wait for completions — retry on EINTR (signal handler fired)
            // instead of panicking, which would silently kill the accept thread.
            match ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => {
                    eprintln!("  io_uring fatal submit_and_wait error: {e}");
                    return;
                }
            }

            // Extract CQEs into a separate buffer to drop the mutable borrow on `ring`
            let mut completions = Vec::new();
            for cqe in ring.completion() {
                completions.push((cqe.result(), cqe.flags()));
            }

            for (fd, flags) in completions {
                if fd < 0 {
                    // EAGAIN or transient error — multishot still active
                    let errno = -fd;
                    if errno == libc::EAGAIN || errno == libc::EINTR {
                        continue;
                    }
                    // Permanent error — re-submit multishot
                    eprintln!("  io_uring accept error: errno {errno}");
                    let accept_e = opcode::AcceptMulti::new(types::Fd(listener_fd))
                        .build()
                        .user_data(0x01);
                    // SAFETY: Re-submission is safe because the file descriptor is owned by the listener
                    unsafe { ring.submission().push(&accept_e).ok() };
                    continue;
                }

                // Got a valid accepted fd
                let raw_fd = fd as RawFd;

                // Set non-blocking for tokio
                // SAFETY: FFI call to fcntl is safe because the fd is validated from io_uring completion
                unsafe {
                    let fcntl_flags = libc::fcntl(raw_fd, libc::F_GETFL);
                    libc::fcntl(raw_fd, libc::F_SETFL, fcntl_flags | libc::O_NONBLOCK);
                }

                // Get peer address
                let addr = match peer_addr(raw_fd) {
                    Some(a) => a,
                    None => {
                        // SAFETY: fd comes from the kernel and is valid to close
                        unsafe { libc::close(raw_fd) };
                        continue;
                    }
                };

                // Convert to tokio TcpStream
                // SAFETY: the raw_fd is fresh from the kernel accept call and exclusive to this thread
                let std_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd) };
                let stream = match TcpStream::from_std(std_stream) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                // Send to tokio workers — if channel full, drop connection (overload shed)
                if tx.try_send(AcceptedConn { stream, addr }).is_err() {
                    // Channel full — connection dropped (back-pressure)
                }

                // Check IORING_CQE_F_MORE — if not set, multishot was cancelled
                const IORING_CQE_F_MORE: u32 = 1 << 1;
                if flags & IORING_CQE_F_MORE == 0 {
                    // Re-submit multishot accept
                    let accept_e = opcode::AcceptMulti::new(types::Fd(listener_fd))
                        .build()
                        .user_data(0x01);
                    // SAFETY: pushing a fresh accept entry for the listener fd is structurally sound
                    unsafe { ring.submission().push(&accept_e).ok() };
                    ring.submit().ok();
                }
            }
        }
    }

    fn peer_addr(fd: RawFd) -> Option<SocketAddr> {
        // SAFETY: zeroed sockaddr_storage is a perfectly valid memory structure for the OS to populate
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: fd is valid and storage bounds are bounded by socklen_t len parameter
        let ret = unsafe {
            libc::getpeername(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len)
        };
        if ret != 0 {
            return None;
        }

        match storage.ss_family as i32 {
            libc::AF_INET => {
                // SAFETY: Family matched AF_INET, so mapping storage memory into sockaddr_in is memory-safe
                let addr = unsafe { &*(&storage as *const _ as *const libc::sockaddr_in) };
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                Some(SocketAddr::from((ip, u16::from_be(addr.sin_port))))
            }
            libc::AF_INET6 => {
                // SAFETY: Family matched AF_INET6, so mapping storage memory into sockaddr_in6 is memory-safe
                let addr = unsafe { &*(&storage as *const _ as *const libc::sockaddr_in6) };
                let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                Some(SocketAddr::from((ip, u16::from_be(addr.sin6_port))))
            }
            _ => None,
        }
    }
}

// `spawn_uring_accept` is consumed externally (main.rs spawns the
// uring accept thread). `AcceptedConn` re-export is required because
// the cfg-gated `run_https_accept_loop` signature in main.rs names it
// in its parameter list — without the re-export the type is reachable
// only as `inner::AcceptedConn`, which is an inaccessible private path.
//
// (The re-export was removed once in v0.1.7 as suspected dead code;
// Phase 1.5 reintroduced the dependency by giving the io_uring branch
// an `Option<Receiver<AcceptedConn>>` parameter rather than hiding the
// receiver inside a dyn-typed boundary. Re-exposing the type here is
// the smallest fix.)
#[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
pub use inner::{spawn_uring_accept, AcceptedConn};
