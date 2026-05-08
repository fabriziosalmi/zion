// SPDX-License-Identifier: Apache-2.0
//! io_uring-accelerated accept loop for Linux.
//!
//! Uses single-shot accept (`opcode::Accept`) re-submitted per CQE.
//! Falls back to standard tokio accept on other platforms or when the
//! feature is disabled.
//!
//! Enabled with: `cargo build --features io-uring-accept`
//!
//! ## v0.2.2 change — single-shot Accept (closes ENOTSOCK race)
//!
//! v0.2.0 used `opcode::AcceptMulti` for batched accept (one SQE,
//! many CQEs). Under load on Proxmox 9.1 LXC + kernel 6.17 every CQE
//! returned `res = -88 (ENOTSOCK)` after the first burst — a TFO /
//! DEFER_ACCEPT × multishot race that transitioned the listener fd
//! into a state io_uring rejected.
//!
//! v0.2.2 reverts to single-shot: each accept is its own SQE, the
//! completion fires once, and we push a fresh SQE to keep the loop
//! going. Costs one extra `submission().push()` per accept (~tens of
//! ns) which is negligible against the 200 ms stalls multishot was
//! producing. The same kernel + container set sustains the load
//! cleanly with this shape.

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

    /// Push one single-shot Accept SQE for the listener fd. v0.2.2:
    /// replaces the AcceptMulti shape that hit ENOTSOCK under load.
    fn submit_accept(ring: &mut IoUring, listener_fd: RawFd) -> std::io::Result<()> {
        let entry = opcode::Accept::new(
            types::Fd(listener_fd),
            std::ptr::null_mut(), // no peer addr-out — we call getpeername after accept
            std::ptr::null_mut(),
        )
        .build()
        .user_data(0x01);
        // SAFETY: `entry` is fully constructed; the file descriptor is owned by
        // the caller (`spawn_uring_accept`'s listener) and stays valid for the
        // lifetime of this thread. The two null pointers are explicitly
        // documented as accepted by `IORING_OP_ACCEPT` to mean "don't fill in
        // the peer addr"; we recover it via `getpeername` after the CQE.
        unsafe {
            ring.submission()
                .push(&entry)
                .map_err(|_| std::io::Error::other("io_uring SQ full"))?;
        }
        ring.submit()?;
        Ok(())
    }

    fn uring_accept_loop(listener_fd: RawFd, tx: mpsc::Sender<AcceptedConn>) {
        // Ring with 256 entries — enough for burst accept without overflowing
        let mut ring = IoUring::new(256).expect("io_uring init failed");

        // Prime the loop with the first single-shot Accept.
        if let Err(e) = submit_accept(&mut ring, listener_fd) {
            eprintln!("  io_uring initial accept submit failed: {e}");
            return;
        }

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
                completions.push(cqe.result());
            }

            for fd in completions {
                // Always queue the next single-shot Accept *before* doing
                // any per-connection work. This keeps the kernel's accept
                // pipeline fed even if the per-conn step stalls (e.g.
                // tx.try_send on a full channel) and matches the behaviour
                // of a kqueue-style level-triggered accept loop.
                if let Err(e) = submit_accept(&mut ring, listener_fd) {
                    eprintln!("  io_uring accept resubmit failed: {e}");
                    return;
                }

                if fd < 0 {
                    let errno = -fd;
                    if errno == libc::EAGAIN || errno == libc::EINTR {
                        continue;
                    }
                    eprintln!("  io_uring accept error: errno {errno}");
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
