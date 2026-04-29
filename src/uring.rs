//! io_uring-accelerated accept loop for Linux.
//!
//! Uses multishot accept: one SQE yields multiple CQEs, so the kernel batches
//! many accepted connections per syscall. Falls back to standard tokio accept
//! on other platforms or when the feature is disabled.
//!
//! Enabled with: `cargo build --features io-uring-accept`

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
            // Wait for completions
            ring.submit_and_wait(1).expect("io_uring wait failed");

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
                    eprintln!("  io_uring accept error: errno {}", errno);
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

// Only `spawn_uring_accept` is consumed externally (by main.rs).
// `AcceptedConn` is the channel item type — internal to this module —
// and was previously re-exported but never used by any caller, so the
// re-export was dead.
#[cfg(all(target_os = "linux", feature = "io-uring-accept"))]
pub use inner::spawn_uring_accept;
