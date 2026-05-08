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

// ─────────────────────────────────────────────────────────────────────────────
// `io-uring-rw` capability probe (issue #51).
//
// The full IORING_OP_READV_FIXED / WRITEV path that replaces tokio's
// read/write half of accepted connections is tracked on a follow-up:
// implementing AsyncRead + AsyncWrite over io_uring without papering
// over a delegating stub requires a careful tokio-reactor integration
// we don't ship half-baked. Until that lands, the `io-uring-rw`
// feature gate enables only this probe — useful regardless because:
//
//   * it surfaces the kernel version on `/metrics` and at boot, so
//     deployments can see at a glance whether the host is ready for
//     the follow-up;
//   * it pins the public probe API now, so the follow-up doesn't have
//     to rev a second feature flag.
//
// The probe lives outside the existing `inner` mod (which is gated on
// `io-uring-accept`) because we want it to compile on the bare lib too —
// the `bootstrap::Platform` consumer reads it from any feature combo.
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum kernel version we'd target for io_uring-driven read/write
/// vectored I/O. 5.19 is when `IORING_OP_READV_FIXED` plus the rest of
/// the rw surface we'd consume reaches mainline-stable on most distros.
///
/// `#[allow(dead_code)]`: only consumed on Linux; on macOS / Windows
/// the `probe_io_uring_rw_supported` branch that uses it is
/// `cfg`-stripped. The const stays in module scope so external
/// diagnostic tooling that wants to format-print it sees one source
/// of truth.
#[allow(dead_code)]
pub const IO_URING_RW_MIN_KERNEL: (u32, u32) = (5, 19);

/// Probe the running kernel's `release` string (via `uname(2)`) and
/// return whether it satisfies [`IO_URING_RW_MIN_KERNEL`]. Always
/// returns `false` on non-Linux. The probe is cheap (one syscall +
/// short string parse) so it's fine to call from boot.
pub fn probe_io_uring_rw_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        kernel_release_at_least(IO_URING_RW_MIN_KERNEL.0, IO_URING_RW_MIN_KERNEL.1)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Read the kernel release via `uname(2)` and return whether it is at
/// least `(maj, min)`. Returns `false` on parse failure or on
/// non-Linux. Public so the doctor + diagnostic surfaces can read the
/// same value the bootstrap probe records.
#[cfg(target_os = "linux")]
pub fn kernel_release_at_least(maj_required: u32, min_required: u32) -> bool {
    let release = match read_kernel_release() {
        Some(s) => s,
        None => return false,
    };
    let (m, n) = match parse_kernel_release(&release) {
        Some(v) => v,
        None => return false,
    };
    m > maj_required || (m == maj_required && n >= min_required)
}

#[cfg(target_os = "linux")]
fn read_kernel_release() -> Option<String> {
    // SAFETY: `uname` writes into a properly sized `utsname` buffer
    // and returns 0 on success. We zero-init the struct first.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::uname(&mut uts as *mut _) };
    if rc != 0 {
        return None;
    }
    // `release` is a fixed-size C string buffer. Walk to the first
    // null and convert to a Rust &str.
    let raw = uts.release.as_ptr();
    // SAFETY: `raw` points into the `uts.release` array which lives
    // for the duration of this function; `from_ptr` walks until null.
    let cstr = unsafe { std::ffi::CStr::from_ptr(raw) };
    cstr.to_str().ok().map(|s| s.to_string())
}

/// Parse a kernel `release` string of the shape `5.19.0-1-amd64`,
/// `6.1.0`, `5.10.205-rt93`, `6.6.0-12-generic` into `(major, minor)`.
/// Returns `None` for shapes that don't have at least two numeric
/// dot-separated components at the start.
#[cfg(target_os = "linux")]
pub(crate) fn parse_kernel_release(s: &str) -> Option<(u32, u32)> {
    let s = s.split(|c: char| c == '-' || c == '+').next()?;
    let mut parts = s.split('.');
    let maj: u32 = parts.next()?.parse().ok()?;
    let min: u32 = parts.next()?.parse().ok()?;
    Some((maj, min))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::parse_kernel_release;

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_release_canonical_shapes() {
        assert_eq!(parse_kernel_release("5.19.0-1-amd64"), Some((5, 19)));
        assert_eq!(parse_kernel_release("6.1.0"), Some((6, 1)));
        assert_eq!(parse_kernel_release("6.6.0-12-generic"), Some((6, 6)));
        assert_eq!(parse_kernel_release("5.10.205-rt93"), Some((5, 10)));
        // Plus-suffix used by some custom builds.
        assert_eq!(parse_kernel_release("5.4.0+"), Some((5, 4)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_release_rejects_garbage() {
        assert_eq!(parse_kernel_release(""), None);
        assert_eq!(parse_kernel_release("foo"), None);
        assert_eq!(parse_kernel_release("5"), None);
        assert_eq!(parse_kernel_release("5.x"), None);
    }

    #[test]
    fn probe_does_not_panic() {
        // Same shape as the kTLS probe — the boot path is allowed to
        // log a warning on the result, but a panic here would take
        // down the whole daemon. This guards both feature configs.
        let _ = super::probe_io_uring_rw_supported();
    }
}
