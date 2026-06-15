// SPDX-License-Identifier: Apache-2.0
//! `RwStream` — the connection byte transport: io_uring when the kernel
//! supports it, tokio `TcpStream` otherwise (issue #51, ADR-0009).
//!
//! A *concrete enum* (not `Box<dyn>`) so the serve path stays monomorphic and
//! the runtime io_uring-vs-tokio choice is a single branch made once at
//! accept. It implements tokio `AsyncRead`/`AsyncWrite` by delegating to the
//! active arm, so it slots under rustls exactly where the raw `TcpStream` does
//! today. The `Uring` arm only exists on `linux + io-uring-rw`; everywhere
//! else `RwStream` is just the `Tcp` arm.
//!
//! Increment 3 (ADR-0009): the enum + delegation + the runtime gate. The
//! serve-path seam that constructs it (lifting the accepted fd into the
//! driver) lands in increment 5; until then this is exercised only by tests.

// Interim until the seam is wired (increment 5, ADR-0009): the enum is
// constructed only by tests for now.
#![allow(dead_code)]

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Per-connection byte transport. `Send + Unpin + 'static` (both arms are), so
/// it drops in under `rustls` + `hyper_util::TokioIo` unchanged.
pub enum RwStream {
    /// The portable path: tokio's epoll-backed `TcpStream`.
    Tcp(TcpStream),
    /// The io_uring path (`linux + io-uring-rw`, kernel >= 5.19).
    #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
    Uring(crate::uring_rw::IoUringStream),
}

impl AsyncRead for RwStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RwStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
            RwStream::Uring(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RwStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            RwStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
            RwStream::Uring(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            RwStream::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
            RwStream::Uring(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            RwStream::Tcp(s) => s.is_write_vectored(),
            #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
            RwStream::Uring(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RwStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
            RwStream::Uring(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RwStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
            RwStream::Uring(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Runtime gate: whether the io_uring rw path should be used. `false` unless
/// built `linux + io-uring-rw` AND the kernel is recent enough (>= 5.19, the
/// `probe_io_uring_rw_supported` check). The serve seam (increment 5) calls
/// this once per accept to pick the `RwStream` arm.
pub fn io_uring_rw_active() -> bool {
    #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
    {
        crate::uring::probe_io_uring_rw_supported() && driver().is_some()
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring-rw")))]
    {
        false
    }
}

/// Lazily-started global rw driver. `None` if the kernel doesn't support the
/// rw path or the ring failed to init — callers fall back to `RwStream::Tcp`.
/// One driver (one ring) for the whole process (ADR-0009).
#[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
pub fn driver() -> Option<&'static std::sync::Arc<crate::uring_rw::Shared>> {
    use std::sync::OnceLock;
    static DRIVER: OnceLock<Option<std::sync::Arc<crate::uring_rw::Shared>>> = OnceLock::new();
    DRIVER
        .get_or_init(|| {
            if !crate::uring::probe_io_uring_rw_supported() {
                return None;
            }
            match crate::uring_rw::start() {
                Ok(s) => Some(s),
                Err(e) => {
                    crate::logging::warn(
                        "uring",
                        &format!("io_uring rw driver init failed: {e}; falling back to tokio I/O"),
                    );
                    None
                }
            }
        })
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    // The Tcp arm must behave exactly like a bare TcpStream (delegation is
    // transparent). Runs on every OS — local verification of the enum.
    #[tokio::test]
    async fn tcp_arm_echo_both_directions() {
        let (client, server) = loopback_pair().await;
        let mut a = RwStream::Tcp(server);
        let mut peer = client;
        let data = payload(256 * 1024);

        // peer -> a
        let d2 = data.clone();
        let w = tokio::spawn(async move {
            peer.write_all(&d2).await.unwrap();
            peer.shutdown().await.unwrap();
            peer
        });
        let mut got = Vec::new();
        a.read_to_end(&mut got).await.unwrap();
        assert!(got == data, "tcp arm read mismatch");
        let mut peer = w.await.unwrap();

        // a -> peer
        let d3 = data.clone();
        let w2 = tokio::spawn(async move {
            a.write_all(&d3).await.unwrap();
            a.shutdown().await.unwrap();
        });
        let mut got2 = Vec::new();
        peer.read_to_end(&mut got2).await.unwrap();
        assert!(got2 == data, "tcp arm write mismatch");
        w2.await.unwrap();
    }

    // The Uring arm echoes byte-exact through the driver, exactly like the
    // bare IoUringStream (increment 1) — proves the delegation is transparent.
    #[cfg(all(target_os = "linux", feature = "io-uring-rw"))]
    #[tokio::test]
    async fn uring_arm_echo_read() {
        use std::os::fd::FromRawFd;
        let drv = driver().expect("io_uring rw driver (kernel >= 5.19)");
        // socketpair: one end into the driver, the other a tokio peer.
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let mut a = RwStream::Uring(drv.register(fds[0]).expect("register"));
        let peer_std = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fds[1]) };
        peer_std.set_nonblocking(true).unwrap();
        let mut peer = tokio::net::UnixStream::from_std(peer_std).unwrap();
        let data = payload(512 * 1024);

        let d2 = data.clone();
        let w = tokio::spawn(async move {
            peer.write_all(&d2).await.unwrap();
            peer.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        a.read_to_end(&mut got).await.unwrap();
        assert!(got == data, "uring arm read mismatch");
        w.await.unwrap();
    }
}
