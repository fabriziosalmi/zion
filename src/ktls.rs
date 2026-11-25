//! kTLS post-handshake offload.
//!
//! Compile with `--features ktls` (Linux only).
//!
//! Once the rustls handshake completes, this module flips the underlying
//! TCP socket into in-kernel TLS mode (`SOL_TLS`/`TLS_TX`+`TLS_RX`).
//! Subsequent reads and writes traverse the kernel's TLS engine, which:
//!
//! 1. **Removes the userspace AEAD trip.** rustls is fast, but moving
//!    record encrypt/decrypt into the kernel saves ~1 syscall + 1 memcpy
//!    per record on the hot path.
//! 2. **Unlocks `sendfile(2)`-style zero-copy.** The kernel can splice
//!    an upstream-fetched static asset directly to the TLS socket
//!    without ever copying it through zion's address space.
//! 3. **Reduces context switches.** The application sees plaintext
//!    AsyncRead/AsyncWrite — same `hyper` integration shape, no
//!    record-framing visible.
//!
//! ## Limitations
//!
//! * Linux >= 5.10 with `CONFIG_TLS=y` (most modern distros).
//! * Cipher must be kTLS-supported: TLS 1.3 with AES-128-GCM,
//!   AES-256-GCM, or ChaCha20-Poly1305. TLS 1.2 also works for the
//!   same AEADs but TLS 1.3 is what zion uses by default.
//! * Some advanced rustls features (early data, post-handshake
//!   authentication) are not preserved across the kTLS upgrade.
//!
//! ## Failure mode
//!
//! The kernel is probed once, at boot ([`offload_enabled`]). When it does
//! not advertise kTLS (`TCP_ULP=tls` refused, typically the `tls` module
//! is not loaded), zion logs one warning and serves every HTTPS
//! connection on userspace rustls: no connection attempts the upgrade.
//!
//! When the kernel does advertise kTLS, every connection is handshaken
//! on a [`CorkStream`] and upgraded. If one upgrade still fails (for
//! example a cipher the kernel does not offload), that connection is
//! closed: `ktls` consumes the stream to read its keys, so there is no
//! userspace stream left to fall back to. The listener stays up.

use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

/// Re-export so callers can name the post-upgrade type without taking
/// a direct dependency on the `ktls` crate version.
pub use ktls::{CorkStream, KtlsStream};

/// Wrap a raw `TcpStream` with the cork adapter required by `ktls` 6.x.
///
/// **Call this BEFORE the rustls handshake**. The cork buffers writes
/// at the application↔kernel boundary so that, when `try_upgrade` is
/// finally called post-handshake, no in-flight encrypted bytes have
/// already been written to the socket — that would otherwise fight
/// with the kernel's `setsockopt(SOL_TLS, TLS_TX)` mode switch.
///
/// Usage shape:
///
/// ```ignore
/// let tcp = listener.accept().await?.0;
/// #[cfg(feature = "ktls")]
/// let inner = zion::ktls::cork_for_handshake(tcp);
/// #[cfg(not(feature = "ktls"))]
/// let inner = tcp;
/// let tls = acceptor.accept(inner).await?;
/// #[cfg(feature = "ktls")]
/// let stream = zion::ktls::try_upgrade(tls).await?;
/// ```
pub fn cork_for_handshake(stream: TcpStream) -> CorkStream<TcpStream> {
    CorkStream::new(stream)
}

/// Upgrade a freshly-handshaken rustls server stream to in-kernel TLS.
///
/// Call this **after** the handshake has completed. Calling it before
/// the handshake finishes returns `io::ErrorKind::Other` because the
/// keys aren't derived yet.
///
/// The argument is `TlsStream<CorkStream<TcpStream>>` because of the
/// requirement noted on [`cork_for_handshake`]. After upgrade, the
/// returned `KtlsStream` reads and writes plaintext directly — the
/// kernel handles AEAD and record framing.
///
/// On failure, the original stream is **consumed** by the call (this
/// is a `ktls` API constraint — it needs ownership to inspect the
/// negotiated keys). Plan for the fallback at the caller: if
/// `try_upgrade` returns `Err`, the connection should be closed —
/// you cannot fall back to userspace mode on the same stream.
pub async fn try_upgrade(
    stream: TlsStream<CorkStream<TcpStream>>,
) -> io::Result<KtlsStream<TcpStream>> {
    // The test override stands for a kernel without the `tls` module, so
    // an upgrade attempted under it fails the way that kernel's would.
    if forced_unsupported() {
        drop(stream);
        return Err(io::Error::other(
            "kTLS upgrade failed: kernel support forced off by the test override",
        ));
    }
    // The cork wrapper is consumed by the upgrade — the kernel takes
    // over record framing, so cork is unnecessary post-upgrade. The
    // returned `KtlsStream` is parameterised on the *raw* `TcpStream`.
    ktls::config_ktls_server(stream)
        .await
        .map_err(|e| io::Error::other(format!("kTLS upgrade failed: {e}")))
}

/// Diagnostic: returns whether the running kernel claims kTLS support.
/// Cheap (single `socket(2)` + `setsockopt` probe + close). Intended to
/// be called once at boot so a deployment can log `kTLS=available` or
/// `kTLS=unavailable: <reason>` in its boot banner.
pub fn probe_kernel_support() -> bool {
    use std::os::fd::AsRawFd;

    let s = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let stream = match std::net::TcpStream::connect(s.local_addr().unwrap()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // SAFETY: setsockopt with a known-valid fd, level, and optname.
    // Passing a NULL optval with len=0 to TCP_ULP queries support
    // without committing to a configuration.
    let ret = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_TCP,
            libc::TCP_ULP,
            c"tls".as_ptr() as *const _,
            4,
        )
    };
    ret == 0
}

/// Test-only override (debug builds only, ignored by release builds):
/// `ZION_TEST_KTLS_UNSUPPORTED=1` makes zion behave as on a kernel
/// without the `tls` module: the boot probe reads "unsupported" and
/// [`try_upgrade`] fails. It lets the userspace path be exercised on a
/// CI runner whose kernel has the module loaded.
pub const FORCE_UNSUPPORTED_ENV: &str = "ZION_TEST_KTLS_UNSUPPORTED";

fn forced_unsupported() -> bool {
    cfg!(debug_assertions) && std::env::var(FORCE_UNSUPPORTED_ENV).as_deref() == Ok("1")
}

/// Whether connections are upgraded to kernel TLS, from the boot probe
/// and the test override. Pure, so the decision is testable anywhere.
pub fn offload_decision(kernel_supports: bool, forced_unsupported: bool) -> bool {
    kernel_supports && !forced_unsupported
}

static OFFLOAD: OnceLock<bool> = OnceLock::new();

/// The kTLS decision for this process: probed once (at boot, which logs
/// it), then read by every connection before its handshake, so the
/// connection is corked only when it is going to be upgraded.
pub fn offload_enabled() -> bool {
    *OFFLOAD.get_or_init(|| offload_decision(probe_kernel_support(), forced_unsupported()))
}

/// The IO a TLS connection is served on: the kernel's TLS socket after a
/// successful upgrade, or userspace rustls when the kernel cannot offload.
/// One concrete type for both, so the HTTP stack above stays generic-free.
/// The rustls state is boxed: it is far larger than the kernel variant.
pub enum ServedIo {
    Kernel(KtlsStream<TcpStream>),
    User(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for ServedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServedIo::Kernel(s) => Pin::new(s).poll_read(cx, buf),
            ServedIo::User(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ServedIo::Kernel(s) => Pin::new(s).poll_write(cx, buf),
            ServedIo::User(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ServedIo::Kernel(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            ServedIo::User(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            ServedIo::Kernel(s) => s.is_write_vectored(),
            ServedIo::User(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServedIo::Kernel(s) => Pin::new(s).poll_flush(cx),
            ServedIo::User(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServedIo::Kernel(s) => Pin::new(s).poll_shutdown(cx),
            ServedIo::User(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// A completed handshake: on a cork adapter when the connection is going
/// to be upgraded, on the bare socket when it is served in userspace.
pub enum Handshaken {
    Corked(TlsStream<CorkStream<TcpStream>>),
    Plain(TlsStream<TcpStream>),
}

impl Handshaken {
    /// The rustls connection state, read before any upgrade.
    pub fn conn_mut(&mut self) -> &mut rustls::ServerConnection {
        match self {
            Handshaken::Corked(s) => s.get_mut().1,
            Handshaken::Plain(s) => s.get_mut().1,
        }
    }

    /// The IO to serve the connection on: upgraded to kernel TLS when it
    /// was corked for it, userspace rustls otherwise.
    pub async fn into_served(self) -> io::Result<ServedIo> {
        match self {
            Handshaken::Corked(s) => try_upgrade(s).await.map(ServedIo::Kernel),
            Handshaken::Plain(s) => Ok(ServedIo::User(Box::new(s))),
        }
    }
}

/// Run the TLS handshake on the socket, corked only when `offload` says
/// the connection is going to be upgraded to kernel TLS.
pub async fn accept(
    acceptor: &tokio_rustls::TlsAcceptor,
    tcp: TcpStream,
    offload: bool,
) -> io::Result<Handshaken> {
    if offload {
        acceptor
            .accept(cork_for_handshake(tcp))
            .await
            .map(Handshaken::Corked)
    } else {
        acceptor.accept(tcp).await.map(Handshaken::Plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decision the accept loop takes before every handshake: upgrade
    /// only when the kernel advertised kTLS and the override is not set.
    /// A kernel without kTLS must never be sent to `try_upgrade`, which
    /// would close every connection.
    #[test]
    fn a_kernel_without_ktls_is_served_in_userspace() {
        assert!(offload_decision(true, false));
        assert!(!offload_decision(false, false));
        assert!(!offload_decision(true, true));
        assert!(!offload_decision(false, true));
    }

    /// Compile-time signature pin for [`try_upgrade`]. If anyone
    /// changes the public type, this test fails and the breaking
    /// change is surfaced loudly. The argument MUST be
    /// `TlsStream<CorkStream<_>>`; passing a raw `TlsStream<TcpStream>`
    /// triggers the `ktls` 6.x API mismatch we hit before the
    /// `cork_for_handshake` indirection.
    #[test]
    fn upgrade_signature_is_pinned() {
        let _f: fn(TlsStream<CorkStream<TcpStream>>) -> _ = try_upgrade;
        let _g: fn(TcpStream) -> CorkStream<TcpStream> = cork_for_handshake;
    }

    /// `probe_kernel_support` must never panic, even in CI containers
    /// without the TLS module loaded. It just returns `false`.
    #[test]
    fn probe_does_not_panic() {
        let _ = probe_kernel_support();
    }
}
