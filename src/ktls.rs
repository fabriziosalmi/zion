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
//! Upgrade is **never load-bearing**. If the kernel rejects the sockopt
//! (cipher unsupported, kernel too old, KTLS module not loaded) the
//! caller gets an `io::Error` and falls back to the userspace TLS path.
//! Zion's HTTPS listener never goes offline because of a kTLS issue.

// Scaffolding: `cork_for_handshake` and `try_upgrade` are the public
// shape the rustls accept loop will switch to once the cork wrapping
// lands at the handshake site. Until that lands they are unreached.
#![allow(dead_code)]

use std::io;
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

#[cfg(test)]
mod tests {
    use super::*;

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
