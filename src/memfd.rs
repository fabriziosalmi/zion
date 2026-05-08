// SPDX-License-Identifier: Apache-2.0
//! Memfd-backed cache entries (issue #52 building block).
//!
//! `memfd_create(2)` creates an anonymous file in tmpfs that lives in
//! kernel memory. Once a body is written, the resulting `RawFd` can
//! be passed directly to `sendfile(2)` so the kernel splices bytes
//! from page cache to the (kTLS-configured) socket without any
//! userspace copy or AEAD pass.
//!
//! This module is the small, testable, hardware-independent piece of
//! the kTLS sendfile path — `Memfd::from_bytes(...)` writes a payload
//! into a fresh memfd and returns a `File` handle the cache can
//! retain alongside its `Bytes` view. The dispatch-side wire-up that
//! actually issues `sendfile(target_socket_fd, memfd, ...)` is
//! tracked separately (see CHANGELOG "Deferred"); it requires
//! sidestepping hyper's body machinery, which is invasive enough to
//! land on its own.
//!
//! ## Linux-only
//!
//! Compiles only under `#[cfg(target_os = "linux")]`. macOS / Windows
//! have no equivalent: BSD's `memfd_create` is gated on `__APPLE_API_PRIVATE`,
//! Windows lacks the concept entirely. The cache wire-up that consumes
//! this module must guard the call site on the same `cfg`.

#![cfg(target_os = "linux")]
// `Memfd::{from_bytes, len, is_empty, as_raw_fd}` are the public API
// the deferred sendfile dispatch path will consume. Until that lands
// the bin compile sees them as unused; module-level allow keeps the
// items intact and their tests reachable instead of having to
// scatter `#[allow]` per item. Same posture as `src/ktls.rs`'s
// `#![allow(dead_code)]` for `cork_for_handshake` / `try_upgrade`
// before the listener wire-up landed.
#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

/// Threshold below which we don't bother creating a memfd. Cache
/// entries smaller than this stay as `Bytes` — the syscall cost of
/// `memfd_create` + `write` + `lseek` exceeds the userspace-copy cost
/// for sub-64-KB payloads.
///
/// 64 KB matches the issue spec ("for cacheable bodies above a
/// threshold (≥ 64 KB)"). Bumping this is cheap.
pub const MIN_MEMFD_THRESHOLD: usize = 64 * 1024;

/// A memfd-backed handle for a cache entry payload. Holds an
/// `OwnedFd` (via `File`) plus the byte length so callers can
/// pass `(fd, 0, len)` to `sendfile(2)` without an extra `fstat`.
///
/// Cheap to clone via `Arc<Memfd>` — the underlying fd is shared.
#[derive(Debug)]
pub struct Memfd {
    file: File,
    len: usize,
}

impl Memfd {
    /// Create a fresh anonymous file in tmpfs and write `bytes` into
    /// it. Seeks back to offset 0 before returning so a subsequent
    /// `sendfile` reads from the start.
    ///
    /// `label` is a debug-visible name (truncated to 249 bytes by
    /// the kernel — RFC: `MFD_NAME_MAX`). It's purely diagnostic;
    /// the fd's identity is the inode number, not the label.
    pub fn from_bytes(label: &str, bytes: &[u8]) -> io::Result<Self> {
        // Sanitise the label: NUL terminator + bounded length.
        let mut label_buf = [0u8; 64];
        let label_bytes = label.as_bytes();
        let n = label_bytes.len().min(label_buf.len() - 1);
        label_buf[..n].copy_from_slice(&label_bytes[..n]);
        // SAFETY: label_buf is 64 bytes including a guaranteed
        // trailing NUL; `memfd_create` reads up to the first NUL.
        let raw: RawFd = unsafe {
            // `MFD_CLOEXEC` so an exec'd child doesn't inherit the
            // page-cache backing. We don't pass `MFD_ALLOW_SEALING`
            // — sealing is only useful when we want to advertise
            // immutability to a peer, which the cache doesn't need.
            libc::syscall(
                libc::SYS_memfd_create,
                label_buf.as_ptr() as *const libc::c_char,
                libc::MFD_CLOEXEC,
            ) as RawFd
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh fd we just received from the
        // kernel and own exclusively. Wrapping it in `File` makes
        // Drop close it for us.
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes)?;
        // Rewind so the consumer can `sendfile` from the start
        // without an explicit `lseek(SEEK_SET, 0)`.
        use std::io::Seek;
        file.seek(io::SeekFrom::Start(0))?;
        Ok(Self {
            file,
            len: bytes.len(),
        })
    }

    /// Length in bytes of the data backed by this memfd.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `len() == 0` shortcut — `Memfd::from_bytes(_, b"")` is legal
    /// and produces an empty entry.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Raw fd for `sendfile(2)`. Borrowed — the `Memfd` keeps
    /// ownership of the underlying file.
    #[inline]
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn round_trip_small_payload() {
        let payload = b"hello, kernel-page-cache";
        let mfd = Memfd::from_bytes("zion-test-small", payload).expect("memfd_create");
        assert_eq!(mfd.len(), payload.len());
        assert!(!mfd.is_empty());

        // Read it back via the same fd to confirm the bytes round-trip.
        // `from_bytes` rewinds, but a separate borrow doesn't share
        // file position — clone the fd and read from a fresh File.
        let raw = mfd.as_raw_fd();
        // SAFETY: `dup` returns a new fd we own. We close it via the
        // File wrapper at scope exit.
        let dup_raw = unsafe { libc::dup(raw) };
        assert!(dup_raw >= 0, "dup failed: {}", io::Error::last_os_error());
        let mut dup = unsafe { File::from_raw_fd(dup_raw) };
        dup.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        dup.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn empty_payload_is_legal() {
        let mfd = Memfd::from_bytes("zion-test-empty", b"").expect("memfd_create");
        assert!(mfd.is_empty());
        assert_eq!(mfd.len(), 0);
    }

    #[test]
    fn large_payload_above_threshold() {
        // The threshold-driven dispatch path consults
        // MIN_MEMFD_THRESHOLD; verify the helper itself doesn't
        // care, so a future caller picking a different threshold
        // can do so without coordinating with this module.
        let payload = vec![0xa5u8; MIN_MEMFD_THRESHOLD * 2];
        let mfd = Memfd::from_bytes("zion-test-large", &payload).expect("memfd_create");
        assert_eq!(mfd.len(), payload.len());
    }

    #[test]
    fn label_truncation_does_not_panic() {
        // A label >64 bytes must be silently truncated (kernel max
        // is 249 anyway; we use a smaller buffer because cache
        // entries are typically named after URL paths and 64 is
        // plenty for `static-cache:/long/path/...`).
        let long = "x".repeat(1024);
        let mfd = Memfd::from_bytes(&long, b"ok").expect("memfd_create with long label");
        assert_eq!(mfd.len(), 2);
    }
}
