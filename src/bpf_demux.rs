// SPDX-License-Identifier: Apache-2.0
//! SO_REUSEPORT + BPF demux loader (issue #53).
//!
//! `SO_REUSEPORT` lets multiple sockets bind the same `(addr, port)`
//! and share connection load. By default the kernel hashes incoming
//! packets to pick one socket from the group. `SO_ATTACH_REUSEPORT_EBPF`
//! replaces that hash with a userspace-loaded eBPF program of type
//! `BPF_PROG_TYPE_SK_REUSEPORT` — the program inspects the new packet
//! and returns either an index into a `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`
//! or `SK_DROP`.
//!
//! Why we want this on `:443`: workers are pinned to NUMA nodes
//! (track #50). The kernel's default hash spreads connections evenly
//! and ignores topology; an eBPF demux can route by client-affinity,
//! by packet-shape (TCP-handshake vs QUIC-initial), or by gossip-
//! driven worker health — all decisions zion already has the data
//! for at runtime.
//!
//! ## What ships now (v1)
//!
//! Foundation only: feature gate + kernel probe + capability probe +
//! a structured boot log. The actual listener wire-up (binding N
//! sockets to the same SO_REUSEPORT group, populating the SOCKARRAY,
//! attaching the program) is deferred — it requires reworking how
//! `main.rs` constructs HTTPS listeners, which is invasive enough to
//! land on its own. Pattern matches `src/uring.rs` (probe today,
//! adapter follow-up) and `src/ktls.rs` (corker today, sendfile
//! follow-up).
//!
//! ## Kernel + capability requirements
//!
//! * Linux >= 5.7 — when `SO_ATTACH_REUSEPORT_EBPF` was extended to
//!   UDP. Required for the unified-`:443` story (TCP HTTPS + UDP
//!   QUIC); on 5.6 and older only TCP works with this attach.
//! * `CAP_BPF` (since 5.8) or `CAP_SYS_ADMIN` (older). The probe
//!   reports the latter as a fallback.
//!
//! ## Failure mode
//!
//! Loading is **never load-bearing** — same posture as XDP and kTLS.
//! A capability mismatch, missing object file, or kernel rejection
//! falls back to the default reuseport hash and zion serves traffic
//! normally; the only loss is the steering ability.

#![allow(dead_code)] // see "What ships now" — listener wire-up deferred

use std::path::PathBuf;

/// Minimum kernel version where `SO_ATTACH_REUSEPORT_EBPF` works for
/// both TCP AND UDP (UDP support landed in 5.7). The issue's unified
/// `:443` story needs both, so 5.7 is our floor.
pub const BPF_DEMUX_MIN_KERNEL: (u32, u32) = (5, 7);

/// Default location the build script writes the compiled BPF ELF
/// object to. Mirrors `crate::xdp::EBPF_OBJECT_PATH`'s shape so an
/// operator can use the same `ZION_*_OBJECT` env-var convention.
///
/// `bpf/build.sh` builds the program; the userspace loader reads
/// from this path (or the `ZION_BPF_DEMUX_OBJECT` env var if set).
pub const DEFAULT_OBJECT_PATH: &str =
    "bpf/zion-bpf-demux/target/bpfel-unknown-none/release/zion-bpf-demux";

/// Probe + boot-log report for the operator. Three states:
///
///   * `Ready` — kernel and capabilities check out, the eventual
///     listener wire-up can attach without further checks.
///   * `KernelTooOld { release }` — uname returned a release we can't
///     attach against (< 5.7).
///   * `MissingCapability` — kernel is recent enough but the running
///     process lacks `CAP_BPF` / `CAP_SYS_ADMIN`. Operator needs to
///     grant the cap (e.g. `setcap cap_bpf+ep`) or run as root.
///   * `NotLinux` — non-Linux build target. Always returned on macOS
///     and Windows; the bool form below normalises this to "false".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemuxReadiness {
    Ready,
    KernelTooOld { release: String },
    MissingCapability,
    NotLinux,
}

impl DemuxReadiness {
    /// Boolean shortcut for `is_ready` — the operator-facing log line
    /// branches on this; the structured variant carries the diagnostic.
    pub fn is_ready(&self) -> bool {
        matches!(self, DemuxReadiness::Ready)
    }
}

/// Run the kernel + capability probes and return the readiness.
/// Cheap (one `uname(2)` + one capability check) — fine for boot.
pub fn probe() -> DemuxReadiness {
    #[cfg(target_os = "linux")]
    {
        let release = match read_kernel_release() {
            Some(s) => s,
            None => {
                return DemuxReadiness::KernelTooOld {
                    release: "unknown".into(),
                }
            }
        };
        let (m, n) = match crate::uring::parse_kernel_release(&release) {
            Some(v) => v,
            None => return DemuxReadiness::KernelTooOld { release },
        };
        if !(m > BPF_DEMUX_MIN_KERNEL.0
            || (m == BPF_DEMUX_MIN_KERNEL.0 && n >= BPF_DEMUX_MIN_KERNEL.1))
        {
            return DemuxReadiness::KernelTooOld { release };
        }
        if !has_bpf_capability() {
            return DemuxReadiness::MissingCapability;
        }
        DemuxReadiness::Ready
    }
    #[cfg(not(target_os = "linux"))]
    {
        DemuxReadiness::NotLinux
    }
}

#[cfg(target_os = "linux")]
fn read_kernel_release() -> Option<String> {
    // SAFETY: `uname` writes into a properly sized utsname buffer
    // and returns 0 on success. We zero-init the struct first.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts as *mut _) } != 0 {
        return None;
    }
    let raw = uts.release.as_ptr();
    // SAFETY: `raw` points into the live `uts.release` buffer; the
    // C string is NUL-terminated by the kernel.
    let cstr = unsafe { std::ffi::CStr::from_ptr(raw) };
    cstr.to_str().ok().map(|s| s.to_string())
}

/// Does the running process hold `CAP_BPF` or (fallback) `CAP_SYS_ADMIN`?
///
/// Implemented by reading `/proc/self/status` rather than calling
/// libcap so we don't add a new C dep just for this probe. The
/// `CapEff` line is a hex bitmask; we test for the relevant bits.
///
/// `CAP_SYS_ADMIN` = 21 (offset). `CAP_BPF` = 39 (since kernel 5.8).
#[cfg(target_os = "linux")]
fn has_bpf_capability() -> bool {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cap_eff_hex = match status
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| l.split_whitespace().nth(1))
    {
        Some(s) => s,
        None => return false,
    };
    let bits: u64 = match u64::from_str_radix(cap_eff_hex, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_BPF: u32 = 39;
    let has_sys_admin = bits & (1u64 << CAP_SYS_ADMIN) != 0;
    let has_bpf = bits & (1u64 << CAP_BPF) != 0;
    has_sys_admin || has_bpf
}

/// Resolve the path to the compiled BPF object. Operators can
/// override [`DEFAULT_OBJECT_PATH`] by setting `ZION_BPF_DEMUX_OBJECT`
/// in the environment.
pub fn object_path() -> PathBuf {
    if let Ok(p) = std::env::var("ZION_BPF_DEMUX_OBJECT") {
        return PathBuf::from(p);
    }
    PathBuf::from(DEFAULT_OBJECT_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        // Same posture as the kTLS / io_uring probes — safe to call
        // from boot, never panics.
        let _ = probe();
    }

    #[test]
    fn readiness_classification() {
        assert!(DemuxReadiness::Ready.is_ready());
        assert!(!DemuxReadiness::NotLinux.is_ready());
        assert!(!DemuxReadiness::MissingCapability.is_ready());
        assert!(!DemuxReadiness::KernelTooOld {
            release: "5.4".into()
        }
        .is_ready());
    }

    #[test]
    fn object_path_env_override() {
        // Use a unique env var name so parallel tests don't clash.
        std::env::set_var("ZION_BPF_DEMUX_OBJECT", "/tmp/zion-test-bpf.o");
        let p = object_path();
        assert_eq!(p.to_string_lossy(), "/tmp/zion-test-bpf.o");
        std::env::remove_var("ZION_BPF_DEMUX_OBJECT");
        let p = object_path();
        assert_eq!(p.to_string_lossy(), DEFAULT_OBJECT_PATH);
    }
}
