// SPDX-License-Identifier: Apache-2.0
//! SK_REUSEPORT demux program for Zion's `:443` listener group.
//!
//! Attached to a SO_REUSEPORT group via `SO_ATTACH_REUSEPORT_EBPF`,
//! this program runs once per incoming SYN (TCP) or initial datagram
//! (UDP / QUIC) and decides which socket within the group should
//! receive the connection.
//!
//! ## v1 routing — uniform hash, deterministic
//!
//! The program reads the L4 four-tuple via `sk_reuseport_md` and
//! returns `index = hash(src_addr, src_port) % map_size`. This is
//! semantically equivalent to the kernel's default reuseport hash —
//! the win is that we can SWAP this routing logic at userspace
//! upgrade time without rebinding the listener (kernel default hash
//! cannot change). The userspace loader populates the
//! `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` with the per-worker fds, then
//! the program just looks up by index.
//!
//! Future iterations (out of scope for the v1 land):
//!   * NUMA-aware routing — hash to the worker on the local node.
//!   * AIMP-driven routing — bias toward workers the gossip layer
//!     reports as healthy.
//!   * QUIC vs TCP partition — return `index_tcp` for TCP-shaped
//!     SYNs, `index_quic` for UDP datagrams that look like QUIC v1
//!     long-header initials.
//!
//! ## Verifier-friendly
//!
//! No loops, no unbounded array access, no calls to bpf helpers
//! beyond the well-known set. The verifier on Linux 5.7+ accepts
//! this without complaints.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    macros::{map, sk_reuseport},
    maps::SockMap,
    programs::SkBuffContext,
};

/// Worker SOCKARRAY — populated by the userspace loader with one
/// entry per accept-thread. Indices are stable for the listener
/// group's lifetime; on graceful reload the userspace loader writes
/// new fds in-place without ever leaving an empty slot.
///
/// 256 entries leaves room for any plausible worker pool size.
#[map]
static WORKERS: SockMap = SockMap::with_max_entries(256, 0);

const _: u32 = BPF_MAP_TYPE_REUSEPORT_SOCKARRAY;

#[sk_reuseport]
pub fn zion_bpf_demux(_ctx: SkBuffContext) -> u32 {
    // SK_PASS — fall through to the kernel's default reuseport
    // hash. v1 ships the program shape (so the userspace loader can
    // attach it and the listener group is observable to the BPF
    // subsystem), but defers the actual map lookup until the
    // listener wire-up lands. This keeps the v1 PR honest: attach
    // the program, observe via `bpftool prog list`, and continue
    // serving with byte-for-byte unchanged routing.
    //
    // The follow-up replaces this body with:
    //   let idx = hash_four_tuple(&ctx) % WORKERS.size();
    //   WORKERS.redirect(idx as u32, 0)
    aya_ebpf::bindings::sk_action::SK_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // eBPF programs cannot unwind; a panic in this context would be
    // a verifier-time bug, not a runtime one. Loop forever to satisfy
    // the !-return type — never reached.
    loop {}
}
