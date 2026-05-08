//! Zion XDP pre-filter.
//!
//! Drops packets whose source IPv4 address matches an LPM-trie of
//! blacklisted CIDRs at the NIC driver layer, before the kernel's
//! networking stack sees them.
//!
//! Maps:
//!   * `BLOCKED_V4`  — `LpmTrie<[u8;4], u32>`, value = action (1=drop)
//!   * `STATS`       — `Array<u64>` of size 2: [0]=drops, [1]=passes
//!
//! IPv6 is intentionally out of scope for the v0 PoC — see
//! `xdp/README.md` for the v1 plan (a parallel `BLOCKED_V6` trie).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{lpm_trie::Key, Array, LpmTrie},
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map]
static BLOCKED_V4: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(65_536, 0);

#[map]
static STATS: Array<u64> = Array::with_max_entries(2, 0);

const IDX_DROPS: u32 = 0;
const IDX_PASSES: u32 = 1;

#[xdp]
pub fn zion_xdp(ctx: XdpContext) -> u32 {
    match try_filter(&ctx) {
        Ok(action) => action,
        // On any parse error (truncated packet, unexpected layout) we
        // err on the side of the kernel stack — XDP is a *filter*, not
        // a deep parser. Misparsed bytes go up the stack and the kernel
        // (or zion's userspace) decides.
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    // SAFETY: ptr_at validated bounds; reading EtherType is a single u16.
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(bump(xdp_action::XDP_PASS, IDX_PASSES));
    }

    let ip: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    // SAFETY: ptr_at validated bounds; reading src_addr is a single u32.
    let src_be = unsafe { (*ip).src_addr };
    // src_addr is stored network-byte-order; LPM keys are also BE bytes.
    let src_octets = src_be.to_ne_bytes();

    // /32 lookup — the map will return the most-specific matching prefix.
    let key = Key::new(32, src_octets);
    if BLOCKED_V4.get(&key).is_some() {
        return Ok(bump(xdp_action::XDP_DROP, IDX_DROPS));
    }
    Ok(bump(xdp_action::XDP_PASS, IDX_PASSES))
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn bump(action: u32, idx: u32) -> u32 {
    if let Some(slot) = STATS.get_ptr_mut(idx) {
        // SAFETY: get_ptr_mut returns a verified-aligned pointer into the
        // array map's per-CPU slot. Wrapping add is fine — drops/passes
        // are saturation-tolerant counters.
        unsafe {
            *slot = (*slot).wrapping_add(1);
        }
    }
    action
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The eBPF verifier rejects programs with reachable panics; this is
    // here only to satisfy the no_std requirement of `#![no_main]`.
    loop {}
}
