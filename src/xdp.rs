//! Userspace loader for the Zion XDP pre-filter.
//!
//! Compile with `--features xdp` (Linux only).
//!
//! The eBPF program itself lives in [`xdp/zion-xdp-prog/`](../../xdp/zion-xdp-prog/)
//! and is built separately via `xdp/build.sh` (it requires nightly Rust
//! and `bpf-linker`, neither of which we want in the main zion build).
//! At runtime the loader reads the compiled ELF object from
//! `XdpConfig::object_path` and attaches the `zion_xdp` program to the
//! configured network interface.
//!
//! ## Flow
//!
//! ```text
//!     zion.toml                       runtime
//!  ┌────────────┐    boot       ┌───────────────────┐
//!  │ [xdp]      │──────────────▶│ XdpHandle::attach │
//!  │ enabled    │               └─────────┬─────────┘
//!  │ interface  │                         │
//!  │ object_path│                         ▼
//!  └────────────┘            ┌──────────────────────────┐
//!                            │ kernel: BLOCKED_V4 trie  │
//!  AIMP gossip ─┐            │         STATS array      │
//!  WAF blocks ──┼─▶ insert ─▶│                          │
//!  Static list ─┘            └──────────────────────────┘
//! ```
//!
//! ## Failure modes
//!
//! * Object file missing / unreadable → returns error; zion logs WARN
//!   and continues without XDP. The TCP listener still binds and serves.
//! * Program load fails (verifier rejection, kernel too old) → same.
//! * Interface does not exist → same.
//!
//! XDP attach is **never load-bearing**. A typo in `zion.toml` should
//! never strand zion offline.

// Scaffolding: the loader exposes `add_blocked_bulk`, `remove_blocked`,
// `Cidr4::host`, etc. for the XDP-AIMP wire that lands in the next PR.
// Until that wire is in place these are unreached from the binary —
// allow them at the file level rather than per-item.
#![allow(dead_code)]

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Configuration parsed from the `[xdp]` section of `zion.toml`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct XdpConfig {
    /// Master switch. When `false` the loader is never invoked.
    #[serde(default)]
    pub enabled: bool,

    /// Interface name to attach to (e.g. `eth0`, `eno1`).
    #[serde(default = "default_iface")]
    pub interface: String,

    /// Path to the compiled eBPF ELF object. Defaults to the conventional
    /// install location used by the .deb / .rpm packages.
    #[serde(default = "default_object_path")]
    pub object_path: PathBuf,

    /// Force SKB (generic) mode instead of native driver mode. Useful in
    /// virtualised environments (LXC, Firecracker) where the virtio NIC
    /// does not implement native XDP. Default: auto (try driver, fall back).
    #[serde(default)]
    pub force_skb_mode: bool,
}

fn default_iface() -> String {
    "eth0".to_string()
}

fn default_object_path() -> PathBuf {
    PathBuf::from("/usr/local/lib/zion/zion-xdp-prog.o")
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: default_iface(),
            object_path: default_object_path(),
            force_skb_mode: false,
        }
    }
}

/// A single IPv4 CIDR entry. Used for `add_blocked` / `remove_blocked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr4 {
    pub addr: Ipv4Addr,
    /// Prefix length in bits (1..=32). 32 = single host.
    pub prefix: u8,
}

impl Cidr4 {
    pub fn host(addr: Ipv4Addr) -> Self {
        Self { addr, prefix: 32 }
    }
}

/// Per-program packet counters read from the `STATS` map.
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpStats {
    pub drops: u64,
    pub passes: u64,
}

/// Live handle on a loaded + attached XDP program.
///
/// `Drop` on this handle detaches the program (via Aya's Drop on the
/// underlying link). Rebinding the listener does NOT need to recreate
/// this handle — XDP attaches to the *interface*, not the socket.
pub struct XdpHandle {
    bpf: Arc<Mutex<Ebpf>>,
    iface: String,
    mode: XdpMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    /// Native XDP — runs in the NIC driver. Fastest. Requires driver support.
    Driver,
    /// Generic / SKB mode — runs after the kernel has built an skb.
    /// Slower than driver mode but works on every NIC.
    Skb,
}

impl XdpHandle {
    /// Load the eBPF object at `obj_path`, attach `zion_xdp` to `iface`.
    ///
    /// Tries native driver mode first; falls back to SKB mode if the
    /// driver does not support it (errno `EOPNOTSUPP`). To force SKB mode
    /// up-front (skipping the driver attempt), set
    /// `XdpConfig::force_skb_mode = true` and use [`Self::attach_with_mode`].
    pub fn attach(iface: &str, obj_path: &Path) -> Result<Self, String> {
        Self::attach_with_mode(iface, obj_path, false)
    }

    pub fn attach_with_mode(iface: &str, obj_path: &Path, force_skb: bool) -> Result<Self, String> {
        let mut bpf = Ebpf::load_file(obj_path)
            .map_err(|e| format!("xdp: load {} failed: {e}", obj_path.display()))?;

        // Best-effort: the eBPF program emits aya-log records on packet
        // drops at TRACE level. Initialising the userspace logger is
        // optional — failure here just means we don't surface those.
        let _ = aya_log::EbpfLogger::init(&mut bpf);

        let program: &mut Xdp = bpf
            .program_mut("zion_xdp")
            .ok_or_else(|| "xdp: program 'zion_xdp' not found in object".to_string())?
            .try_into()
            .map_err(|e| format!("xdp: program is not an Xdp program: {e}"))?;
        program
            .load()
            .map_err(|e| format!("xdp: program.load() failed: {e}"))?;

        let mode = if force_skb {
            program
                .attach(iface, XdpFlags::SKB_MODE)
                .map_err(|e| format!("xdp: attach SKB to {iface} failed: {e}"))?;
            XdpMode::Skb
        } else {
            // Try driver mode, fall back to SKB on EOPNOTSUPP. We treat
            // *any* error from the driver attach as a reason to retry in
            // SKB rather than parsing errno fragments — the second call
            // will fail loudly if SKB doesn't work either.
            match program.attach(iface, XdpFlags::default()) {
                Ok(_) => XdpMode::Driver,
                Err(driver_err) => {
                    program
                        .attach(iface, XdpFlags::SKB_MODE)
                        .map_err(|e| {
                            format!(
                                "xdp: attach driver+SKB both failed on {iface}; driver: {driver_err}; skb: {e}"
                            )
                        })?;
                    XdpMode::Skb
                }
            }
        };

        Ok(Self {
            bpf: Arc::new(Mutex::new(bpf)),
            iface: iface.to_string(),
            mode,
        })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn mode(&self) -> XdpMode {
        self.mode
    }

    /// Insert a CIDR into the `BLOCKED_V4` LPM-trie. Subsequent packets
    /// from the matching range are dropped at NIC layer.
    ///
    /// Idempotent — re-inserting the same key is a no-op (BPF_ANY flag).
    pub async fn add_blocked(&self, cidr: Cidr4) -> Result<(), String> {
        let mut bpf = self.bpf.lock().await;
        let map = bpf
            .map_mut("BLOCKED_V4")
            .ok_or_else(|| "xdp: BLOCKED_V4 map missing".to_string())?;
        let mut trie: LpmTrie<_, [u8; 4], u32> =
            LpmTrie::try_from(map).map_err(|e| format!("xdp: BLOCKED_V4 typing: {e}"))?;
        let key = Key::new(cidr.prefix as u32, cidr.addr.octets());
        trie.insert(&key, 1u32, 0)
            .map_err(|e| format!("xdp: BLOCKED_V4 insert {cidr:?}: {e}"))?;
        Ok(())
    }

    /// Remove a CIDR from `BLOCKED_V4`. No-op if not present.
    pub async fn remove_blocked(&self, cidr: Cidr4) -> Result<(), String> {
        let mut bpf = self.bpf.lock().await;
        let map = bpf
            .map_mut("BLOCKED_V4")
            .ok_or_else(|| "xdp: BLOCKED_V4 map missing".to_string())?;
        let mut trie: LpmTrie<_, [u8; 4], u32> =
            LpmTrie::try_from(map).map_err(|e| format!("xdp: BLOCKED_V4 typing: {e}"))?;
        let key = Key::new(cidr.prefix as u32, cidr.addr.octets());
        let _ = trie.remove(&key);
        Ok(())
    }

    /// Read drops + passes counters. Cheap — single map syscall pair.
    pub async fn stats(&self) -> Result<XdpStats, String> {
        let bpf = self.bpf.lock().await;
        let map = bpf
            .map("STATS")
            .ok_or_else(|| "xdp: STATS map missing".to_string())?;
        let arr: Array<_, u64> =
            Array::try_from(map).map_err(|e| format!("xdp: STATS typing: {e}"))?;
        let drops = arr.get(&0u32, 0).unwrap_or(0);
        let passes = arr.get(&1u32, 0).unwrap_or(0);
        Ok(XdpStats { drops, passes })
    }

    /// Bulk insert. Used at boot to seed the map from a static blocklist
    /// or from the AIMP-replicated reputation map. Skips entries that
    /// fail (logs the failure to the boot logger) so a single malformed
    /// CIDR doesn't strand the whole load.
    pub async fn add_blocked_bulk<I>(&self, cidrs: I) -> Result<usize, String>
    where
        I: IntoIterator<Item = Cidr4>,
    {
        let mut bpf = self.bpf.lock().await;
        let map = bpf
            .map_mut("BLOCKED_V4")
            .ok_or_else(|| "xdp: BLOCKED_V4 map missing".to_string())?;
        let mut trie: LpmTrie<_, [u8; 4], u32> =
            LpmTrie::try_from(map).map_err(|e| format!("xdp: BLOCKED_V4 typing: {e}"))?;
        let mut n = 0usize;
        for cidr in cidrs {
            let key = Key::new(cidr.prefix as u32, cidr.addr.octets());
            if trie.insert(&key, 1u32, 0).is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_host_is_32_prefix() {
        let c = Cidr4::host(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(c.prefix, 32);
        assert_eq!(c.addr.octets(), [8, 8, 8, 8]);
    }

    #[test]
    fn config_default_is_disabled() {
        let c = XdpConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.interface, "eth0");
    }

    /// We do not unit-test the actual BPF load here — that requires
    /// `CAP_NET_ADMIN`, a kernel with XDP support, and the eBPF object
    /// to have been built by `xdp/build.sh`. Integration tests live
    /// under `tests/xdp_smoke.rs` and are gated on the `xdp` feature
    /// AND the `ZION_XDP_OBJECT` env var being set.
    #[test]
    fn placeholder_attach_compiles() {
        // This is a compile-time assertion that XdpHandle::attach has
        // the expected signature. Calling it without an iface/perm
        // would always fail; we just check the type shape.
        let _: fn(&str, &Path) -> Result<XdpHandle, String> = XdpHandle::attach;
    }
}
