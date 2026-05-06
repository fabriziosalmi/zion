// SPDX-License-Identifier: Apache-2.0
//! Zion Sovereign Edge — IP classification and regional intelligence.
//!
//! Compile with `--features geo-ita` to bake Italian ASN/CIDR data into
//! the binary. Activate at runtime via `[sovereign]` in zion.toml.
//!
//! Architecture:
//! - **Zero overhead when disabled**: if `[sovereign]` is absent from
//!   zion.toml, the gate is never called — not even a branch.
//! - **O(log N) lookup**: sorted CIDR ranges with binary search.
//! - **Zero allocation**: all data is `const`/`static`, no heap.
//! - **Hot-reload safe**: classification is stateless, reads only the
//!   baked-in data + the `SovereignConfig` from the config snapshot.

#[cfg(feature = "geo-ita")]
pub mod data_ita;

#[cfg(feature = "geo-eu")]
pub mod data_eu;

use std::net::IpAddr;

// ═══════════════════════════════════════════════════════════════════
// IP Classification
// ═══════════════════════════════════════════════════════════════════

/// Classification of an IP address by origin and role.
/// Used for sovereign edge decisions (logging, metrics, policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpClass {
    /// Italian government / institutional (AgID, SPID providers, PEC)
    GovIta,
    /// Italian residential ISP (TIM, Vodafone, WindTre, Fastweb, Iliad)
    ResidentialIta,
    /// Italian datacenter / hosting (Aruba, Register, Seeweb, etc.)
    DatacenterIta,
    /// EU institutional (EU Parliament, ECB, Europol ranges)
    #[cfg(feature = "geo-eu")]
    GovEu,
    /// EU residential (major ISPs per country)
    #[cfg(feature = "geo-eu")]
    #[allow(dead_code)] // reserved for Phase 2 — data_eu.rs expansion pending
    ResidentialEu,
    /// EU datacenter / cloud
    #[cfg(feature = "geo-eu")]
    #[allow(dead_code)] // reserved for Phase 2 — data_eu.rs expansion pending
    DatacenterEu,
    /// Unclassified — not in any baked-in dataset
    Unknown,
}

impl IpClass {
    /// Short label for structured logging and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GovIta => "gov_ita",
            Self::ResidentialIta => "residential_ita",
            Self::DatacenterIta => "datacenter_ita",
            #[cfg(feature = "geo-eu")]
            Self::GovEu => "gov_eu",
            #[cfg(feature = "geo-eu")]
            Self::ResidentialEu => "residential_eu",
            #[cfg(feature = "geo-eu")]
            Self::DatacenterEu => "datacenter_eu",
            Self::Unknown => "unknown",
        }
    }

    /// Stable index into [`CLASS_COUNTERS`]. Hand-rolled instead of
    /// `enum_iterator` so this stays a `const fn` and the enum stays
    /// `#[derive(Copy)]`-able. Update both sides if a new variant lands.
    #[inline]
    const fn index(self) -> usize {
        match self {
            Self::GovIta => 0,
            Self::ResidentialIta => 1,
            Self::DatacenterIta => 2,
            #[cfg(feature = "geo-eu")]
            Self::GovEu => 3,
            #[cfg(feature = "geo-eu")]
            Self::ResidentialEu => 4,
            #[cfg(feature = "geo-eu")]
            Self::DatacenterEu => 5,
            Self::Unknown => CLASS_COUNTERS.len() - 1,
        }
    }
}

/// Per-class request counters. Bumped on every classification result by
/// `record_classification`. Exposed on `/metrics` as
/// `zion_sovereign_classifications_total{class="..."}`.
///
/// We use a fixed-size array instead of a HashMap because the enum is
/// closed: each slot is a single atomic u64, the lookup is O(1) by
/// `IpClass::index`, and the layout is a single cache line on every
/// architecture we ship to.
pub static CLASS_COUNTERS: [std::sync::atomic::AtomicU64; CLASS_COUNT] =
    [const { std::sync::atomic::AtomicU64::new(0) }; CLASS_COUNT];

#[cfg(feature = "geo-eu")]
const CLASS_COUNT: usize = 7; // 6 named + Unknown

#[cfg(not(feature = "geo-eu"))]
const CLASS_COUNT: usize = 4; // GovIta, ResidentialIta, DatacenterIta, Unknown

/// Bump the per-class counter. Inline-able to a single `fetch_add`.
#[inline]
pub fn record_classification(class: IpClass) {
    CLASS_COUNTERS[class.index()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Iterate `(class_label, count)` pairs for the metrics renderer.
/// Returns one entry per known class (cheap — bounded constant).
pub fn classification_counts() -> impl Iterator<Item = (&'static str, u64)> {
    [
        IpClass::GovIta,
        IpClass::ResidentialIta,
        IpClass::DatacenterIta,
        #[cfg(feature = "geo-eu")]
        IpClass::GovEu,
        #[cfg(feature = "geo-eu")]
        IpClass::ResidentialEu,
        #[cfg(feature = "geo-eu")]
        IpClass::DatacenterEu,
        IpClass::Unknown,
    ]
    .into_iter()
    .map(|c| {
        (
            c.as_str(),
            CLASS_COUNTERS[c.index()].load(std::sync::atomic::Ordering::Relaxed),
        )
    })
}

impl std::fmt::Display for IpClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ═══════════════════════════════════════════════════════════════════
// CIDR Range Representation (compile-time baked)
// ═══════════════════════════════════════════════════════════════════

/// A single CIDR range entry: [start_ip, end_ip] → IpClass.
/// Stored as packed u32 for IPv4. IPv6 support is deferred to Phase 2.
///
/// The arrays in `data_ita.rs` / `data_eu.rs` are sorted by `start`
/// so we can binary-search in O(log N).
#[derive(Debug, Clone, Copy)]
pub struct CidrEntry {
    /// First IP in the range (host order u32)
    pub start: u32,
    /// Last IP in the range (host order u32), inclusive
    pub end: u32,
    /// Classification for IPs in this range
    pub class: IpClass,
}

/// Convert a CIDR notation prefix to (start, end) u32 range.
/// Useful for `const` initialization of `CidrEntry` arrays.
///
/// Example: `cidr_range(192, 168, 1, 0, 24)` → `(0xC0A80100, 0xC0A801FF)`
pub const fn cidr_range(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> (u32, u32) {
    let ip = (a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | d as u32;
    if prefix_len >= 32 {
        return (ip, ip);
    }
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    let start = ip & mask;
    let end = start | !mask;
    (start, end)
}

// ═══════════════════════════════════════════════════════════════════
// Classifier
// ═══════════════════════════════════════════════════════════════════

/// Classify an IP address using the baked-in regional data.
/// Returns `IpClass::Unknown` if the IP is not in any dataset.
///
/// O(log N) binary search over sorted CIDR ranges. Zero allocation.
pub fn classify(ip: IpAddr) -> IpClass {
    let ipv4 = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(v6) => {
            // Check for IPv4-mapped IPv6 (::ffff:a.b.c.d)
            match v6.to_ipv4_mapped() {
                Some(v4) => u32::from(v4),
                None => return IpClass::Unknown, // Pure IPv6 — Phase 2
            }
        }
    };

    // Search ITA data first (more specific)
    #[cfg(feature = "geo-ita")]
    {
        let result = lookup(ipv4, data_ita::RANGES);
        if result != IpClass::Unknown {
            return result;
        }
    }

    // Then EU data (broader)
    #[cfg(feature = "geo-eu")]
    {
        let result = lookup(ipv4, data_eu::RANGES);
        if result != IpClass::Unknown {
            return result;
        }
    }

    IpClass::Unknown
}

/// Binary search a sorted `CidrEntry` array for the given IPv4 address.
#[inline]
fn lookup(ip: u32, ranges: &[CidrEntry]) -> IpClass {
    // Binary search: find the last range whose `start <= ip`
    let idx = ranges.partition_point(|entry| entry.start <= ip);
    if idx == 0 {
        return IpClass::Unknown;
    }
    let entry = &ranges[idx - 1];
    if ip <= entry.end {
        entry.class
    } else {
        IpClass::Unknown
    }
}

// ═══════════════════════════════════════════════════════════════════
// Sovereign Config (parsed from zion.toml)
// ═══════════════════════════════════════════════════════════════════

/// Configuration for the `[sovereign]` section in zion.toml.
/// Parsed at boot and on hot-reload. When `enabled = false` (default),
/// the sovereign gate is never invoked — zero overhead.
#[allow(dead_code)] // region/signals/signal_listen reserved for Phase 2/3
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SovereignConfig {
    /// Master switch. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Region hint: "ita" or "eu". Controls which baked-in dataset
    /// is preferred for classification. Both are always searched if
    /// compiled in; this affects logging/metrics labels.
    #[serde(default = "default_region")]
    pub region: String,

    /// Whether to emit signals to the gossip mesh (Phase 3).
    #[serde(default)]
    pub signals: bool,

    /// Listen address for signal gossip (Phase 3).
    #[serde(default = "default_signal_listen")]
    pub signal_listen: String,

    /// Log IP classification in structured request logs.
    #[serde(default = "default_true")]
    pub log_classification: bool,
}

impl Default for SovereignConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            region: "ita".to_string(),
            signals: false,
            signal_listen: "0.0.0.0:9443".to_string(),
            log_classification: true,
        }
    }
}

fn default_region() -> String {
    "ita".to_string()
}
fn default_signal_listen() -> String {
    "0.0.0.0:9443".to_string()
}
fn default_true() -> bool {
    true
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_range_basic() {
        let (start, end) = cidr_range(10, 0, 0, 0, 8);
        assert_eq!(start, 0x0A000000);
        assert_eq!(end, 0x0AFFFFFF);
    }

    #[test]
    fn cidr_range_32() {
        let (start, end) = cidr_range(192, 168, 1, 1, 32);
        assert_eq!(start, end);
        assert_eq!(start, 0xC0A80101);
    }

    #[test]
    fn cidr_range_24() {
        let (start, end) = cidr_range(192, 168, 1, 0, 24);
        assert_eq!(start, 0xC0A80100);
        assert_eq!(end, 0xC0A801FF);
    }

    #[test]
    fn lookup_empty_returns_unknown() {
        let result = lookup(0x0A000001, &[]);
        assert_eq!(result, IpClass::Unknown);
    }

    #[test]
    fn lookup_match() {
        let ranges = &[CidrEntry {
            start: 0x0A000000,
            end: 0x0AFFFFFF,
            class: IpClass::ResidentialIta,
        }];
        assert_eq!(lookup(0x0A000001, ranges), IpClass::ResidentialIta);
        assert_eq!(lookup(0x0AFFFFFF, ranges), IpClass::ResidentialIta);
        assert_eq!(lookup(0x0B000000, ranges), IpClass::Unknown);
        assert_eq!(lookup(0x09FFFFFF, ranges), IpClass::Unknown);
    }

    #[test]
    fn lookup_multiple_ranges() {
        let ranges = &[
            CidrEntry {
                start: 0x0A000000,
                end: 0x0A00FFFF,
                class: IpClass::GovIta,
            },
            CidrEntry {
                start: 0xC0A80000,
                end: 0xC0A8FFFF,
                class: IpClass::DatacenterIta,
            },
        ];
        assert_eq!(lookup(0x0A000100, ranges), IpClass::GovIta);
        assert_eq!(lookup(0xC0A80001, ranges), IpClass::DatacenterIta);
        assert_eq!(lookup(0x08000000, ranges), IpClass::Unknown); // before first
        assert_eq!(lookup(0x0B000000, ranges), IpClass::Unknown); // gap between
    }

    #[test]
    fn classify_unknown_ip() {
        // Random public IP not in any dataset
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(classify(ip), IpClass::Unknown);
    }

    #[test]
    fn ipclass_display() {
        assert_eq!(IpClass::GovIta.as_str(), "gov_ita");
        assert_eq!(IpClass::ResidentialIta.as_str(), "residential_ita");
        assert_eq!(IpClass::Unknown.as_str(), "unknown");
    }
}
