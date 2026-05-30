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
    /// EU member-state allocation, role unknown. The country-level
    /// baseline from RIPE delegated stats (EU27); a more specific
    /// curated-ASN class below overrides it where known.
    #[cfg(feature = "geo-eu")]
    Eu,
    /// EU institutional (EU Parliament, ECB, Europol, national gov/research)
    #[cfg(feature = "geo-eu")]
    GovEu,
    /// EU residential (major ISPs per country)
    #[cfg(feature = "geo-eu")]
    ResidentialEu,
    /// EU datacenter / cloud
    #[cfg(feature = "geo-eu")]
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
            Self::Eu => "eu",
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
    ///
    /// `Self::Unknown` resolves to `CLASS_COUNT - 1` rather than
    /// `CLASS_COUNTERS.len() - 1`: referencing a `static` from a
    /// `const fn` is unstable on rustc < 1.83 (E0658, see
    /// rust-lang/rust#119618), and the project's MSRV floor is 1.82.
    /// Both expressions evaluate to the same usize.
    #[inline]
    const fn index(self) -> usize {
        match self {
            Self::GovIta => 0,
            Self::ResidentialIta => 1,
            Self::DatacenterIta => 2,
            #[cfg(feature = "geo-eu")]
            Self::Eu => 3,
            #[cfg(feature = "geo-eu")]
            Self::GovEu => 4,
            #[cfg(feature = "geo-eu")]
            Self::ResidentialEu => 5,
            #[cfg(feature = "geo-eu")]
            Self::DatacenterEu => 6,
            Self::Unknown => CLASS_COUNT - 1,
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
const CLASS_COUNT: usize = 8; // 7 named (3 ITA + Eu/GovEu/ResidentialEu/DatacenterEu) + Unknown

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
        IpClass::Eu,
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

/// A single IPv4 CIDR range entry: [start_ip, end_ip] → IpClass.
/// Stored as packed u32.
///
/// The `RANGES` arrays in `data_ita.rs` / `data_eu.rs` are sorted by
/// `start` so we can binary-search in O(log N).
#[derive(Debug, Clone, Copy)]
pub struct CidrEntry {
    /// First IP in the range (host order u32)
    pub start: u32,
    /// Last IP in the range (host order u32), inclusive
    pub end: u32,
    /// Classification for IPs in this range
    pub class: IpClass,
}

/// A single IPv6 CIDR range entry: [start_ip, end_ip] → IpClass.
/// Stored as packed u128 (host order, i.e. `u128::from(Ipv6Addr)`).
///
/// The `RANGES6` arrays in `data_ita.rs` / `data_eu.rs` are sorted by
/// `start` so we can binary-search in O(log N), same as the v4 path.
#[derive(Debug, Clone, Copy)]
pub struct CidrEntry6 {
    /// First IP in the range (host order u128)
    pub start: u128,
    /// Last IP in the range (host order u128), inclusive
    pub end: u128,
    /// Classification for IPs in this range
    pub class: IpClass,
}

/// Convert a CIDR notation prefix to (start, end) u32 range.
/// Useful for `const` initialization of `CidrEntry` arrays.
///
/// `#[allow(dead_code)]`: the generated `data_*.rs` now emit raw
/// `cr(start, end, class)` calls (no dotted-quad+prefix), so nothing in
/// the binary calls this — but it's a public const-init utility, kept for
/// hand-written entries/fixtures and exercised by the unit tests below.
///
/// Example: `cidr_range(192, 168, 1, 0, 24)` → `(0xC0A80100, 0xC0A801FF)`
#[allow(dead_code)]
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
    // Normalise to either a v4 u32 or a v6 u128. IPv4-mapped IPv6
    // (`::ffff:a.b.c.d`) folds onto the v4 path so a dual-stack listener
    // classifies a mapped client the same as a native v4 one. The `_`
    // prefixes silence `unused_variable` when no geo feature is enabled
    // (the reader blocks below are then `cfg`-stripped).
    let (_ipv4, _ipv6): (Option<u32>, Option<u128>) = match ip {
        IpAddr::V4(v4) => (Some(u32::from(v4)), None),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (Some(u32::from(v4)), None),
            None => (None, Some(u128::from(v6))),
        },
    };

    // IPv4 path: ITA first (more specific), then EU.
    if let Some(_v4) = _ipv4 {
        #[cfg(feature = "geo-ita")]
        {
            let result = lookup(_v4, data_ita::RANGES);
            if result != IpClass::Unknown {
                return result;
            }
        }
        #[cfg(feature = "geo-eu")]
        {
            let result = lookup(_v4, data_eu::RANGES);
            if result != IpClass::Unknown {
                return result;
            }
        }
    }

    // IPv6 path: same ITA-then-EU precedence over the u128 tables.
    if let Some(_v6) = _ipv6 {
        #[cfg(feature = "geo-ita")]
        {
            let result = lookup6(_v6, data_ita::RANGES6);
            if result != IpClass::Unknown {
                return result;
            }
        }
        #[cfg(feature = "geo-eu")]
        {
            let result = lookup6(_v6, data_eu::RANGES6);
            if result != IpClass::Unknown {
                return result;
            }
        }
    }

    IpClass::Unknown
}

/// Binary search a sorted `CidrEntry` array for the given IPv4 address.
///
/// `#[allow(dead_code)]`: the public `classify` only calls this under
/// `feature = "geo-ita"` or `feature = "geo-eu"`, but the function itself
/// is unit-tested below regardless of feature flags so the bench-time
/// build (no-default-features) keeps coverage. Suppressing the warning is
/// preferable to gating tests behind `cfg(any(...))`.
#[allow(dead_code)]
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

/// Binary search a sorted `CidrEntry6` array for the given IPv6 address.
/// Identical shape to [`lookup`], over u128 bounds. See its note re
/// `#[allow(dead_code)]`.
#[allow(dead_code)]
#[inline]
fn lookup6(ip: u128, ranges: &[CidrEntry6]) -> IpClass {
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

    /// Tag-driven enforcement policy (`[sovereign.enforce]`, issue #150).
    /// Off by default — classification stays a pure signal unless the
    /// operator opts a class (or a mesh-reputation threshold) into a
    /// hard deny.
    #[serde(default)]
    pub enforce: EnforceConfig,
}

/// `[sovereign.enforce]` — promotes the origin tag / mesh-reputation
/// score from *signal* to an opt-in admission gate (issue #150). Disabled
/// by default. The local WAF / rate-limiter / auth gates stay
/// authoritative; this only adds a deny on top.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EnforceConfig {
    /// Master switch. Default: false (signals-only).
    #[serde(default)]
    pub enabled: bool,
    /// `IpClass` labels (as in [`IpClass::as_str`], e.g. `"unknown"`,
    /// `"datacenter_eu"`) whose requests are denied with `403`. On a
    /// `geo-eu` build, `["unknown"]` denies every non-EU source while the
    /// EU classes pass — the sovereign allowlist *by complement*.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Deny (`403`) when the AIMP mesh reputation score for the source
    /// exceeds this threshold. `0.0` = off (default). Promotes the mesh
    /// score from advisory header to optional hard gate (ADR-0008
    /// high-confidence path). Requires `--features sovereign-aimp`.
    #[serde(default)]
    pub mesh_score_deny_above: f32,
}

impl Default for EnforceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            deny: Vec::new(),
            mesh_score_deny_above: 0.0,
        }
    }
}

/// Resolved, hot-path form of [`EnforceConfig`]: deny labels lowercased
/// into a set for O(1) membership. Pure decision methods so the policy is
/// unit-testable without a live request.
#[derive(Debug, Clone, Default)]
pub struct EnforcePolicy {
    pub enabled: bool,
    deny: std::collections::HashSet<String>,
    mesh_score_deny_above: f32,
}

impl EnforcePolicy {
    pub fn from_config(c: &EnforceConfig) -> Self {
        Self {
            enabled: c.enabled,
            deny: c.deny.iter().map(|s| s.to_ascii_lowercase()).collect(),
            mesh_score_deny_above: c.mesh_score_deny_above,
        }
    }

    /// True if a request from `class_label` should be denied (`403`).
    #[inline]
    pub fn denies_class(&self, class_label: &str) -> bool {
        self.enabled && self.deny.contains(class_label)
    }

    /// True if a source with mesh reputation `score` should be denied.
    #[inline]
    #[allow(dead_code)] // only reached on `--features sovereign-aimp`
    pub fn denies_score(&self, score: f32) -> bool {
        self.enabled && self.mesh_score_deny_above > 0.0 && score > self.mesh_score_deny_above
    }

    /// Deny labels that don't match any known `IpClass` — surfaced at
    /// config-load so a typo (`"datacentre_eu"`) doesn't silently no-op.
    pub fn unknown_deny_labels(&self) -> Vec<&str> {
        let known = known_class_labels();
        self.deny
            .iter()
            .filter(|l| !known.contains(&l.as_str()))
            .map(|s| s.as_str())
            .collect()
    }
}

/// Every `IpClass` label valid in the current build (the EU labels exist
/// only under `--features geo-eu`). Used to validate enforcement config.
pub fn known_class_labels() -> &'static [&'static str] {
    &[
        "gov_ita",
        "residential_ita",
        "datacenter_ita",
        #[cfg(feature = "geo-eu")]
        "eu",
        #[cfg(feature = "geo-eu")]
        "gov_eu",
        #[cfg(feature = "geo-eu")]
        "residential_eu",
        #[cfg(feature = "geo-eu")]
        "datacenter_eu",
        "unknown",
    ]
}

impl Default for SovereignConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            region: "ita".to_string(),
            signals: false,
            signal_listen: "0.0.0.0:9443".to_string(),
            log_classification: true,
            enforce: EnforceConfig::default(),
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

    // ── EU dataset (geo-eu) ──────────────────────────────────────────
    #[cfg(feature = "geo-eu")]
    #[test]
    fn classify_eu_baseline_and_role_override() {
        // 8.8.8.8 (Google, US) stays Unknown — proves we don't classify
        // the whole world as EU.
        assert_eq!(classify("8.8.8.8".parse().unwrap()), IpClass::Unknown);

        // 193.0.0.1 is RIPE NCC's own block (NL) — a stable EU-27
        // allocation with no curated-ASN role, so it lands on the
        // country-level baseline.
        assert_eq!(classify("193.0.0.1".parse().unwrap()), IpClass::Eu);

        // 217.0.0.1 is Deutsche Telekom (AS3320, DE residential). It sits
        // inside the EU baseline but the curated ASN override wins — this
        // is the whole point of the hybrid model. We assert it resolves to
        // *some* EU class (role data is regenerated from upstream feeds,
        // so don't pin the exact role) and is more specific than Unknown.
        let dt = classify("217.0.0.1".parse().unwrap());
        assert!(
            matches!(
                dt,
                IpClass::Eu | IpClass::GovEu | IpClass::ResidentialEu | IpClass::DatacenterEu
            ),
            "217.0.0.1 (Deutsche Telekom, DE) should classify as an EU class, got {dt:?}"
        );
    }

    #[cfg(feature = "geo-eu")]
    #[test]
    fn ipclass_display_eu() {
        assert_eq!(IpClass::Eu.as_str(), "eu");
        assert_eq!(IpClass::GovEu.as_str(), "gov_eu");
        assert_eq!(IpClass::ResidentialEu.as_str(), "residential_eu");
        assert_eq!(IpClass::DatacenterEu.as_str(), "datacenter_eu");
    }

    // ── Tag-driven enforcement policy (issue #150) ───────────────────
    #[test]
    fn enforce_disabled_denies_nothing() {
        let p = EnforcePolicy::from_config(&EnforceConfig {
            enabled: false,
            deny: vec!["unknown".into()],
            mesh_score_deny_above: 0.5,
        });
        assert!(!p.denies_class("unknown"));
        assert!(!p.denies_score(0.99));
    }

    #[test]
    fn enforce_denies_listed_class_case_insensitively() {
        let p = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            deny: vec!["Unknown".into(), "DATACENTER_EU".into()],
            mesh_score_deny_above: 0.0,
        });
        assert!(p.denies_class("unknown"));
        assert!(p.denies_class("datacenter_eu"));
        // A class not on the list passes (the sovereign-allowlist-by-complement).
        assert!(!p.denies_class("residential_eu"));
        assert!(!p.denies_class("gov_ita"));
    }

    #[test]
    fn enforce_score_threshold_is_strict_and_off_at_zero() {
        let off = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            deny: vec![],
            mesh_score_deny_above: 0.0, // 0 = disabled
        });
        assert!(!off.denies_score(1.0));

        let p = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            deny: vec![],
            mesh_score_deny_above: 0.9,
        });
        assert!(p.denies_score(0.91));
        assert!(!p.denies_score(0.9)); // strict `>`, equal does not deny
        assert!(!p.denies_score(0.5));
    }

    #[test]
    fn enforce_flags_typoed_deny_labels() {
        let p = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            deny: vec!["unknown".into(), "datacentre_eu".into()], // British typo
            mesh_score_deny_above: 0.0,
        });
        let unknown = p.unknown_deny_labels();
        assert!(unknown.contains(&"datacentre_eu"));
        assert!(!unknown.contains(&"unknown"));
    }

    #[cfg(feature = "geo-eu")]
    #[test]
    fn classify_eu_ipv6() {
        // 2606:4700::1 (Cloudflare, US) stays Unknown — no false EU positive.
        assert_eq!(classify("2606:4700::1".parse().unwrap()), IpClass::Unknown);

        // 2001:608::1 is a stable DE allocation (RIPE) with no curated-ASN
        // role → country-level baseline.
        assert_eq!(classify("2001:608::1".parse().unwrap()), IpClass::Eu);

        // 2003:a::1 is Deutsche Telekom v6 (AS3320) — the curated ASN role
        // overrides the baseline, proving the hybrid model works on the
        // u128 path too. Don't pin the exact role (regenerated upstream),
        // just assert it's an EU class.
        let dt6 = classify("2003:a::1".parse().unwrap());
        assert!(
            matches!(
                dt6,
                IpClass::Eu | IpClass::GovEu | IpClass::ResidentialEu | IpClass::DatacenterEu
            ),
            "2003:a::1 (Deutsche Telekom v6) should classify as an EU class, got {dt6:?}"
        );
    }
}
