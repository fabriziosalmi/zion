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

    /// The class a label names (as in [`IpClass::as_str`], any case), among the
    /// classes this build has. `None` for anything else.
    pub fn from_label(label: &str) -> Option<Self> {
        ALL_CLASSES
            .iter()
            .copied()
            .find(|c| c.as_str().eq_ignore_ascii_case(label))
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

/// Every class of this build, in the order of [`IpClass::index`].
const ALL_CLASSES: &[IpClass] = &[
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
];

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
// Operator overrides (`[sovereign.overrides]`)
// ═══════════════════════════════════════════════════════════════════
//
// The tables are compiled in, and they are built from what registries and
// BGP say. When a row is wrong for the operator (their own office range, a
// partner's network, a block the table has not caught up with), fixing it
// must not take a rebuild: a CIDR and a class in the config, read at boot
// and on reload, and consulted before the tables.

/// Resolved `[sovereign.overrides]`: disjoint address ranges with a class,
/// sorted for binary search. Nested prefixes are flattened when the config is
/// loaded, so a request costs one search and the most specific prefix wins.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    v4: Vec<(u32, u32, IpClass)>,
    v6: Vec<(u128, u128, IpClass)>,
    entries: usize,
}

impl Overrides {
    /// Parse and flatten `"CIDR" = "class"` pairs. Every problem is reported,
    /// not only the first: an operator fixing a list wants the whole list.
    pub fn from_config<'a, I>(pairs: I) -> Result<Self, Vec<String>>
    where
        I: IntoIterator<Item = (&'a String, &'a String)>,
    {
        let mut errors = Vec::new();
        let mut v4: Vec<(u128, u128, IpClass)> = Vec::new();
        let mut v6: Vec<(u128, u128, IpClass)> = Vec::new();
        let mut entries = 0;
        for (cidr, label) in pairs {
            let class = IpClass::from_label(label);
            if class.is_none() {
                errors.push(format!(
                    "sovereign.overrides \"{cidr}\": \"{label}\" is not a class of this build (known: {})",
                    known_class_labels().join(", ")
                ));
            }
            match parse_cidr(cidr) {
                Ok((start, end, is_v4)) => {
                    if let Some(class) = class {
                        if is_v4 { &mut v4 } else { &mut v6 }.push((start, end, class));
                        entries += 1;
                    }
                }
                Err(why) => errors.push(format!("sovereign.overrides \"{cidr}\": {why}")),
            }
        }
        for family in [&mut v4, &mut v6] {
            // A parent before its children: by start, then the larger block first.
            family.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            for w in family.windows(2) {
                if (w[0].0, w[0].1) == (w[1].0, w[1].1) {
                    errors.push(format!(
                        "sovereign.overrides: the same network is listed twice ({})",
                        if w[0].1 <= u128::from(u32::MAX) {
                            std::net::Ipv4Addr::from(w[0].0 as u32).to_string()
                        } else {
                            std::net::Ipv6Addr::from(w[0].0).to_string()
                        }
                    ));
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(Self {
            v4: flatten(&v4)
                .into_iter()
                .map(|(s, e, c)| (s as u32, e as u32, c))
                .collect(),
            v6: flatten(&v6),
            entries,
        })
    }

    /// How many `"CIDR" = "class"` pairs are in force.
    pub fn len(&self) -> usize {
        self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// The class the operator gave this address, if any. An override to
    /// `unknown` is an answer too: it takes the address out of the tables.
    #[inline]
    pub fn lookup(&self, ip: IpAddr) -> Option<IpClass> {
        if self.entries == 0 {
            return None;
        }
        match ip {
            IpAddr::V4(v4) => find(u32::from(v4), &self.v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => find(u32::from(v4), &self.v4),
                None => find(u128::from(v6), &self.v6),
            },
        }
    }
}

/// Classify an address: the operator's overrides first, then the tables.
#[inline]
pub fn classify_with(overrides: &Overrides, ip: IpAddr) -> IpClass {
    overrides.lookup(ip).unwrap_or_else(|| classify(ip))
}

/// The range containing `ip` in a sorted, disjoint list.
#[inline]
fn find<T: Copy + Ord>(ip: T, ranges: &[(T, T, IpClass)]) -> Option<IpClass> {
    let idx = ranges.partition_point(|r| r.0 <= ip);
    let r = ranges.get(idx.checked_sub(1)?)?;
    (ip <= r.1).then_some(r.2)
}

/// `a.b.c.d/len`, `x:y::/len` or a bare address, as inclusive bounds and
/// "is IPv4". Strict: a prefix with host bits set is refused, because
/// `10.1.2.3/8` is more often a typo for a /32 than a way to write `10/8`.
fn parse_cidr(text: &str) -> Result<(u128, u128, bool), String> {
    let (addr, len) = match text.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (text, None),
    };
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| "not an address or a CIDR (e.g. 203.0.113.0/24, 2001:db8::/32)".to_string())?;
    let (value, bits, is_v4) = match ip {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32u32, true),
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => {
            return Err("an IPv4-mapped IPv6 address: write the IPv4 network".to_string())
        }
        IpAddr::V6(v6) => (u128::from(v6), 128u32, false),
    };
    let len: u32 = match len {
        None => bits,
        Some(l) => l
            .parse()
            .ok()
            .filter(|n| *n <= bits && l.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| format!("the prefix length must be 0 to {bits}"))?,
    };
    // `::/0` leaves 128 host bits: a shift by the whole width is not defined.
    let host_mask: u128 = match bits - len {
        128 => u128::MAX,
        host_bits => (1u128 << host_bits) - 1,
    };
    if value & host_mask != 0 {
        let network = value & !host_mask;
        let shown = if is_v4 {
            std::net::Ipv4Addr::from(network as u32).to_string()
        } else {
            std::net::Ipv6Addr::from(network).to_string()
        };
        return Err(format!(
            "has bits set beyond the /{len}: write {shown}/{len}, or the single address with /{bits}"
        ));
    }
    Ok((value, value | host_mask, is_v4))
}

/// Turn nested prefixes into disjoint ranges where the most specific prefix
/// wins. `entries` is sorted parent-before-child (by start, larger first) and
/// holds no duplicate. Two CIDR blocks either nest or do not touch, so one
/// pass with a stack of the blocks currently open is enough.
fn flatten(entries: &[(u128, u128, IpClass)]) -> Vec<(u128, u128, IpClass)> {
    fn emit(out: &mut Vec<(u128, u128, IpClass)>, start: u128, end: u128, class: IpClass) {
        match out.last_mut() {
            Some(last) if last.2 == class && last.1.checked_add(1) == Some(start) => last.1 = end,
            _ => out.push((start, end, class)),
        }
    }
    let mut out = Vec::with_capacity(entries.len());
    let mut open: Vec<(u128, u128, IpClass)> = Vec::new();
    // The first address not written yet; `None` once the top of the space is written.
    let mut cursor: Option<u128> = Some(0);
    for &entry in entries {
        // Blocks that end before this one starts are finished.
        while let Some(&top) = open.last() {
            if top.1 >= entry.0 {
                break;
            }
            if let Some(at) = cursor.filter(|at| *at <= top.1) {
                emit(&mut out, at, top.1, top.2);
            }
            cursor = top.1.checked_add(1);
            open.pop();
        }
        // What is left on top contains this one: its part before it is written.
        if let (Some(&top), Some(at)) = (open.last(), cursor) {
            if at < entry.0 {
                emit(&mut out, at, entry.0 - 1, top.2);
            }
        }
        cursor = Some(entry.0);
        open.push(entry);
    }
    while let Some(top) = open.pop() {
        if let Some(at) = cursor.filter(|at| *at <= top.1) {
            emit(&mut out, at, top.1, top.2);
        }
        cursor = top.1.checked_add(1);
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
// Data age
// ═══════════════════════════════════════════════════════════════════
//
// The tables are compiled in. They are refreshed in the repository every
// week, and a binary keeps the ones it was built with for as long as it
// runs: without a date, nothing on the machine says how old they are.

/// The tables compiled into this build: `(region, day of the last snapshot)`.
pub fn snapshots() -> &'static [(&'static str, &'static str)] {
    &[
        #[cfg(feature = "geo-ita")]
        ("ita", data_ita::SNAPSHOT_DATE),
        #[cfg(feature = "geo-eu")]
        ("eu", data_eu::SNAPSHOT_DATE),
    ]
}

/// A table older than this is reported at boot. Six weekly refreshes: address
/// space is allocated, moved and re-announced every week, and the table also
/// waits up to three snapshots before it follows.
pub const STALE_AFTER_DAYS: i64 = 45;

/// Days from 1970-01-01 to a `YYYY-MM-DD` date (proleptic Gregorian calendar).
/// `None` when the text is not a date.
pub fn days_from_civil(date: &str) -> Option<i64> {
    let b = date.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |s: &str| -> Option<i64> {
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())
            .flatten()
    };
    let (y, m, d) = (num(&date[0..4])?, num(&date[5..7])?, num(&date[8..10])?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_len = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if d < 1 || d > month_len {
        return None;
    }
    // Days-from-civil, with the year starting in March so that the leap day
    // is the last day of the year.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Midnight UTC of a snapshot date, in seconds since the epoch.
pub fn snapshot_epoch_secs(date: &str) -> Option<i64> {
    days_from_civil(date).map(|d| d * 86_400)
}

/// How many whole days old a snapshot date is at `now_secs` (seconds since
/// the epoch). Negative when the date is in the future (a clock set wrong).
pub fn age_days(date: &str, now_secs: u64) -> Option<i64> {
    days_from_civil(date).map(|d| (now_secs / 86_400) as i64 - d)
}

/// The compiled-in tables older than [`STALE_AFTER_DAYS`] at `now_secs`:
/// `(region, snapshot date, age in days)`.
pub fn stale_tables(now_secs: u64) -> Vec<(&'static str, &'static str, i64)> {
    snapshots()
        .iter()
        .filter_map(|&(region, date)| {
            let age = age_days(date, now_secs)?;
            (age > STALE_AFTER_DAYS).then_some((region, date, age))
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════
// Sovereign Config (parsed from zion.toml)
// ═══════════════════════════════════════════════════════════════════

/// Configuration for the `[sovereign]` section in zion.toml.
/// Parsed at boot and on hot-reload. When `enabled = false` (default),
/// the sovereign gate is never invoked — zero overhead.
#[allow(dead_code)] // region/signals/signal_listen reserved for Phase 2/3
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// `[sovereign.overrides]`: `"CIDR" = "class"`. Consulted before the
    /// compiled-in tables, the most specific prefix wins. Read at boot and on
    /// reload, so a wrong row in a table does not need a rebuild.
    #[serde(default)]
    pub overrides: std::collections::BTreeMap<String, String>,
}

/// `[sovereign.enforce]` — promotes the origin tag / mesh-reputation
/// score from *signal* to an opt-in admission gate (issue #150). Disabled
/// by default. The local WAF / rate-limiter / auth gates stay
/// authoritative; this only adds a deny on top.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// L7 tarpit (#151): escalate a deny from a cheap `403` to a bounded
    /// *held* connection. Off by default.
    #[serde(default)]
    pub tarpit: TarpitConfig,
}

impl Default for EnforceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            deny: Vec::new(),
            mesh_score_deny_above: 0.0,
            tarpit: TarpitConfig::default(),
        }
    }
}

/// `[sovereign.enforce.tarpit]` — escalate an enforcement *deny* from a
/// cheap `403` to a bounded held connection (issue #151). Off by default.
/// Bounded by `max_concurrent`: at the ceiling the tarpit sheds back to an
/// immediate `403`, so it can never become a self-inflicted resource sink.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TarpitConfig {
    /// Master switch. Default: false (denies stay immediate 403s). Only
    /// takes effect when `[sovereign.enforce] enabled = true`.
    #[serde(default)]
    pub enabled: bool,
    /// How long a flagged connection is held before its rejection, seconds.
    #[serde(default = "default_tarpit_hold_secs")]
    pub hold_secs: u64,
    /// Hard ceiling on concurrently-held connections. At the ceiling the
    /// tarpit sheds to an immediate `403`. `0` holds nothing (sheds all).
    #[serde(default = "default_tarpit_max_concurrent")]
    pub max_concurrent: u32,
}

fn default_tarpit_hold_secs() -> u64 {
    10
}

fn default_tarpit_max_concurrent() -> u32 {
    // Small fixed fraction of any box's connection pool (the global ceiling
    // is RAM-scaled with a ~1000 floor). Kept comfortably below the
    // `conn_limit/4` self-DoS clamp applied at config-load (#151) so the
    // default never trips the clamp warning. Operators can raise it; the
    // clamp still bounds an over-large override.
    128
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hold_secs: default_tarpit_hold_secs(),
            max_concurrent: default_tarpit_max_concurrent(),
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
    /// True only when enforcement *and* the tarpit are both on (#151) — a
    /// tarpit with no enforcement deny would never fire.
    pub tarpit_enabled: bool,
    /// How long a flagged connection is held before its rejection.
    pub tarpit_hold: std::time::Duration,
    /// Hard ceiling on concurrently-held tarpit connections; at the ceiling
    /// the deny path sheds to an immediate rejection.
    pub tarpit_max_concurrent: u32,
}

impl EnforcePolicy {
    pub fn from_config(c: &EnforceConfig) -> Self {
        Self {
            enabled: c.enabled,
            deny: c.deny.iter().map(|s| s.to_ascii_lowercase()).collect(),
            mesh_score_deny_above: c.mesh_score_deny_above,
            // The tarpit is an escalation of an enforcement deny, so it is
            // live only when enforcement itself is enabled.
            tarpit_enabled: c.enabled && c.tarpit.enabled,
            tarpit_hold: std::time::Duration::from_secs(c.tarpit.hold_secs),
            tarpit_max_concurrent: c.tarpit.max_concurrent,
        }
    }

    /// Clamp the tarpit concurrency ceiling to a safe fraction (1/4) of the
    /// global connection pool and report what changed (#151). A held tarpit
    /// connection keeps its global connection-pool permit and per-IP slot for
    /// the whole hold, so an unbounded ceiling lets a flood of flagged sources
    /// pin admission — this invariant belongs to the enforcement policy, not
    /// the composition root. No-op unless the tarpit is enabled with a positive
    /// ceiling. Returns `Some((old, cap))` when it clamped, so the caller can
    /// warn; `None` when nothing changed.
    pub fn clamp_tarpit_concurrency(&mut self, conn_limit_max: usize) -> Option<(u32, u32)> {
        if !self.tarpit_enabled || self.tarpit_max_concurrent == 0 {
            return None;
        }
        let safety_cap = ((conn_limit_max / 4) as u32).max(1);
        if self.tarpit_max_concurrent > safety_cap {
            let old = self.tarpit_max_concurrent;
            self.tarpit_max_concurrent = safety_cap;
            Some((old, safety_cap))
        } else {
            None
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
            overrides: std::collections::BTreeMap::new(),
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

    // ── Golden classification (regression net) ───────────────────────
    // A small, stable set with its role PINNED. Unlike the loose EU test
    // above, these fail if a role changes at all — so even with correct
    // upstream data, a curated ASN silently dropping out or a lookup
    // regression is caught. Regenerated alongside the CIDR tables; if a
    // legitimate RIPE reassignment moves one of these, update it deliberately.
    #[cfg(feature = "geo-ita")]
    #[test]
    fn golden_classify_italian_roles() {
        // 193.206.0.1 — GARR (AS137), the Italian academic/research network.
        assert_eq!(classify("193.206.0.1".parse().unwrap()), IpClass::GovIta);
        // 2.16.17.0 — a curated Italian residential-ISP range.
        assert_eq!(
            classify("2.16.17.0".parse().unwrap()),
            IpClass::ResidentialIta
        );
        // 62.123.0.1 — Retelit (AS12797), a curated hoster, in space registered
        // in Italy: both conditions of `DatacenterIta`.
        assert_eq!(
            classify("62.123.0.1".parse().unwrap()),
            IpClass::DatacenterIta
        );
        // A non-sovereign IP stays Unknown.
        assert_eq!(classify("8.8.8.8".parse().unwrap()), IpClass::Unknown);
    }

    // A role class needs a curated ASN AND space registered in the region.
    // 2.26.132.0 is announced by OVH (AS16276, curated on both lists) from a
    // block registered in the United States. It was `DatacenterIta`, then
    // `DatacenterEu`; by the registry it is neither Italian nor in the EU-27.
    #[cfg(feature = "geo-ita")]
    #[test]
    fn a_curated_hoster_range_registered_outside_the_region_has_no_class() {
        assert_eq!(classify("2.26.132.0".parse().unwrap()), IpClass::Unknown);
        // The same company's space registered in France keeps its EU role.
        #[cfg(feature = "geo-eu")]
        assert_eq!(
            classify("57.128.0.1".parse().unwrap()),
            IpClass::DatacenterEu
        );
    }

    #[cfg(feature = "geo-eu")]
    #[test]
    fn golden_classify_eu_roles() {
        // 193.0.0.1 — RIPE NCC (NL): an EU-27 allocation with no curated role.
        assert_eq!(classify("193.0.0.1".parse().unwrap()), IpClass::Eu);
        // 217.0.0.1 — Deutsche Telekom (AS3320, DE): curated residential override.
        assert_eq!(
            classify("217.0.0.1".parse().unwrap()),
            IpClass::ResidentialEu
        );
        // 45.12.192.0 — a curated EU government/research range.
        assert_eq!(classify("45.12.192.0".parse().unwrap()), IpClass::GovEu);
        // 62.171.128.1 — Contabo (AS51167, DE): a curated EU datacenter.
        assert_eq!(
            classify("62.171.128.1".parse().unwrap()),
            IpClass::DatacenterEu
        );
    }

    // ── One pinned address per curated ASN ───────────────────────────
    //
    // The tables are regenerated every week. These addresses are what a
    // refresh must not move without someone noticing: for each curated ASN,
    // one address in its largest long-held block, with the class it must
    // have. A refresh that drops an ASN, or a change that breaks the lookup,
    // fails here by name. An address that really moved (the operator gave the
    // block back) is updated by hand, which is the point.
    //
    // `(ASN, address, class)`. Chosen on the 2026-10-06 tables.
    #[cfg(feature = "geo-ita")]
    const ITALIAN_POINTS: &[(u32, &str, IpClass)] = &[
        (137, "193.205.0.1", IpClass::GovIta), // GARR
        (137, "2001:760::1", IpClass::GovIta),
        (2598, "192.65.131.1", IpClass::GovIta), // CNR
        (2598, "2001:67c:1b08::1", IpClass::GovIta),
        (41325, "84.38.60.1", IpClass::GovIta), // Regione Marche
        (3269, "79.10.0.1", IpClass::ResidentialIta), // TIM
        (3269, "2a01:2000::1", IpClass::ResidentialIta),
        (16232, "2.192.0.1", IpClass::ResidentialIta), // TIM mobile
        (16232, "2a03:8980::1", IpClass::ResidentialIta),
        (12874, "93.32.0.1", IpClass::ResidentialIta), // Fastweb
        (12874, "2001:b00::1", IpClass::ResidentialIta),
        (30722, "93.64.0.1", IpClass::ResidentialIta), // Vodafone Italia
        (30722, "2a01:820::1", IpClass::ResidentialIta),
        (1267, "151.20.0.1", IpClass::ResidentialIta), // Wind Tre
        (1267, "2a02:b000::1", IpClass::ResidentialIta),
        (8612, "84.220.0.1", IpClass::ResidentialIta), // Tiscali
        (8612, "2a01:7d0::1", IpClass::ResidentialIta),
        (35612, "146.241.0.1", IpClass::ResidentialIta), // Eolo
        (35612, "2001:4c90::1", IpClass::ResidentialIta),
        (210278, "101.56.0.1", IpClass::ResidentialIta), // Sky Italia
        (210278, "2a0e:400::1", IpClass::ResidentialIta),
        (31034, "80.211.0.1", IpClass::DatacenterIta), // Aruba
        (31034, "2a00:6d40::1", IpClass::DatacenterIta),
        (12797, "62.123.128.1", IpClass::DatacenterIta), // Retelit (ex Atlanet)
        (60798, "45.14.184.1", IpClass::DatacenterIta),  // Servereasy
        (60798, "2a00:82e0::1", IpClass::DatacenterIta),
        (49367, "95.141.40.1", IpClass::DatacenterIta), // Seflow
        (49367, "2a0a:5b80::1", IpClass::DatacenterIta),
        (201333, "212.54.240.1", IpClass::DatacenterIta), // Naquadria
        (201333, "2a02:4722::1", IpClass::DatacenterIta),
        (197075, "37.77.160.1", IpClass::DatacenterIta), // Active Network
        (197075, "2a03:ff80::1", IpClass::DatacenterIta),
        (8968, "78.4.0.1", IpClass::DatacenterIta), // Retelit (ex BT Italia)
        (8968, "2a02:4d80::1", IpClass::DatacenterIta),
        (39120, "89.21.192.1", IpClass::DatacenterIta), // Convergenze
        (39120, "2a01:9a80::1", IpClass::DatacenterIta),
        (34758, "31.6.80.1", IpClass::DatacenterIta), // Axera
        (34758, "2a04:2080::1", IpClass::DatacenterIta),
        (16276, "45.66.82.1", IpClass::DatacenterIta), // OVH, its block registered in Italy
    ];

    /// Curated Italian ASNs with no pinned address, each with the reason.
    #[cfg(feature = "geo-ita")]
    const ITALIAN_WITHOUT_POINT: &[(u32, &str)] = &[(
        24608,
        "Wind Tre's second ASN, curated on 2026-10-06: an added ASN waits two weekly snapshots like any observation, so its ranges are not in the table yet. Pin 5.84.0.1 once they are",
    )];

    #[cfg(feature = "geo-eu")]
    const EU_POINTS: &[(u32, &str, IpClass)] = &[
        (20965, "62.40.96.1", IpClass::GovEu), // GEANT
        (20965, "2001:798::1", IpClass::GovEu),
        (21320, "83.97.88.1", IpClass::GovEu), // GEANT
        (680, "141.44.0.1", IpClass::GovEu),   // DFN
        (680, "2001:4cf0::1", IpClass::GovEu),
        (2200, "132.166.0.1", IpClass::GovEu), // Renater
        (2200, "2a07:2e40::1", IpClass::GovEu),
        (766, "193.144.0.1", IpClass::GovEu), // RedIRIS
        (766, "2001:720::1", IpClass::GovEu),
        (1103, "145.144.0.1", IpClass::GovEu), // SURF
        (1103, "2001:611::1", IpClass::GovEu),
        (3320, "79.192.0.1", IpClass::ResidentialEu), // Deutsche Telekom
        (3320, "2003:100::1", IpClass::ResidentialEu),
        (3209, "188.96.0.1", IpClass::ResidentialEu), // Vodafone Germany
        (3209, "2a00::1", IpClass::ResidentialEu),
        (3215, "90.10.0.1", IpClass::ResidentialEu), // Orange
        (3215, "2a01:cb00::1", IpClass::ResidentialEu),
        (12322, "82.224.0.1", IpClass::ResidentialEu), // Free
        (12322, "2a01:e30::1", IpClass::ResidentialEu),
        (3352, "83.32.0.1", IpClass::ResidentialEu), // Telefonica
        (3352, "2a02:9100::1", IpClass::ResidentialEu),
        (1136, "77.160.0.1", IpClass::ResidentialEu), // KPN
        (1136, "2a02:a400::1", IpClass::ResidentialEu),
        (5432, "109.128.0.1", IpClass::ResidentialEu), // Proximus
        (5432, "2a02:a000::1", IpClass::ResidentialEu),
        (5617, "83.10.0.1", IpClass::ResidentialEu), // Orange Polska
        (5617, "2a01:1200::1", IpClass::ResidentialEu),
        (8447, "91.112.0.1", IpClass::ResidentialEu), // A1 Telekom Austria
        (8447, "2001:850::1", IpClass::ResidentialEu),
        (16276, "57.128.0.1", IpClass::DatacenterEu), // OVH
        (16276, "2001:41d0::1", IpClass::DatacenterEu),
        (24940, "2.28.0.1", IpClass::DatacenterEu), // Hetzner
        (24940, "2a06:be80::1", IpClass::DatacenterEu),
        (213230, "5.161.0.1", IpClass::DatacenterEu), // Hetzner
        (213230, "2a01:4ff::1", IpClass::DatacenterEu),
        (12876, "51.15.0.1", IpClass::DatacenterEu), // Scaleway
        (12876, "2001:bc8:7000::1", IpClass::DatacenterEu),
        (8560, "82.223.0.1", IpClass::DatacenterEu), // IONOS
        (8560, "2a0d:7f00::1", IpClass::DatacenterEu),
        (60781, "85.17.0.1", IpClass::DatacenterEu), // LeaseWeb
        (60781, "2a01:b2e0::1", IpClass::DatacenterEu),
        (51167, "169.58.0.1", IpClass::DatacenterEu), // Contabo
        (51167, "2a02:c204::1", IpClass::DatacenterEu),
    ];

    /// Curated EU ASNs with no pinned EU address: they are Italian operators,
    /// and the Italian table, consulted first, already answers for their space.
    #[cfg(feature = "geo-eu")]
    const EU_WITHOUT_POINT: &[(u32, &str)] = &[
        (137, "GARR: its space is in the Italian table"),
        (2598, "CNR: its space is in the Italian table"),
        (3269, "TIM: its space is in the Italian table"),
        (12797, "Retelit: its space is in the Italian table"),
    ];

    /// Addresses that must stay `Unknown` on every build: large networks
    /// outside the EU-27, among them three European countries that are not
    /// members.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    const OUTSIDE: &[(&str, &str)] = &[
        ("8.8.8.8", "Google, US"),
        ("1.1.1.1", "Cloudflare, US"),
        ("77.88.8.8", "Yandex, RU"),
        ("114.114.114.114", "114DNS, CN"),
        ("212.58.244.1", "BBC, GB: not in the EU-27"),
        ("195.176.0.1", "SWITCH, CH: not in the EU-27"),
        ("158.36.0.1", "Sikt, NO: not in the EU-27"),
        ("2606:4700:4700::1111", "Cloudflare, US"),
        ("2001:4860:4860::8888", "Google, US"),
        ("2a02:6b8::feed:ff", "Yandex, RU"),
        ("2001:630::1", "Jisc, GB: not in the EU-27"),
        ("2001:620::1", "SWITCH, CH: not in the EU-27"),
    ];

    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    fn check_points(points: &[(u32, &str, IpClass)]) {
        let wrong: Vec<String> = points
            .iter()
            .filter_map(|&(asn, ip, want)| {
                let got = classify(ip.parse().unwrap());
                (got != want).then(|| format!("AS{asn} {ip}: {got:?}, expected {want:?}"))
            })
            .collect();
        assert!(
            wrong.is_empty(),
            "pinned addresses moved:\n{}",
            wrong.join("\n")
        );
    }

    /// Every curated ASN is either pinned or excused, and nothing is pinned or
    /// excused that is not curated: the list in the generator and the points
    /// here cannot drift apart.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    fn check_coverage(
        curated: &[(u32, IpClass)],
        points: &[(u32, &str, IpClass)],
        excused: &[(u32, &str)],
    ) {
        use std::collections::BTreeSet;
        let curated: BTreeSet<u32> = curated.iter().map(|&(asn, _)| asn).collect();
        let pinned: BTreeSet<u32> = points.iter().map(|&(asn, _, _)| asn).collect();
        let excused: BTreeSet<u32> = excused.iter().map(|&(asn, _)| asn).collect();
        let covered: BTreeSet<u32> = pinned.union(&excused).copied().collect();
        assert_eq!(
            curated.difference(&covered).collect::<Vec<_>>(),
            Vec::<&u32>::new(),
            "curated ASNs with no pinned address and no stated reason"
        );
        assert_eq!(
            covered.difference(&curated).collect::<Vec<_>>(),
            Vec::<&u32>::new(),
            "pinned or excused ASNs that are not on the curated list"
        );
        assert_eq!(
            pinned.intersection(&excused).collect::<Vec<_>>(),
            Vec::<&u32>::new(),
            "ASNs both pinned and excused"
        );
    }

    #[cfg(feature = "geo-ita")]
    #[test]
    fn every_curated_italian_asn_keeps_its_pinned_address() {
        check_points(ITALIAN_POINTS);
        check_coverage(
            data_ita::CURATED_ASNS,
            ITALIAN_POINTS,
            ITALIAN_WITHOUT_POINT,
        );
        // The role of each point is the role its ASN is curated with.
        for &(asn, ip, class) in ITALIAN_POINTS {
            let curated = data_ita::CURATED_ASNS.iter().find(|c| c.0 == asn).unwrap();
            assert_eq!(curated.1, class, "AS{asn} {ip}");
        }
    }

    #[cfg(feature = "geo-eu")]
    #[test]
    fn every_curated_eu_asn_keeps_its_pinned_address() {
        check_points(EU_POINTS);
        check_coverage(data_eu::CURATED_ASNS, EU_POINTS, EU_WITHOUT_POINT);
        for &(asn, ip, class) in EU_POINTS {
            let curated = data_eu::CURATED_ASNS.iter().find(|c| c.0 == asn).unwrap();
            assert_eq!(curated.1, class, "AS{asn} {ip}");
        }
    }

    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    #[test]
    fn large_networks_outside_the_region_stay_unknown() {
        let wrong: Vec<String> = OUTSIDE
            .iter()
            .filter_map(|&(ip, who)| {
                let got = classify(ip.parse().unwrap());
                (got != IpClass::Unknown).then(|| format!("{ip} ({who}): {got:?}"))
            })
            .collect();
        assert!(
            wrong.is_empty(),
            "classified, and must not be:\n{}",
            wrong.join("\n")
        );
    }

    // ── Floors ────────────────────────────────────────────────────────
    // A table that lost most of a class still sorts and does not overlap.
    // Each floor is about three quarters of the class on 2026-10-06.
    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    fn v4_addresses(ranges: &[CidrEntry], class: IpClass) -> u64 {
        ranges
            .iter()
            .filter(|e| e.class == class)
            .map(|e| u64::from(e.end - e.start) + 1)
            .sum()
    }

    #[cfg(feature = "geo-ita")]
    #[test]
    fn the_italian_table_holds_each_class() {
        let t = data_ita::RANGES;
        assert!(v4_addresses(t, IpClass::GovIta) > 2_000_000);
        assert!(v4_addresses(t, IpClass::ResidentialIta) > 29_000_000);
        assert!(v4_addresses(t, IpClass::DatacenterIta) > 1_000_000);
        assert!(data_ita::RANGES6.len() >= 20);
    }

    #[cfg(feature = "geo-eu")]
    #[test]
    fn the_eu_table_holds_each_class() {
        let t = data_eu::RANGES;
        assert!(v4_addresses(t, IpClass::Eu) > 265_000_000);
        assert!(v4_addresses(t, IpClass::GovEu) > 16_000_000);
        assert!(v4_addresses(t, IpClass::ResidentialEu) > 94_000_000);
        assert!(v4_addresses(t, IpClass::DatacenterEu) > 6_400_000);
        assert!(data_eu::RANGES6.len() >= 11_000);
    }

    // ── Operator overrides ────────────────────────────────────────────
    fn overrides(pairs: &[(&str, &str)]) -> Result<Overrides, Vec<String>> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(c, l)| (c.to_string(), l.to_string()))
            .collect();
        Overrides::from_config(owned.iter().map(|(c, l)| (c, l)))
    }

    fn class_of(o: &Overrides, ip: &str) -> Option<IpClass> {
        o.lookup(ip.parse().unwrap())
    }

    #[test]
    fn a_cidr_parses_to_its_first_and_last_address() {
        assert_eq!(
            parse_cidr("203.0.113.0/24"),
            Ok((0xCB00_7100, 0xCB00_71FF, true))
        );
        assert_eq!(
            parse_cidr("203.0.113.7"),
            Ok((0xCB00_7107, 0xCB00_7107, true))
        );
        assert_eq!(
            parse_cidr("203.0.113.7/32"),
            Ok((0xCB00_7107, 0xCB00_7107, true))
        );
        assert_eq!(parse_cidr("0.0.0.0/0"), Ok((0, 0xFFFF_FFFF, true)));
        let db8 = 0x2001_0db8u128 << 96;
        assert_eq!(
            parse_cidr("2001:db8::/32"),
            Ok((db8, db8 | ((1u128 << 96) - 1), false))
        );
        assert_eq!(parse_cidr("2001:db8::1"), Ok((db8 | 1, db8 | 1, false)));
        assert_eq!(parse_cidr("::/0"), Ok((0, u128::MAX, false)));
    }

    #[test]
    fn a_cidr_that_is_not_one_says_why() {
        for bad in [
            "",
            "203.0.113",
            "203.0.113.0/",
            "example.com",
            "203.0.113.0/24/1",
            "/24",
        ] {
            assert!(
                parse_cidr(bad)
                    .unwrap_err()
                    .starts_with("not an address or a CIDR")
                    || parse_cidr(bad)
                        .unwrap_err()
                        .starts_with("the prefix length"),
                "{bad:?}: {:?}",
                parse_cidr(bad)
            );
        }
        for bad in [
            "203.0.113.0/33",
            "203.0.113.0/-1",
            "203.0.113.0/+8",
            "203.0.113.0/ 8",
            "203.0.113.0/8x",
        ] {
            assert_eq!(
                parse_cidr(bad).unwrap_err(),
                "the prefix length must be 0 to 32",
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_cidr("2001:db8::/129").unwrap_err(),
            "the prefix length must be 0 to 128"
        );
        // Host bits set: say what the network is.
        assert_eq!(
            parse_cidr("203.0.113.7/24").unwrap_err(),
            "has bits set beyond the /24: write 203.0.113.0/24, or the single address with /32"
        );
        assert_eq!(
            parse_cidr("2001:db8::1/32").unwrap_err(),
            "has bits set beyond the /32: write 2001:db8::/32, or the single address with /128"
        );
        assert_eq!(
            parse_cidr("::ffff:203.0.113.0/120").unwrap_err(),
            "an IPv4-mapped IPv6 address: write the IPv4 network"
        );
    }

    #[test]
    fn every_problem_in_an_override_list_is_reported() {
        let errs = overrides(&[
            ("203.0.113.0/24", "residential_ita"),
            ("198.51.100.9/24", "gov_ita"),
            ("192.0.2.0/24", "datacentre_ita"),
            ("not-a-cidr", "also-not-a-class"),
        ])
        .unwrap_err();
        assert_eq!(errs.len(), 4, "{errs:#?}");
        assert!(errs.iter().any(|e| e
            .starts_with("sovereign.overrides \"198.51.100.9/24\": has bits set beyond the /24")));
        assert!(errs.iter().any(|e| e.starts_with(
            "sovereign.overrides \"192.0.2.0/24\": \"datacentre_ita\" is not a class of this build (known: gov_ita, "
        )));
        assert!(errs
            .iter()
            .any(|e| e.contains("\"also-not-a-class\" is not a class")));
        assert!(errs
            .iter()
            .any(|e| e.starts_with("sovereign.overrides \"not-a-cidr\": not an address")));
    }

    #[test]
    fn the_same_network_written_twice_is_refused() {
        let errs = overrides(&[
            ("2001:db8::/32", "gov_ita"),
            ("2001:0db8:0::/32", "unknown"),
        ])
        .unwrap_err();
        assert_eq!(
            errs,
            ["sovereign.overrides: the same network is listed twice (2001:db8::)"]
        );
        let errs =
            overrides(&[("203.0.113.7", "gov_ita"), ("203.0.113.7/32", "gov_ita")]).unwrap_err();
        assert_eq!(
            errs,
            ["sovereign.overrides: the same network is listed twice (203.0.113.7)"]
        );
        // The same prefix in the two families is two networks.
        assert!(overrides(&[("0.0.0.0/0", "unknown"), ("::/0", "unknown")]).is_ok());
    }

    #[test]
    fn the_most_specific_override_wins() {
        let o = overrides(&[
            ("203.0.113.0/24", "residential_ita"),
            ("203.0.113.64/26", "datacenter_ita"),
            ("203.0.113.80/32", "Gov_Ita"), // labels in any case
            ("2001:db8::/32", "gov_ita"),
            ("2001:db8:ff00::/40", "unknown"),
        ])
        .unwrap();
        assert_eq!(o.len(), 5);
        assert!(!o.is_empty());
        assert_eq!(class_of(&o, "203.0.112.255"), None);
        assert_eq!(class_of(&o, "203.0.113.0"), Some(IpClass::ResidentialIta));
        assert_eq!(class_of(&o, "203.0.113.63"), Some(IpClass::ResidentialIta));
        assert_eq!(class_of(&o, "203.0.113.64"), Some(IpClass::DatacenterIta));
        assert_eq!(class_of(&o, "203.0.113.79"), Some(IpClass::DatacenterIta));
        assert_eq!(class_of(&o, "203.0.113.80"), Some(IpClass::GovIta));
        assert_eq!(class_of(&o, "203.0.113.81"), Some(IpClass::DatacenterIta));
        assert_eq!(class_of(&o, "203.0.113.127"), Some(IpClass::DatacenterIta));
        assert_eq!(class_of(&o, "203.0.113.128"), Some(IpClass::ResidentialIta));
        assert_eq!(class_of(&o, "203.0.113.255"), Some(IpClass::ResidentialIta));
        assert_eq!(class_of(&o, "203.0.114.0"), None);
        // IPv6, and an override to `unknown` is an answer, not an absence.
        assert_eq!(class_of(&o, "2001:db8::1"), Some(IpClass::GovIta));
        assert_eq!(class_of(&o, "2001:db8:ff00::1"), Some(IpClass::Unknown));
        assert_eq!(
            class_of(&o, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
            Some(IpClass::Unknown)
        );
        assert_eq!(class_of(&o, "2001:db9::"), None);
        // An IPv4 client seen through a dual-stack socket is the same client.
        assert_eq!(class_of(&o, "::ffff:203.0.113.80"), Some(IpClass::GovIta));
    }

    #[test]
    fn an_override_can_cover_the_whole_address_space() {
        let o = overrides(&[
            ("0.0.0.0/0", "unknown"),
            ("255.255.255.255", "gov_ita"),
            ("::/0", "residential_ita"),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "gov_ita"),
            ("::", "datacenter_ita"),
        ])
        .unwrap();
        assert_eq!(class_of(&o, "0.0.0.0"), Some(IpClass::Unknown));
        assert_eq!(class_of(&o, "255.255.255.254"), Some(IpClass::Unknown));
        assert_eq!(class_of(&o, "255.255.255.255"), Some(IpClass::GovIta));
        assert_eq!(class_of(&o, "::"), Some(IpClass::DatacenterIta));
        assert_eq!(class_of(&o, "::1"), Some(IpClass::ResidentialIta));
        assert_eq!(
            class_of(&o, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"),
            Some(IpClass::ResidentialIta)
        );
        assert_eq!(
            class_of(&o, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            Some(IpClass::GovIta)
        );
    }

    #[test]
    fn no_overrides_answer_nothing() {
        let o = overrides(&[]).unwrap();
        assert!(o.is_empty());
        assert_eq!(o.len(), 0);
        assert_eq!(class_of(&o, "203.0.113.1"), None);
        assert_eq!(class_of(&Overrides::default(), "2001:db8::1"), None);
        // `classify_with` then is `classify`.
        for ip in ["8.8.8.8", "193.205.0.1", "2001:760::1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(classify_with(&o, ip), classify(ip));
        }
    }

    #[test]
    fn labels_name_the_classes_of_this_build() {
        for &label in known_class_labels() {
            assert_eq!(IpClass::from_label(label).unwrap().as_str(), label);
            assert_eq!(
                IpClass::from_label(&label.to_uppercase()).unwrap().as_str(),
                label
            );
        }
        assert_eq!(ALL_CLASSES.len(), known_class_labels().len());
        assert_eq!(IpClass::from_label("datacentre_ita"), None);
        assert_eq!(IpClass::from_label(""), None);
        #[cfg(not(feature = "geo-eu"))]
        assert_eq!(IpClass::from_label("eu"), None);
    }

    // An override decides before the tables do, in both directions: a foreign
    // address made Italian, and an Italian one taken out.
    #[cfg(feature = "geo-ita")]
    #[test]
    fn an_override_is_consulted_before_the_tables() {
        let o = overrides(&[
            ("8.8.8.0/24", "gov_ita"),
            ("193.205.0.0/24", "unknown"),
            ("2001:760::/64", "datacenter_ita"),
        ])
        .unwrap();
        let class = |ip: &str| classify_with(&o, ip.parse().unwrap());
        assert_eq!(classify("8.8.8.8".parse().unwrap()), IpClass::Unknown);
        assert_eq!(class("8.8.8.8"), IpClass::GovIta);
        assert_eq!(classify("193.205.0.1".parse().unwrap()), IpClass::GovIta);
        assert_eq!(class("193.205.0.1"), IpClass::Unknown);
        assert_eq!(class("2001:760::1"), IpClass::DatacenterIta);
        // Next to an override the table still answers.
        assert_eq!(class("193.205.1.1"), IpClass::GovIta);
        assert_eq!(class("2001:760:1::1"), IpClass::GovIta);
        assert_eq!(class("8.8.4.4"), IpClass::Unknown);
    }

    mod override_properties {
        use super::*;
        use proptest::prelude::*;

        const CLASSES: [IpClass; 4] = [
            IpClass::GovIta,
            IpClass::ResidentialIta,
            IpClass::DatacenterIta,
            IpClass::Unknown,
        ];

        /// Up to 24 prefixes inside a block of 4,096 addresses: `(offset, extra
        /// prefix bits 0..=12, class)`.
        fn prefixes() -> impl Strategy<Value = Vec<(u32, u32, usize)>> {
            proptest::collection::vec((0u32..4096, 0u32..=12, 0usize..4), 0..24)
        }

        /// The class of the most specific prefix that contains `offset`, the way
        /// a person would look it up: try every prefix, keep the longest.
        fn by_hand(list: &[(u32, u32, IpClass)], offset: u32) -> Option<IpClass> {
            list.iter()
                .filter(|(start, bits, _)| offset >> (12 - bits) == start >> (12 - bits))
                .max_by_key(|(_, bits, _)| *bits)
                .map(|(_, _, class)| *class)
        }

        fn dedup(raw: Vec<(u32, u32, usize)>) -> Vec<(u32, u32, IpClass)> {
            let mut seen = std::collections::BTreeSet::new();
            raw.into_iter()
                .map(|(offset, bits, class)| {
                    let start = (offset >> (12 - bits)) << (12 - bits);
                    (start, bits, CLASSES[class])
                })
                .filter(|(start, bits, _)| seen.insert((*start, *bits)))
                .collect()
        }

        proptest! {
            #[test]
            fn ipv4_lookup_is_the_most_specific_prefix(raw in prefixes()) {
                let list = dedup(raw);
                let base = u32::from(std::net::Ipv4Addr::new(10, 20, 0, 0));
                let pairs: Vec<(String, String)> = list.iter().map(|(start, bits, class)| (
                    format!("{}/{}", std::net::Ipv4Addr::from(base + start), 20 + bits),
                    class.as_str().to_string(),
                )).collect();
                let o = Overrides::from_config(pairs.iter().map(|(c, l)| (c, l))).unwrap();
                prop_assert_eq!(o.len(), list.len());
                for offset in 0..4096u32 {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::from(base + offset));
                    prop_assert_eq!(o.lookup(ip), by_hand(&list, offset), "offset {}", offset);
                }
                // Outside the block nothing answers.
                prop_assert_eq!(o.lookup(IpAddr::V4(std::net::Ipv4Addr::from(base - 1))), None);
                prop_assert_eq!(o.lookup(IpAddr::V4(std::net::Ipv4Addr::from(base + 4096))), None);
                // Written down as sorted ranges that do not touch needlessly.
                for w in o.v4.windows(2) {
                    prop_assert!(w[0].1 < w[1].0);
                    prop_assert!(!(w[0].1 + 1 == w[1].0 && w[0].2 == w[1].2));
                }
            }

            #[test]
            fn ipv6_lookup_is_the_most_specific_prefix(raw in prefixes()) {
                let list = dedup(raw);
                // The last 4,096 addresses of the space: the top edge is where
                // "one past the end" does not exist.
                let base = u128::MAX - 4095;
                let pairs: Vec<(String, String)> = list.iter().map(|(start, bits, class)| (
                    format!("{}/{}", std::net::Ipv6Addr::from(base + u128::from(*start)), 116 + bits),
                    class.as_str().to_string(),
                )).collect();
                let o = Overrides::from_config(pairs.iter().map(|(c, l)| (c, l))).unwrap();
                for offset in 0..4096u32 {
                    let ip = IpAddr::V6(std::net::Ipv6Addr::from(base + u128::from(offset)));
                    prop_assert_eq!(o.lookup(ip), by_hand(&list, offset), "offset {}", offset);
                }
                prop_assert_eq!(o.lookup(IpAddr::V6(std::net::Ipv6Addr::from(base - 1))), None);
            }
        }
    }

    // ── Data age ──────────────────────────────────────────────────────
    #[test]
    fn days_from_civil_counts_from_the_epoch() {
        assert_eq!(days_from_civil("1970-01-01"), Some(0));
        assert_eq!(days_from_civil("1970-01-02"), Some(1));
        assert_eq!(days_from_civil("1969-12-31"), Some(-1));
        assert_eq!(days_from_civil("2000-03-01"), Some(11_017));
        assert_eq!(days_from_civil("2026-10-06"), Some(20_732));
        // Leap years: 2024 and 2000 have a 29 February, 2026 and 1900 do not.
        assert_eq!(
            days_from_civil("2024-03-01").unwrap() - days_from_civil("2024-02-28").unwrap(),
            2
        );
        assert_eq!(
            days_from_civil("2026-03-01").unwrap() - days_from_civil("2026-02-28").unwrap(),
            1
        );
        assert!(days_from_civil("2000-02-29").is_some());
        assert!(days_from_civil("1900-02-29").is_none());
        // A year is 365 or 366 days wherever it is taken.
        assert_eq!(
            days_from_civil("2027-01-01").unwrap() - days_from_civil("2026-01-01").unwrap(),
            365
        );
    }

    #[test]
    fn days_from_civil_refuses_what_is_not_a_date() {
        for bad in [
            "",
            "2026-10-6",
            "2026/10/06",
            "2026-13-01",
            "2026-00-10",
            "2026-04-31",
            "2026-02-30",
            "2026-10-00",
            "20261006",
            "2026-1O-06",
            "+026-10-06",
            "2026-10-06 ",
        ] {
            assert_eq!(days_from_civil(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn age_is_counted_in_whole_days() {
        let midnight = 20_732 * 86_400; // 2026-10-06T00:00:00Z
        assert_eq!(snapshot_epoch_secs("2026-10-06"), Some(midnight as i64));
        assert_eq!(age_days("2026-10-06", midnight), Some(0));
        assert_eq!(age_days("2026-10-06", midnight + 86_399), Some(0));
        assert_eq!(age_days("2026-10-06", midnight + 86_400), Some(1));
        assert_eq!(age_days("2026-10-06", midnight - 1), Some(-1));
        assert_eq!(age_days("not a date", midnight), None);
    }

    #[cfg(any(feature = "geo-ita", feature = "geo-eu"))]
    #[test]
    fn a_table_is_stale_past_forty_five_days_and_not_before() {
        let (region, date) = snapshots()[0];
        let day0 = (days_from_civil(date).unwrap() * 86_400) as u64;
        assert!(stale_tables(day0).is_empty());
        assert!(stale_tables(day0 + 45 * 86_400).is_empty());
        let stale = stale_tables(day0 + 46 * 86_400);
        assert_eq!(stale.len(), snapshots().len());
        assert_eq!(stale[0], (region, date, 46));
        // A clock set before the snapshot is not staleness.
        assert!(stale_tables(0).is_empty());
    }

    #[test]
    fn the_build_lists_the_tables_it_carries() {
        let regions: Vec<&str> = snapshots().iter().map(|s| s.0).collect();
        let mut want: Vec<&str> = Vec::new();
        if cfg!(feature = "geo-ita") {
            want.push("ita");
        }
        if cfg!(feature = "geo-eu") {
            want.push("eu");
        }
        assert_eq!(regions, want);
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        });
        assert!(!off.denies_score(1.0));

        let p = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            deny: vec![],
            mesh_score_deny_above: 0.9,
            ..Default::default()
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
            ..Default::default()
        });
        let unknown = p.unknown_deny_labels();
        assert!(unknown.contains(&"datacentre_eu"));
        assert!(!unknown.contains(&"unknown"));
    }

    #[test]
    fn tarpit_resolves_and_requires_enforcement_on() {
        // Tarpit on but enforcement off → not live (a tarpit with no deny to
        // escalate would never fire).
        let off = EnforcePolicy::from_config(&EnforceConfig {
            enabled: false,
            tarpit: TarpitConfig {
                enabled: true,
                hold_secs: 5,
                max_concurrent: 32,
            },
            ..Default::default()
        });
        assert!(!off.tarpit_enabled);

        // Both on → live, with resolved hold + ceiling.
        let on = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            deny: vec!["unknown".into()],
            tarpit: TarpitConfig {
                enabled: true,
                hold_secs: 7,
                max_concurrent: 64,
            },
            ..Default::default()
        });
        assert!(on.tarpit_enabled);
        assert_eq!(on.tarpit_hold, std::time::Duration::from_secs(7));
        assert_eq!(on.tarpit_max_concurrent, 64);

        // Default config → tarpit off.
        assert!(!EnforcePolicy::from_config(&EnforceConfig::default()).tarpit_enabled);
    }

    #[test]
    fn clamp_tarpit_concurrency_caps_at_quarter_of_pool() {
        let mut p = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            deny: vec!["unknown".into()],
            tarpit: TarpitConfig {
                enabled: true,
                hold_secs: 5,
                max_concurrent: 10_000,
            },
            ..Default::default()
        });
        // 10_000 > 40_000/4 = 10_000? No — must exceed. Pool 20_000 → cap 5_000.
        assert_eq!(p.clamp_tarpit_concurrency(20_000), Some((10_000, 5_000)));
        assert_eq!(p.tarpit_max_concurrent, 5_000);
        // Already within 1/4 → no clamp, no change.
        assert_eq!(p.clamp_tarpit_concurrency(20_000), None);
        assert_eq!(p.tarpit_max_concurrent, 5_000);

        // Tarpit disabled → never clamps.
        let mut off = EnforcePolicy::from_config(&EnforceConfig {
            enabled: true,
            tarpit: TarpitConfig {
                enabled: false,
                hold_secs: 5,
                max_concurrent: 10_000,
            },
            ..Default::default()
        });
        assert_eq!(off.clamp_tarpit_concurrency(4), None);
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
