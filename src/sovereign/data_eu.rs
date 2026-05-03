//! Baked-in EU CIDR ranges for sovereign edge classification.
//!
//! This is a stub for Phase 2. The full EU dataset will be generated
//! by the CI pipeline from RIPE NCC RIS dumps, covering all EU28+
//! member state ASNs.
//!
//! Layout: same as data_ita.rs — sorted CidrEntry array.

use super::{CidrEntry, IpClass, cidr_range};

/// EU CIDR ranges — sorted by start IP (ascending).
/// Phase 2: will be populated by CI from RIPE NCC data.
pub static RANGES: &[CidrEntry] = &[
    // ═══════════════════════════════════════════════════════════════
    // EU INSTITUTIONAL (seed — Phase 2 will expand)
    // ═══════════════════════════════════════════════════════════════

    // European Commission / EU Council (Brussels)
    cr(147, 67, 0, 0, 16, IpClass::GovEu),        // 147.67.0.0/16 — EU institutions
    cr(158, 167, 0, 0, 16, IpClass::GovEu),       // 158.167.0.0/16 — European Commission
    cr(158, 169, 0, 0, 16, IpClass::GovEu),       // 158.169.0.0/16 — EU Parliament

    // GÉANT (European Research Network)
    cr(62, 40, 96, 0, 19, IpClass::GovEu),        // 62.40.96.0/19 — GÉANT backbone
];

/// Const constructor for CidrEntry.
const fn cr(a: u8, b: u8, c: u8, d: u8, prefix_len: u8, class: IpClass) -> CidrEntry {
    let (start, end) = cidr_range(a, b, c, d, prefix_len);
    CidrEntry { start, end, class }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_sorted() {
        for window in RANGES.windows(2) {
            assert!(
                window[0].start < window[1].start,
                "EU RANGES not sorted: 0x{:08X} >= 0x{:08X}",
                window[0].start,
                window[1].start
            );
        }
    }

    #[test]
    fn classify_eu_commission() {
        let ip: std::net::IpAddr = "158.167.1.1".parse().unwrap();
        assert_eq!(
            super::super::classify(ip),
            IpClass::GovEu,
            "158.167.1.1 should be gov_eu (European Commission)"
        );
    }
}
