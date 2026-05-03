#!/usr/bin/env python3
"""Generate sovereign CIDR data for Zion from RIPE NCC and IPtoASN sources.

Usage:
    python3 generate_sovereign_data.py \
        --country IT \
        --ripe delegated-ripencc-latest \
        --iptoasn ip2asn-v4.tsv \
        --output src/sovereign/data_ita.rs

Produces a sorted, non-overlapping array of CidrEntry structs for
binary search in the Zion sovereign edge classifier.
"""

import argparse
import ipaddress
import sys
from dataclasses import dataclass
from pathlib import Path

# ── Italian ASN classification ──────────────────────────────────
# Maintained manually — PR changes are reviewed by humans.
# Source: PeeringDB, RIPE NCC, public whois data.

GOV_ASNS = {
    # GARR — Italian academic/research network
    137, 2598, 20959,
    # Lepida — Emilia-Romagna PA
    5535, 41325,
    # CINECA — supercomputing consortium
    2601,
    # CNR — Consiglio Nazionale delle Ricerche
    5473,
    # INFN — Istituto Nazionale Fisica Nucleare
    5501,
    # Italian Ministry of Defence
    42911,
}

RESIDENTIAL_ASNS = {
    # TIM / Telecom Italia
    3269, 16232,
    # Fastweb
    12874,
    # Vodafone Italia
    30722,
    # Wind Tre
    1267, 6882,
    # Iliad Italia
    29447, 21479,
    # Tiscali
    8612,
    # Eolo (fixed wireless)
    35612,
    # Sky Italia (broadband)
    210278,
    # PosteMobile
    41336,
}

DATACENTER_ASNS = {
    # Aruba
    12797, 31034, 202032, 60798,
    # Seeweb
    49367,
    # Netsons
    201333, 197075,
    # VHosting
    47541,
    # BT Italia
    8968,
    # MC-Link
    8928,
    # Serverplan
    39120,
    # FlameNetworks
    34758,
    # OVH Italy
    16276,
    # Hetzner (operates in IT)
    24940,
}


@dataclass
class CidrRange:
    start: int
    end: int
    ip_class: str

    @property
    def prefix(self) -> str:
        """Best-effort CIDR notation for the comment."""
        try:
            nets = list(ipaddress.summarize_address_range(
                ipaddress.IPv4Address(self.start),
                ipaddress.IPv4Address(self.end),
            ))
            return str(nets[0]) if len(nets) == 1 else f"{nets[0]}..{nets[-1]}"
        except Exception:
            return f"{ipaddress.IPv4Address(self.start)}-{ipaddress.IPv4Address(self.end)}"


def parse_ripe_delegated(path: Path, country: str) -> list[CidrRange]:
    """Parse RIPE NCC delegated stats for a country's IPv4 allocations."""
    ranges = []
    with open(path) as f:
        for line in f:
            if line.startswith('#') or line.startswith('ripencc|*'):
                continue
            parts = line.strip().split('|')
            if len(parts) < 7:
                continue
            registry, cc, rec_type, start_ip, count_str = parts[0], parts[1], parts[2], parts[3], parts[4]
            if cc != country or rec_type != 'ipv4':
                continue
            try:
                count = int(count_str)
                start = int(ipaddress.IPv4Address(start_ip))
                end = start + count - 1
                ranges.append(CidrRange(start, end, 'Unknown'))
            except (ValueError, ipaddress.AddressValueError):
                continue
    return ranges


def parse_iptoasn(path: Path) -> dict[int, list[CidrRange]]:
    """Parse IPtoASN TSV: start\tend\tASN\tcountry\tdescription."""
    asn_ranges: dict[int, list[CidrRange]] = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 5:
                continue
            try:
                start = int(ipaddress.IPv4Address(parts[0]))
                end = int(ipaddress.IPv4Address(parts[1]))
                asn = int(parts[2])
                if asn == 0:
                    continue
                asn_ranges.setdefault(asn, []).append(CidrRange(start, end, 'Unknown'))
            except (ValueError, ipaddress.AddressValueError):
                continue
    return asn_ranges


def classify_asn(asn: int) -> str | None:
    """Classify an ASN into an IpClass variant name."""
    if asn in GOV_ASNS:
        return 'GovIta'
    if asn in RESIDENTIAL_ASNS:
        return 'ResidentialIta'
    if asn in DATACENTER_ASNS:
        return 'DatacenterIta'
    return None


def merge_ranges(ranges: list[CidrRange]) -> list[CidrRange]:
    """Merge overlapping/adjacent ranges with the same class."""
    if not ranges:
        return []
    ranges.sort(key=lambda r: (r.start, r.end))
    merged = [ranges[0]]
    for r in ranges[1:]:
        last = merged[-1]
        if r.start <= last.end + 1 and r.ip_class == last.ip_class:
            last.end = max(last.end, r.end)
        else:
            merged.append(r)
    return merged


def remove_overlaps(ranges: list[CidrRange]) -> list[CidrRange]:
    """Remove overlapping ranges, keeping the more specific (smaller) one."""
    ranges.sort(key=lambda r: (r.start, -(r.end - r.start)))
    result = []
    for r in ranges:
        if result and r.start <= result[-1].end:
            # Overlap — skip the broader range
            if r.end - r.start < result[-1].end - result[-1].start:
                result[-1] = r  # Keep smaller
            continue
        result.append(r)
    return result


def ip_to_dotted(ip: int) -> tuple[int, int, int, int]:
    """Convert u32 to (a, b, c, d)."""
    return (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF


def guess_prefix_len(start: int, end: int) -> int:
    """Guess the CIDR prefix length from a start/end range."""
    size = end - start + 1
    if size & (size - 1) != 0:
        return 0  # Not a power of 2
    import math
    return 32 - int(math.log2(size))


def generate_rust(ranges: list[CidrRange], module_name: str) -> str:
    """Generate the Rust source for the data module."""
    lines = [
        f'//! Baked-in Italian CIDR ranges for sovereign edge classification.',
        f'//!',
        f'//! AUTO-GENERATED by scripts/generate_sovereign_data.py',
        f'//! DO NOT EDIT MANUALLY — changes will be overwritten by CI.',
        f'//!',
        f'//! Sources: RIPE NCC delegated stats + IPtoASN (Team Cymru)',
        f'',
        f'use super::{{CidrEntry, IpClass, cidr_range}};',
        f'',
        f'/// Italian CIDR ranges — sorted by start IP (ascending).',
        f'pub static RANGES: &[CidrEntry] = &[',
    ]

    current_class = None
    for r in ranges:
        if r.ip_class != current_class:
            current_class = r.ip_class
            class_label = {
                'GovIta': 'GOVERNMENT / INSTITUTIONAL',
                'ResidentialIta': 'RESIDENTIAL ISPs',
                'DatacenterIta': 'DATACENTER / HOSTING',
            }.get(current_class, current_class)
            lines.append(f'    // ── {class_label} ──')

        a, b, c, d = ip_to_dotted(r.start)
        prefix = guess_prefix_len(r.start, r.end)
        comment = r.prefix
        lines.append(
            f'    cr({a}, {b}, {c}, {d}, {prefix}, IpClass::{r.ip_class}),'
            f'  // {comment}'
        )

    lines.extend([
        '];',
        '',
        '/// Const constructor for CidrEntry.',
        'const fn cr(a: u8, b: u8, c: u8, d: u8, prefix_len: u8, class: IpClass) -> CidrEntry {',
        '    let (start, end) = cidr_range(a, b, c, d, prefix_len);',
        '    CidrEntry { start, end, class }',
        '}',
        '',
        '#[cfg(test)]',
        'mod tests {',
        '    use super::*;',
        '',
        '    #[test]',
        '    fn ranges_are_sorted() {',
        '        for window in RANGES.windows(2) {',
        '            assert!(',
        '                window[0].start < window[1].start,',
        '                "RANGES not sorted: 0x{:08X} >= 0x{:08X}",',
        '                window[0].start,',
        '                window[1].start',
        '            );',
        '        }',
        '    }',
        '',
        '    #[test]',
        '    fn ranges_dont_overlap() {',
        '        for window in RANGES.windows(2) {',
        '            assert!(',
        '                window[0].end < window[1].start,',
        '                "RANGES overlap: [0x{:08X}..0x{:08X}] and [0x{:08X}..0x{:08X}]",',
        '                window[0].start,',
        '                window[0].end,',
        '                window[1].start,',
        '                window[1].end',
        '            );',
        '        }',
        '    }',
        '}',
        '',
    ])

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Generate sovereign CIDR data for Zion')
    parser.add_argument('--country', default='IT', help='Country code (default: IT)')
    parser.add_argument('--ripe', required=True, help='Path to delegated-ripencc-latest')
    parser.add_argument('--iptoasn', required=True, help='Path to ip2asn-v4.tsv')
    parser.add_argument('--output', required=True, help='Output .rs file path')
    parser.add_argument('--module-name', default='data_ita', help='Rust module name')
    args = parser.parse_args()

    print(f'Parsing RIPE delegated stats for {args.country}...')
    ripe_ranges = parse_ripe_delegated(Path(args.ripe), args.country)
    print(f'  Found {len(ripe_ranges)} IPv4 allocations for {args.country}')

    print(f'Parsing IPtoASN...')
    asn_ranges = parse_iptoasn(Path(args.iptoasn))
    print(f'  Loaded {len(asn_ranges)} ASNs')

    # Classify known ASNs
    classified = []
    for asn, ranges in asn_ranges.items():
        ip_class = classify_asn(asn)
        if ip_class:
            for r in ranges:
                r.ip_class = ip_class
                classified.append(r)

    print(f'  Classified {len(classified)} ranges across {len(GOV_ASNS | RESIDENTIAL_ASNS | DATACENTER_ASNS)} ASNs')

    # Sort, merge, dedup
    classified = merge_ranges(classified)
    classified = remove_overlaps(classified)
    classified.sort(key=lambda r: r.start)

    print(f'  Final: {len(classified)} non-overlapping ranges')

    # Generate Rust
    rust_code = generate_rust(classified, args.module_name)
    Path(args.output).write_text(rust_code)
    print(f'  Written to {args.output}')


if __name__ == '__main__':
    main()
