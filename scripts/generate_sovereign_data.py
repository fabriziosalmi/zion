#!/usr/bin/env python3
"""Generate sovereign CIDR data for Zion from RIPE NCC and IPtoASN sources.

Usage (Italy — ASN-role only, unchanged):
    python3 generate_sovereign_data.py \
        --region ita \
        --ripe delegated-ripencc-latest \
        --iptoasn ip2asn-v4.tsv \
        --output src/sovereign/data_ita.rs

Usage (EU — hybrid: country baseline + curated-ASN role override):
    python3 generate_sovereign_data.py \
        --region eu \
        --ripe delegated-ripencc-latest \
        --iptoasn ip2asn-v4.tsv \
        --output src/sovereign/data_eu.rs

Produces a sorted, non-overlapping array of CidrEntry structs for
binary search in the Zion sovereign edge classifier.

Region models:
  * ``ita`` — ASN-driven only. Emits ranges for the hand-curated Italian
    ASN sets below (gov / residential / datacenter). RIPE allocations are
    not emitted; an IP is classified only if it sits in a known ASN.
  * ``eu``  — hybrid. Every IPv4 allocation RIPE delegates to an EU-27
    member state is emitted as the country-level baseline ``Eu``; ranges
    belonging to a curated EU ASN override it with the more specific
    ``GovEu`` / ``ResidentialEu`` / ``DatacenterEu`` role. This answers
    "% EU vs non-EU traffic" with full coverage while still surfacing the
    role where we know it.
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

# ── EU-27 member states (ISO-3166 alpha-2, as used in RIPE delegated
# stats `cc` field). RIPE NCC also delegates to non-EU European/ME/CA
# countries, so we filter to exactly the 27 member states. ───────────
EU27 = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
    "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
    "RO", "SK", "SI", "ES", "SE",
}

# ── Curated EU ASN role overrides (hybrid model). Not exhaustive — the
# RIPE country baseline covers everything else as plain `Eu`; these only
# add role where it's well-known. Reviewed by humans on PR. ───────────
GOV_EU_ASNS = {
    # GÉANT — pan-European research backbone
    20965, 21320,
    # DFN (Germany), RENATER (France), RedIRIS (Spain), SURF (NL),
    # GARR (Italy), national research/education networks
    680, 2200, 766, 1103, 137, 2598,
    # European Commission / EU institutions
    5400,
}

RESIDENTIAL_EU_ASNS = {
    # Deutsche Telekom (DE)
    3320,
    # Vodafone group (DE/multiple)
    3209,
    # Orange (FR)
    3215,
    # Free/Iliad (FR)
    12322,
    # Telefonica / Movistar (ES)
    3352,
    # KPN (NL)
    1136,
    # Proximus (BE)
    5432,
    # TIM (IT)
    3269,
    # Orange Polska (PL)
    5617,
    # Telekom Austria (AT)
    8447,
}

DATACENTER_EU_ASNS = {
    # OVH (FR)
    16276,
    # Hetzner (DE)
    24940, 213230,
    # Scaleway / Online SAS (FR)
    12876,
    # IONOS / 1&1 (DE)
    8560,
    # Aruba (IT)
    12797,
    # LeaseWeb (NL)
    60781, 16265,
    # Contabo (DE)
    51167,
}

# ── Region configuration table ───────────────────────────────────────
REGIONS = {
    "ita": {
        "module": "data_ita",
        "adjective": "Italian",
        "countries": {"IT"},
        "baseline_class": None,  # ASN-only, no country baseline
        "asn_roles": [
            (GOV_ASNS, "GovIta"),
            (RESIDENTIAL_ASNS, "ResidentialIta"),
            (DATACENTER_ASNS, "DatacenterIta"),
        ],
    },
    "eu": {
        "module": "data_eu",
        "adjective": "EU-27",
        "countries": EU27,
        "baseline_class": "Eu",  # every EU-27 allocation → Eu baseline
        "asn_roles": [
            (GOV_EU_ASNS, "GovEu"),
            (RESIDENTIAL_EU_ASNS, "ResidentialEu"),
            (DATACENTER_EU_ASNS, "DatacenterEu"),
        ],
    },
}

# Role classes win over the country baseline; lower number = lower
# priority. Baseline gets 0, every role gets 1 (roles never overlap each
# other — an ASN maps to a single role set).
BASELINE_PRIORITY = 0
ROLE_PRIORITY = 1


@dataclass
class CidrRange:
    start: int
    end: int
    ip_class: str
    priority: int = ROLE_PRIORITY

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


def parse_ripe_delegated(path: Path, countries: set[str]) -> list[CidrRange]:
    """Parse RIPE NCC delegated stats for the given countries' IPv4 allocations."""
    ranges = []
    with open(path) as f:
        for line in f:
            if line.startswith('#') or line.startswith('ripencc|*'):
                continue
            parts = line.strip().split('|')
            if len(parts) < 7:
                continue
            cc, rec_type, start_ip, count_str = parts[1], parts[2], parts[3], parts[4]
            if cc not in countries or rec_type != 'ipv4':
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


def merge_same_class(ranges: list[CidrRange]) -> list[CidrRange]:
    """Merge overlapping/adjacent ranges that share a class (and priority)."""
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


def resolve_priority(ranges: list[CidrRange]) -> list[CidrRange]:
    """Flatten possibly-overlapping ranges into a sorted, non-overlapping set
    where each address takes the class of the highest-priority range that
    covers it (role > baseline). Ties keep the first seen.

    Sweep over elementary segments between every boundary; for each segment
    pick the max-priority covering range, then coalesce adjacent equal-class
    segments.
    """
    if not ranges:
        return []
    # Boundary points: each range contributes `start` and `end+1`.
    bounds = set()
    for r in ranges:
        bounds.add(r.start)
        bounds.add(r.end + 1)
    points = sorted(bounds)

    # Index ranges by start for a forward sweep.
    ranges_sorted = sorted(ranges, key=lambda r: r.start)
    out: list[CidrRange] = []
    active: list[CidrRange] = []
    ri = 0
    n = len(ranges_sorted)
    for i in range(len(points) - 1):
        seg_start = points[i]
        seg_end = points[i + 1] - 1  # inclusive
        # Add ranges that start at/before this segment.
        while ri < n and ranges_sorted[ri].start <= seg_start:
            active.append(ranges_sorted[ri])
            ri += 1
        # Drop ranges that ended before this segment.
        active = [r for r in active if r.end >= seg_start]
        if not active:
            continue
        # Highest priority wins; ties → keep the earliest-added (stable).
        best = max(active, key=lambda r: r.priority)
        if out and out[-1].ip_class == best.ip_class and out[-1].end + 1 == seg_start:
            out[-1].end = seg_end
        else:
            out.append(CidrRange(seg_start, seg_end, best.ip_class, best.priority))
    return out


def generate_rust(ranges: list[CidrRange], region: dict) -> str:
    """Generate the Rust source for the data module.

    Emits explicit `CidrEntry { start, end, class }` literals (host-order
    u32) rather than a dotted-quad + prefix helper, so arbitrary ranges —
    including non-CIDR-aligned remainders left by priority resolution —
    are represented exactly in a single entry. Adjacent same-class ranges
    are coalesced upstream, keeping the table small.
    """
    adjective = region["adjective"]
    lines = [
        f'//! Baked-in {adjective} CIDR ranges for sovereign edge classification.',
        f'//!',
        f'//! AUTO-GENERATED by scripts/generate_sovereign_data.py',
        f'//! DO NOT EDIT MANUALLY — changes will be overwritten by CI.',
        f'//!',
        f'//! Sources: RIPE NCC delegated stats + IPtoASN (Team Cymru)',
        f'',
        f'use super::{{CidrEntry, IpClass}};',
        f'',
        f'/// {adjective} CIDR ranges — sorted by start IP (ascending),',
        f'/// non-overlapping. `start`/`end` are inclusive host-order u32.',
        f'pub static RANGES: &[CidrEntry] = &[',
    ]

    class_label = {
        'GovIta': 'GOVERNMENT / INSTITUTIONAL',
        'ResidentialIta': 'RESIDENTIAL ISPs',
        'DatacenterIta': 'DATACENTER / HOSTING',
        'Eu': 'EU-27 BASELINE (country-level)',
        'GovEu': 'EU GOVERNMENT / RESEARCH',
        'ResidentialEu': 'EU RESIDENTIAL ISPs',
        'DatacenterEu': 'EU DATACENTER / CLOUD',
    }

    current_class = None
    for r in ranges:
        if r.ip_class != current_class:
            current_class = r.ip_class
            label = class_label.get(current_class, current_class)
            lines.append(f'    // ── {label} ──')
        lines.append(
            f'    CidrEntry {{ start: 0x{r.start:08X}, end: 0x{r.end:08X}, '
            f'class: IpClass::{r.ip_class} }},'
        )

    lines.extend([
        '];',
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
    parser.add_argument('--region', default='ita', choices=sorted(REGIONS),
                        help='Region model: ita (ASN-only) or eu (country baseline + ASN roles)')
    parser.add_argument('--ripe', required=True, help='Path to delegated-ripencc-latest')
    parser.add_argument('--iptoasn', required=True, help='Path to ip2asn-v4.tsv')
    parser.add_argument('--output', required=True, help='Output .rs file path')
    args = parser.parse_args()

    region = REGIONS[args.region]
    asn_to_class = {asn: cls for asns, cls in region["asn_roles"] for asn in asns}

    print(f'Region: {args.region} ({region["adjective"]})')

    # ── ASN-role ranges (priority over baseline) ──
    print('Parsing IPtoASN...')
    asn_ranges = parse_iptoasn(Path(args.iptoasn))
    print(f'  Loaded {len(asn_ranges)} ASNs')
    role_ranges: list[CidrRange] = []
    for asn, ranges in asn_ranges.items():
        cls = asn_to_class.get(asn)
        if cls:
            for r in ranges:
                r.ip_class = cls
                r.priority = ROLE_PRIORITY
                role_ranges.append(r)
    print(f'  Classified {len(role_ranges)} ranges across {len(asn_to_class)} curated ASNs')

    all_ranges = list(role_ranges)

    # ── Country baseline (EU only) ──
    if region["baseline_class"] is not None:
        print(f'Parsing RIPE delegated stats for {len(region["countries"])} countries...')
        base = parse_ripe_delegated(Path(args.ripe), region["countries"])
        for r in base:
            r.ip_class = region["baseline_class"]
            r.priority = BASELINE_PRIORITY
        print(f'  Found {len(base)} IPv4 allocations')
        all_ranges.extend(base)

    if not all_ranges:
        print('ERROR: no ranges produced', file=sys.stderr)
        sys.exit(1)

    # ── Resolve priority into a non-overlapping set, coalesce, sort ──
    resolved = resolve_priority(all_ranges)
    resolved = merge_same_class(resolved)
    resolved.sort(key=lambda r: r.start)
    print(f'  Final: {len(resolved)} non-overlapping ranges')

    rust_code = generate_rust(resolved, region)
    Path(args.output).write_text(rust_code)
    print(f'  Written to {args.output}')


if __name__ == '__main__':
    main()
