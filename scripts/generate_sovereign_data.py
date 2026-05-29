#!/usr/bin/env python3
"""Generate sovereign CIDR data for Zion from RIPE NCC and IPtoASN sources.

Usage (Italy — ASN-role only):
    python3 generate_sovereign_data.py \
        --region ita \
        --ripe delegated-ripencc-latest \
        --iptoasn ip2asn-v4.tsv \
        --iptoasn6 ip2asn-v6.tsv \
        --output src/sovereign/data_ita.rs

Usage (EU — hybrid: country baseline + curated-ASN role override):
    python3 generate_sovereign_data.py \
        --region eu \
        --ripe delegated-ripencc-latest \
        --iptoasn ip2asn-v4.tsv \
        --iptoasn6 ip2asn-v6.tsv \
        --output src/sovereign/data_eu.rs

Produces two sorted, non-overlapping arrays — `RANGES` (IPv4, u32) and
`RANGES6` (IPv6, u128) — for binary search in the Zion classifier.

Region models:
  * ``ita`` — ASN-driven only. Emits ranges for the hand-curated Italian
    ASN sets below. RIPE allocations are not emitted; an IP is classified
    only if it sits in a known ASN.
  * ``eu``  — hybrid. Every allocation RIPE delegates to an EU-27 member
    state is emitted as the country-level baseline ``Eu``; ranges of a
    curated EU ASN override it with the more specific role. Answers
    "% EU vs non-EU traffic" with full coverage, role where we know it.
"""

import argparse
import ipaddress
import sys
from dataclasses import dataclass
from pathlib import Path

# ── Italian ASN classification ──────────────────────────────────
GOV_ASNS = {
    137, 2598, 20959,   # GARR (academic/research)
    5535, 41325,        # Lepida (Emilia-Romagna PA)
    2601,               # CINECA
    5473,               # CNR
    5501,               # INFN
    42911,              # Ministry of Defence
}
RESIDENTIAL_ASNS = {
    3269, 16232,        # TIM / Telecom Italia
    12874,              # Fastweb
    30722,              # Vodafone Italia
    1267, 6882,         # Wind Tre
    29447, 21479,       # Iliad Italia
    8612,               # Tiscali
    35612,              # Eolo
    210278,             # Sky Italia
    41336,              # PosteMobile
}
DATACENTER_ASNS = {
    12797, 31034, 202032, 60798,  # Aruba
    49367,              # Seeweb
    201333, 197075,     # Netsons
    47541,              # VHosting
    8968,               # BT Italia
    8928,               # MC-Link
    39120,              # Serverplan
    34758,              # FlameNetworks
    16276,              # OVH Italy
    24940,              # Hetzner (operates in IT)
}

# ── EU-27 member states (ISO-3166 alpha-2, RIPE `cc` field). ──────────
EU27 = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
    "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
    "RO", "SK", "SI", "ES", "SE",
}

# ── Curated EU ASN role overrides (hybrid model). Not exhaustive — the
# RIPE country baseline covers the rest as plain `Eu`. ────────────────
GOV_EU_ASNS = {
    20965, 21320,       # GÉANT
    680, 2200, 766, 1103, 137, 2598,  # DFN/RENATER/RedIRIS/SURF/GARR
    5400,               # EU institutions
}
RESIDENTIAL_EU_ASNS = {
    3320,               # Deutsche Telekom (DE)
    3209,               # Vodafone group
    3215,               # Orange (FR)
    12322,              # Free/Iliad (FR)
    3352,               # Telefonica (ES)
    1136,               # KPN (NL)
    5432,               # Proximus (BE)
    3269,               # TIM (IT)
    5617,               # Orange Polska (PL)
    8447,               # Telekom Austria (AT)
}
DATACENTER_EU_ASNS = {
    16276,              # OVH (FR)
    24940, 213230,      # Hetzner (DE)
    12876,              # Scaleway/Online (FR)
    8560,               # IONOS (DE)
    12797,              # Aruba (IT)
    60781, 16265,       # LeaseWeb (NL)
    51167,              # Contabo (DE)
}

REGIONS = {
    "ita": {
        "module": "data_ita",
        "adjective": "Italian",
        "countries": {"IT"},
        "baseline_class": None,
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
        "baseline_class": "Eu",
        "asn_roles": [
            (GOV_EU_ASNS, "GovEu"),
            (RESIDENTIAL_EU_ASNS, "ResidentialEu"),
            (DATACENTER_EU_ASNS, "DatacenterEu"),
        ],
    },
}

BASELINE_PRIORITY = 0
ROLE_PRIORITY = 1


@dataclass
class Range:
    start: int
    end: int
    ip_class: str
    priority: int = ROLE_PRIORITY


def parse_ripe_delegated(path: Path, countries: set[str]) -> dict[str, list[Range]]:
    """Parse RIPE NCC delegated stats; return {'v4': [...], 'v6': [...]}.

    IPv4 records carry a host *count*; IPv6 records carry a *prefix length*.
    """
    out = {"v4": [], "v6": []}
    with open(path) as f:
        for line in f:
            if line.startswith('#') or line.startswith('ripencc|*'):
                continue
            parts = line.strip().split('|')
            if len(parts) < 7:
                continue
            cc, rec_type, start_ip, value = parts[1], parts[2], parts[3], parts[4]
            if cc not in countries:
                continue
            try:
                if rec_type == 'ipv4':
                    start = int(ipaddress.IPv4Address(start_ip))
                    end = start + int(value) - 1
                    out["v4"].append(Range(start, end, 'Unknown'))
                elif rec_type == 'ipv6':
                    net = ipaddress.IPv6Network(f"{start_ip}/{value}", strict=False)
                    out["v6"].append(Range(int(net.network_address),
                                           int(net.broadcast_address), 'Unknown'))
            except (ValueError, ipaddress.AddressValueError):
                continue
    return out


def parse_iptoasn(path: Path, family: str) -> dict[int, list[Range]]:
    """Parse IPtoASN TSV (start, end, ASN, cc, desc) for the given family."""
    addr = ipaddress.IPv4Address if family == "v4" else ipaddress.IPv6Address
    asn_ranges: dict[int, list[Range]] = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 5:
                continue
            try:
                start = int(addr(parts[0]))
                end = int(addr(parts[1]))
                asn = int(parts[2])
                if asn == 0:
                    continue
                asn_ranges.setdefault(asn, []).append(Range(start, end, 'Unknown'))
            except (ValueError, ipaddress.AddressValueError):
                continue
    return asn_ranges


def merge_same_class(ranges: list[Range]) -> list[Range]:
    """Merge overlapping/adjacent ranges that share a class."""
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


def resolve_priority(ranges: list[Range]) -> list[Range]:
    """Flatten possibly-overlapping ranges into a sorted, non-overlapping set
    where each address takes the class of the highest-priority covering range
    (role > baseline). Sweep elementary segments between every boundary."""
    if not ranges:
        return []
    bounds = set()
    for r in ranges:
        bounds.add(r.start)
        bounds.add(r.end + 1)
    points = sorted(bounds)
    ranges_sorted = sorted(ranges, key=lambda r: r.start)
    out: list[Range] = []
    active: list[Range] = []
    ri = 0
    n = len(ranges_sorted)
    for i in range(len(points) - 1):
        seg_start = points[i]
        seg_end = points[i + 1] - 1
        while ri < n and ranges_sorted[ri].start <= seg_start:
            active.append(ranges_sorted[ri])
            ri += 1
        active = [r for r in active if r.end >= seg_start]
        if not active:
            continue
        best = max(active, key=lambda r: r.priority)
        if out and out[-1].ip_class == best.ip_class and out[-1].end + 1 == seg_start:
            out[-1].end = seg_end
        else:
            out.append(Range(seg_start, seg_end, best.ip_class, best.priority))
    return out


def build_family(role_by_asn: dict[int, list[Range]], asn_to_class: dict[int, str],
                 baseline: list[Range], baseline_class: str | None) -> list[Range]:
    """Combine curated-ASN role ranges (priority) with the optional country
    baseline into a sorted, non-overlapping set for one address family."""
    ranges: list[Range] = []
    for asn, rs in role_by_asn.items():
        cls = asn_to_class.get(asn)
        if cls:
            for r in rs:
                ranges.append(Range(r.start, r.end, cls, ROLE_PRIORITY))
    if baseline_class is not None:
        for r in baseline:
            ranges.append(Range(r.start, r.end, baseline_class, BASELINE_PRIORITY))
    resolved = resolve_priority(ranges)
    resolved = merge_same_class(resolved)
    resolved.sort(key=lambda r: r.start)
    return resolved


CLASS_LABEL = {
    'GovIta': 'GOVERNMENT / INSTITUTIONAL',
    'ResidentialIta': 'RESIDENTIAL ISPs',
    'DatacenterIta': 'DATACENTER / HOSTING',
    'Eu': 'EU-27 BASELINE (country-level)',
    'GovEu': 'EU GOVERNMENT / RESEARCH',
    'ResidentialEu': 'EU RESIDENTIAL ISPs',
    'DatacenterEu': 'EU DATACENTER / CLOUD',
}


def emit_array(ranges: list[Range], name: str, ty: str, ctor: str, width: int) -> list[str]:
    """Emit one `pub static <name>: &[<ty>]` array via the `<ctor>()` helper.

    Function-call form (not struct literals): rustfmt keeps a call on one
    line, where a struct literal wider than `struct_lit_width` would be
    exploded onto four — fatal for a 25k-entry table.
    """
    lines = [
        f'/// Sorted by start IP (ascending), non-overlapping.',
        # rustfmt would explode each `cr(...)`/`cr6(...)` call onto multiple
        # lines once its args exceed `fn_call_width` (the u128 v6 literals
        # do) — turning a ~40k-entry table into ~160k lines. Skip it.
        f'#[rustfmt::skip]',
        f'pub static {name}: &[{ty}] = &[',
    ]
    current = None
    for r in ranges:
        if r.ip_class != current:
            current = r.ip_class
            lines.append(f'    // ── {CLASS_LABEL.get(current, current)} ──')
        lines.append(f'    {ctor}(0x{r.start:0{width}X}, 0x{r.end:0{width}X}, IpClass::{r.ip_class}),')
    lines.append('];')
    return lines


def generate_rust(v4: list[Range], v6: list[Range], region: dict) -> str:
    adjective = region["adjective"]
    lines = [
        f'//! Baked-in {adjective} CIDR ranges for sovereign edge classification.',
        '//!',
        '//! AUTO-GENERATED by scripts/generate_sovereign_data.py',
        '//! DO NOT EDIT MANUALLY — changes will be overwritten by CI.',
        '//!',
        '//! Sources: RIPE NCC delegated stats + IPtoASN (Team Cymru), v4 + v6.',
        '',
        'use super::{CidrEntry, CidrEntry6, IpClass};',
        '',
    ]
    lines += emit_array(v4, "RANGES", "CidrEntry", "cr", 8)
    lines.append('')
    lines += emit_array(v6, "RANGES6", "CidrEntry6", "cr6", 32)
    lines += [
        '',
        '/// Const constructor — raw inclusive host-order u32 bounds.',
        'const fn cr(start: u32, end: u32, class: IpClass) -> CidrEntry {',
        '    CidrEntry { start, end, class }',
        '}',
        '',
        '/// Const constructor — raw inclusive host-order u128 bounds.',
        'const fn cr6(start: u128, end: u128, class: IpClass) -> CidrEntry6 {',
        '    CidrEntry6 { start, end, class }',
        '}',
        '',
        '#[cfg(test)]',
        'mod tests {',
        '    use super::*;',
        '',
        '    #[test]',
        '    fn ranges_are_sorted() {',
        '        for w in RANGES.windows(2) {',
        '            assert!(w[0].start < w[1].start, "RANGES not sorted");',
        '        }',
        '        for w in RANGES6.windows(2) {',
        '            assert!(w[0].start < w[1].start, "RANGES6 not sorted");',
        '        }',
        '    }',
        '',
        '    #[test]',
        '    fn ranges_dont_overlap() {',
        '        for w in RANGES.windows(2) {',
        '            assert!(w[0].end < w[1].start, "RANGES overlap");',
        '        }',
        '        for w in RANGES6.windows(2) {',
        '            assert!(w[0].end < w[1].start, "RANGES6 overlap");',
        '        }',
        '    }',
        '}',
        '',
    ]
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Generate sovereign CIDR data for Zion')
    parser.add_argument('--region', default='ita', choices=sorted(REGIONS))
    parser.add_argument('--ripe', required=True, help='Path to delegated-ripencc-latest')
    parser.add_argument('--iptoasn', required=True, help='Path to ip2asn-v4.tsv')
    parser.add_argument('--iptoasn6', required=True, help='Path to ip2asn-v6.tsv')
    parser.add_argument('--output', required=True, help='Output .rs file path')
    args = parser.parse_args()

    region = REGIONS[args.region]
    asn_to_class = {asn: cls for asns, cls in region["asn_roles"] for asn in asns}
    print(f'Region: {args.region} ({region["adjective"]})')

    ripe = parse_ripe_delegated(Path(args.ripe), region["countries"])
    print(f'  RIPE: {len(ripe["v4"])} v4 + {len(ripe["v6"])} v6 allocations')

    role_v4 = parse_iptoasn(Path(args.iptoasn), "v4")
    role_v6 = parse_iptoasn(Path(args.iptoasn6), "v6")
    print(f'  IPtoASN: {len(role_v4)} v4 ASNs + {len(role_v6)} v6 ASNs loaded; '
          f'{len(asn_to_class)} curated')

    v4 = build_family(role_v4, asn_to_class, ripe["v4"], region["baseline_class"])
    v6 = build_family(role_v6, asn_to_class, ripe["v6"], region["baseline_class"])
    print(f'  Final: {len(v4)} v4 + {len(v6)} v6 non-overlapping ranges')

    if not v4 and not v6:
        print('ERROR: no ranges produced', file=sys.stderr)
        sys.exit(1)

    Path(args.output).write_text(generate_rust(v4, v6, region))
    print(f'  Written to {args.output}')


if __name__ == '__main__':
    main()
