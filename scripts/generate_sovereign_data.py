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

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
import unicodedata
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ── Italian ASN classification ──────────────────────────────────
#
# Each ASN maps to its EXPECTED holder — a distinctive token of the org that
# curated this ASN into the role. This is DATA, not a comment: the generator
# verifies it against the live RIPEstat holder (validate_holders below) and
# fails closed on a mismatch, so an ASN silently reassigned by RIPE to a new
# (even foreign) holder can no longer be re-labelled with an Italian role.
# Verified against RIPEstat as-overview 2026-08-31 — every entry below matches
# its live holder; drifted ASNs (reassigned away from the curated org) were
# REMOVED, and legitimate Italian reassignments carry the new holder's name.
GOV_ASNS = {
    137: "GARR",                 # ASGARR Consortium GARR (research)
    2598: "CNR",                 # Consiglio Nazionale delle Ricerche
    41325: "Regione Marche",     # regional PA
}
RESIDENTIAL_ASNS = {
    3269: "Telecom Italia",      # TIM
    16232: "Telecom Italia",     # TIM
    12874: "Fastweb",
    30722: "Vodafone",           # Vodafone Italia (now Fastweb-owned; AS-name retains VODAFONE)
    1267: "Wind Tre",
    8612: "Tiscali",
    35612: "Eolo",               # NGI / EOLO
    210278: "Sky Italia",
}
DATACENTER_ASNS = {
    31034: "Aruba",
    12797: "Retelit",            # ex-Aruba/Atlanet, now Retelit (IT carrier)
    60798: "Servereasy",         # ex-Aruba, now Servereasy (IT hosting)
    49367: "Seflow",             # curated "Seeweb" was the wrong ASN; AS49367 is Seflow (IT)
    201333: "Naquadria",         # ex-Netsons, now Naquadria (IT hosting)
    197075: "Active Network",    # ex-Netsons, now Active Network (IT)
    8968: "Retelit",             # ex-BT Italia, now Retelit
    39120: "Convergenze",        # ex-Serverplan, now Convergenze (IT operator)
    34758: "Axera",              # ex-FlameNetworks, now Axera (IT)
    16276: "OVH",                # OVH (FR) — curated as operating in IT
    24940: "Hetzner",            # Hetzner (DE) — curated as operating in IT
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
    20965: "GEANT", 21320: "GEANT",
    680: "DFN",                  # Deutsches Forschungsnetz (DE)
    2200: "Renater",             # RENATER (FR)
    766: "RedIRIS",              # Red.es (ES)
    1103: "SURF",                # SURF (NL)
    137: "GARR", 2598: "CNR",    # IT research
}
RESIDENTIAL_EU_ASNS = {
    3320: "Deutsche Telekom",    # DE
    3209: "Vodafone",            # DE (Vodafone GmbH)
    3215: "Orange",              # FR
    12322: "Free Proxad",        # Free/Iliad (FR)
    3352: "Telefonica",          # ES
    1136: "KPN",                 # NL
    5432: "Proximus",            # BE
    3269: "Telecom Italia",      # IT
    5617: "Orange Polska",       # PL
    8447: "A1 Telekom Austria",  # AT
}
DATACENTER_EU_ASNS = {
    16276: "OVH",                # FR
    24940: "Hetzner", 213230: "Hetzner",  # DE
    12876: "Scaleway",           # FR
    8560: "IONOS",               # DE
    12797: "Retelit",            # ex-Aruba, now Retelit (IT)
    60781: "LeaseWeb", 16265: "LeaseWeb",  # NL
    51167: "Contabo",            # DE
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


# ── Holder validation (drift detection) ───────────────────────────────────
# The pipeline used to chase the ASN *number*; RIPE reassigns ASNs, so a curated
# number can silently start pointing at a different — even foreign — holder, and
# the weekly job would import the new holder's ranges under the old Italian/EU
# role. validate_holders() closes that hole: fetch each ASN's live holder and
# fail the build on a mismatch (unless --allow-drift). Live calls happen ONLY
# here (the scheduled/manual generation job) — never in the Rust test matrix,
# which reads the baked data.

RIPESTAT_URL = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{}"

# Legal forms / generic words that carry no identity — dropped before matching.
# NOTE: geographic words like "italia"/"italy" are deliberately NOT noise. With
# the require-ALL-tokens match below, keeping them makes matching STRONGER, not
# weaker: "Telecom Italia" reduces to {telecom, italia}, so a reassignment to a
# different "Telecom X" (e.g. Telecom Argentina) is correctly rejected — it lacks
# "italia". Under the old any-overlap match they had to be dropped (two IT holders
# share "italia"); require-all handles that case via the distinctive token instead.
_NOISE = {
    "asn", "as", "srl", "spa", "sa", "s", "p", "a", "network", "networks",
    "gmbh", "sas", "llc", "group", "consortium", "pjsc",
    "plc", "oao", "ooo", "inc", "ltd", "ltda", "bv", "ag", "se", "nv", "the",
}


def _tokens(name: str) -> set[str]:
    """Lowercase, accent-stripped (NFD → drop combining marks, so
    «Telefónica» == «TELEFONICA»), noise-filtered significant tokens."""
    nfd = unicodedata.normalize("NFD", name)
    ascii_name = "".join(c for c in nfd if not unicodedata.combining(c))
    out, tok = set(), ""
    for ch in ascii_name.lower():
        if ch.isalnum():
            tok += ch
        else:
            if len(tok) > 1 and tok not in _NOISE:
                out.add(tok)
            tok = ""
    if len(tok) > 1 and tok not in _NOISE:
        out.add(tok)
    return out


def holder_matches(expected: str, actual: str) -> bool:
    """True if EVERY significant token of the expected holder appears in the live
    holder. Stricter than a single-token overlap: a reassignment that merely
    shares one generic token (e.g. `telecom`, `orange`) no longer validates
    unless the live holder actually carries the full expected name. An expected
    name that reduces to no significant tokens (all noise) never matches — that
    is a curation error to fix, not a silent pass."""
    exp = _tokens(expected)
    return bool(exp) and exp <= _tokens(actual)


def fetch_holder(asn: int, timeout: int = 15) -> str:
    """Live RIPEstat holder for an ASN (read-only GET). Network-only."""
    with urllib.request.urlopen(RIPESTAT_URL.format(asn), timeout=timeout) as r:
        return json.load(r)["data"]["holder"]


def validate_holders(asn_to_expected: dict[int, str], allow_drift: bool = False,
                     sleep: float = 0.2) -> set[int]:
    """GET each curated ASN's live holder, compare to the expected name, and
    fail closed (exit 2) on any drift unless allow_drift. Returns drifted ASNs."""
    drift = []
    for asn in sorted(asn_to_expected):
        expected = asn_to_expected[asn]
        try:
            live = fetch_holder(asn)
        except Exception as e:  # a lookup failure is drift, never a silent pass
            drift.append((asn, expected, f"<lookup failed: {e}>"))
            continue
        if not holder_matches(expected, live):
            drift.append((asn, expected, live))
        time.sleep(sleep)
    if not drift:
        print(f"  Holder validation: {len(asn_to_expected)} curated ASNs, 0 drift.")
        return set()
    print("\nHOLDER DRIFT — a curated ASN no longer matches its live holder:",
          file=sys.stderr)
    for asn, expected, live in drift:
        print(f"  AS{asn:<7} expected ~ '{expected}'   →   live '{live}'", file=sys.stderr)
    print("\nFix each BY HAND in scripts/generate_sovereign_data.py:\n"
          "  • legitimate reassignment, still sovereign → update the expected name;\n"
          "  • reassigned to a non-sovereign/foreign holder → REMOVE the ASN.",
          file=sys.stderr)
    if not allow_drift:
        print("\nRefusing to generate (fail-closed). Pass --allow-drift to override.",
              file=sys.stderr)
        sys.exit(2)
    print("\n--allow-drift set: generating anyway (drifted ASNs are still emitted).",
          file=sys.stderr)
    return {asn for asn, _, _ in drift}


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
        '/// Sorted by start IP (ascending), non-overlapping.',
        # rustfmt would explode each `cr(...)`/`cr6(...)` call onto multiple
        # lines once its args exceed `fn_call_width` (the u128 v6 literals
        # do) — turning a ~40k-entry table into ~160k lines. Skip it.
        '#[rustfmt::skip]',
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


def generate_rust(v4: list[Range], v6: list[Range], region: dict,
                  snapshot_date: str) -> str:
    adjective = region["adjective"]
    lines = [
        f'//! Baked-in {adjective} CIDR ranges for sovereign edge classification.',
        '//!',
        '//! AUTO-GENERATED by scripts/generate_sovereign_data.py',
        '//! DO NOT EDIT MANUALLY — changes will be overwritten by CI.',
        '//!',
        '//! Sources: RIPE NCC delegated stats + IPtoASN (Team Cymru), v4 + v6.',
        f'//! Snapshot date: {snapshot_date} (curated-ASN holders validated'
        ' against RIPEstat as-overview on this date — see the generator).',
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
    parser.add_argument('--allow-drift', action='store_true',
                        help='Generate even if a curated ASN drifted from its expected '
                             'holder (default: fail closed). Drifted ASNs are still emitted.')
    parser.add_argument('--snapshot-date', default=None,
                        help='Snapshot date stamped in the generated header (default: today UTC).')
    args = parser.parse_args()
    snapshot_date = args.snapshot_date or datetime.now(timezone.utc).date().isoformat()

    region = REGIONS[args.region]
    asn_to_class = {asn: cls for asns, cls in region["asn_roles"] for asn in asns}
    print(f'Region: {args.region} ({region["adjective"]})')

    # Fail closed if any curated ASN has drifted from its expected holder — the
    # security-correctness core: never re-label a reassigned ASN's ranges.
    asn_to_expected = {asn: name for asns, _ in region["asn_roles"]
                       for asn, name in asns.items()}
    print(f'  Validating {len(asn_to_expected)} curated ASN holders against RIPEstat…')
    validate_holders(asn_to_expected, allow_drift=args.allow_drift)

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

    Path(args.output).write_text(generate_rust(v4, v6, region, snapshot_date))
    print(f'  Written to {args.output}')


if __name__ == '__main__':
    main()
