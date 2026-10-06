#!/usr/bin/env python3
"""Generate sovereign CIDR data for Zion from RIPE NCC and IPtoASN sources.

Usage (the files come from scripts/fetch_sovereign_sources.sh):
    python3 generate_sovereign_data.py \
        --region ita \
        --ripe delegated-ripencc-latest --ripe-md5 delegated-ripencc-latest.md5 \
        --iptoasn ip2asn-v4.tsv --iptoasn6 ip2asn-v6.tsv \
        --manifest SOURCES.tsv \
        --output src/sovereign/data_ita.rs

`--region eu` builds the hybrid EU table (country baseline + curated-ASN role
override) into src/sovereign/data_eu.rs.

Before it writes anything the generator checks the source files (exit 4),
validates every curated ASN against its live RIPEstat holder (exit 2) and
measures the new table against the one it replaces (exit 3 past the refusal
threshold). `--verify-only` stops after the first of these.

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
import bisect
import hashlib
import ipaddress
import json
import re
import sys
import time
import unicodedata
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

# Exit codes: the workflow tells a human which of these happened.
EXIT_NO_RANGES = 1
EXIT_HOLDER_DRIFT = 2    # a curated ASN changed holder
EXIT_OVER_BUDGET = 3     # the refresh moves a class by more than REFUSE_CLASS_SHARE
EXIT_INPUT = 4           # a source file failed its integrity checks

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
    60781: "LeaseWeb",           # NL (AS16265, its other ASN, last announced a prefix in 2020)
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
        # A class listed here needs more than a curated ASN: the range must also
        # be registered (RIPE delegation) in one of these countries. OVH and
        # Hetzner are curated as hosters that operate in Italy, and they
        # announce space registered in France, Germany, Israel: before this
        # rule, 85 % of the IPv4 addresses called `DatacenterIta` were
        # registered outside Italy.
        "registered_in": {"DatacenterIta": {"IT"}},
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
        sys.exit(EXIT_HOLDER_DRIFT)
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


# ── Input integrity ────────────────────────────────────────────────────────
# The tables are only as good as the three files they are built from, and a
# download can go wrong quietly: a truncated transfer, an error page saved as
# data, a mirror serving last month's file. Each check below refuses one of
# those before a single range is emitted. They rely on what the files say about
# themselves (RIPE's record counts and date, IPtoASN covering the address space
# end to end), so they need no hand-tuned expectation of "how big is normal".

class InputError(Exception):
    """A source file is truncated, replaced, stale or otherwise not what it claims."""


# IPtoASN lists the routed space in order and fills what is not routed with
# "Not routed" rows, so consecutive rows touch: a hole is a slice of the file
# that went missing. The one hole the IPv6 file has by construction is in the
# reserved space below 2000::/3 (between ::1 and 64:ff9b::1:0:0).
IPTOASN_V6_GLOBAL_UNICAST = int(ipaddress.IPv6Address("2000::"))
# The v4 file spans the first to the last announced prefix: it must start inside
# 1.0.0.0/8 and reach 223.0.0.0/8, the last unicast /8 (what a cut past that
# point loses is APNIC space no table here uses). The v6 file is padded to both
# ends of the space.
IPTOASN_V4_MUST_START_BY = int(ipaddress.IPv4Address("1.255.255.255"))
IPTOASN_V4_MUST_REACH = int(ipaddress.IPv4Address("223.0.0.0"))
IPTOASN_V6_END = (1 << 128) - 1
# Sanity floors, far below today's 538,650 / 183,433 rows and 79,140 / 38,236
# origin ASNs: they only stop a well-formed file that is not a full table.
IPTOASN_MIN_ROWS = {"v4": 300_000, "v6": 100_000}
IPTOASN_MIN_ASNS = {"v4": 60_000, "v6": 25_000}

RIPE_MAX_AGE_DAYS = 7


def verify_ripe(path: Path, md5_path: Path | None = None,
                today: str | None = None) -> dict:
    """Check a RIPE NCC delegated-stats file against its own header, summary
    lines and (if given) the `.md5` RIPE publishes next to it. Returns the
    file's date and record counts. Raises InputError."""
    raw = Path(path).read_bytes()
    if md5_path is not None:
        published = re.search(r"\b[0-9a-fA-F]{32}\b", Path(md5_path).read_text())
        if not published:
            raise InputError(f"RIPE: {md5_path} holds no MD5 digest")
        actual = hashlib.md5(raw, usedforsecurity=False).hexdigest()
        if actual != published.group(0).lower():
            raise InputError(f"RIPE: MD5 is {actual}, RIPE publishes "
                             f"{published.group(0).lower()} (partial or replaced download)")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as e:
        raise InputError(f"RIPE: not a delegated-stats file ({e})") from None

    header = None
    summary: dict[str, int] = {}
    counted: dict[str, int] = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if header is None:
            if len(parts) != 7 or parts[0] != "2" or parts[1] != "ripencc":
                raise InputError(f"RIPE: line {n} is not a version-2 ripencc header: "
                                 f"{line[:60]!r}")
            header = parts
            continue
        if len(parts) == 6 and parts[1] == "*" and parts[5] == "summary":
            summary[parts[2]] = int(parts[4])
            continue
        if len(parts) < 7 or parts[0] != "ripencc" or parts[2] not in ("ipv4", "ipv6", "asn"):
            raise InputError(f"RIPE: line {n} is not a record: {line[:60]!r}")
        counted[parts[2]] = counted.get(parts[2], 0) + 1
    if header is None:
        raise InputError("RIPE: no header line (empty file)")
    for kind in ("ipv4", "ipv6", "asn"):
        if kind not in summary:
            raise InputError(f"RIPE: no summary line for {kind}")
        if counted.get(kind, 0) != summary[kind]:
            raise InputError(f"RIPE: {counted.get(kind, 0)} {kind} records, the file's own "
                             f"summary says {summary[kind]} (truncated?)")
    if sum(counted.values()) != int(header[3]):
        raise InputError(f"RIPE: {sum(counted.values())} records, the header says {header[3]}")

    try:
        end = datetime.strptime(header[5], "%Y%m%d").date()
    except ValueError:
        raise InputError(f"RIPE: header end date {header[5]!r} is not a date") from None
    ref = (datetime.strptime(today, "%Y-%m-%d").date() if today
           else datetime.now(timezone.utc).date())
    age = (ref - end).days
    if age > RIPE_MAX_AGE_DAYS:
        raise InputError(f"RIPE: file is dated {end.isoformat()}, {age} days before {ref.isoformat()} "
                         f"(more than {RIPE_MAX_AGE_DAYS}: a stale mirror or cache)")
    return {"date": end.isoformat(), "records": counted, "md5_checked": md5_path is not None}


def verify_iptoasn(path: Path, family: str) -> dict:
    """Check an IPtoASN table for one address family: every row parses, rows are
    in order with no hole between them, the table reaches the end of the address
    space and is the size of a full table. Returns its row and origin-ASN counts. Raises InputError."""
    addr = ipaddress.IPv4Address if family == "v4" else ipaddress.IPv6Address
    name = f"IPtoASN {family}"
    rows = 0
    asns: set[int] = set()
    first = prev_end = None
    with open(path, errors="replace") as f:
        for n, line in enumerate(f, 1):
            parts = line.rstrip("\n").split("\t")
            try:
                if len(parts) < 5:
                    raise ValueError("fewer than 5 columns")
                start, end, asn = int(addr(parts[0])), int(addr(parts[1])), int(parts[2])
            except (ValueError, ipaddress.AddressValueError) as e:
                raise InputError(f"{name}: line {n} does not parse ({e}): {line[:60]!r}") from None
            if end < start:
                raise InputError(f"{name}: line {n} ends before it starts")
            if prev_end is not None:
                if start <= prev_end:
                    raise InputError(f"{name}: line {n} is out of order or overlaps the previous row")
                if start != prev_end + 1 and (family == "v4" or start > IPTOASN_V6_GLOBAL_UNICAST):
                    raise InputError(f"{name}: line {n} does not follow the previous row: "
                                     f"{addr(prev_end + 1)} to {addr(start - 1)} is missing")
            else:
                first = start
            prev_end = end
            rows += 1
            if asn:
                asns.add(asn)
    if rows == 0:
        raise InputError(f"{name}: empty file")
    if family == "v4":
        if first > IPTOASN_V4_MUST_START_BY:
            raise InputError(f"{name}: starts at {addr(first)}, not inside 1.0.0.0/8 (head missing)")
        if prev_end < IPTOASN_V4_MUST_REACH:
            raise InputError(f"{name}: ends at {addr(prev_end)}, before 223.0.0.0/8 (truncated)")
    else:
        if first != 0:
            raise InputError(f"{name}: starts at {addr(first)}, not at :: (head missing)")
        if prev_end != IPTOASN_V6_END:
            raise InputError(f"{name}: ends at {addr(prev_end)}, not at the end of the "
                             f"address space (truncated)")
    if rows < IPTOASN_MIN_ROWS[family]:
        raise InputError(f"{name}: {rows} rows, fewer than {IPTOASN_MIN_ROWS[family]} "
                         f"(not a full table)")
    if len(asns) < IPTOASN_MIN_ASNS[family]:
        raise InputError(f"{name}: {len(asns)} origin ASNs, fewer than "
                         f"{IPTOASN_MIN_ASNS[family]} (not a full table)")
    return {"rows": rows, "asns": len(asns)}


IPTOASN_MAX_AGE_DAYS = 7


def load_manifest(path: Path) -> dict[str, dict]:
    """Read the SOURCES.tsv that scripts/fetch_sovereign_sources.sh writes next to
    the files it downloads: name, URL, HTTP Last-Modified, size, SHA-256."""
    out: dict[str, dict] = {}
    for line in Path(path).read_text().splitlines():
        parts = line.split("\t")
        if len(parts) != 5:
            raise InputError(f"manifest: not five columns: {line[:60]!r}")
        name, url, modified, size, sha256 = parts
        out[name] = {"url": url, "last_modified": modified, "bytes": int(size), "sha256": sha256}
    return out


def verify_against_manifest(path: Path, manifest: dict[str, dict], today: str | None) -> dict:
    """The file is the one that was downloaded (size and SHA-256), and the server
    did not hand out an old one (Last-Modified). Returns the manifest entry."""
    name = Path(path).name
    entry = manifest.get(name)
    if entry is None:
        raise InputError(f"manifest: no entry for {name}")
    raw = Path(path).read_bytes()
    if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise InputError(f"{name}: not the file the manifest describes "
                         f"(size or SHA-256 differs: changed after the download)")
    try:
        modified = parsedate_to_datetime(entry["last_modified"]).date()
    except (TypeError, ValueError):
        raise InputError(f"{name}: no usable Last-Modified in the manifest "
                         f"({entry['last_modified']!r})") from None
    ref = (datetime.strptime(today, "%Y-%m-%d").date() if today
           else datetime.now(timezone.utc).date())
    age = (ref - modified).days
    if age > IPTOASN_MAX_AGE_DAYS:
        raise InputError(f"{name}: last modified {modified.isoformat()}, {age} days before "
                         f"{ref.isoformat()} (more than {IPTOASN_MAX_AGE_DAYS}: a stale file)")
    return entry


def verify_inputs(ripe: Path, iptoasn4: Path, iptoasn6: Path, md5: Path | None = None,
                  manifest_path: Path | None = None, today: str | None = None) -> dict:
    """Run every integrity check on the three source files. Returns what they
    say about themselves, for the report. Raises InputError on the first failure."""
    sources = {
        "ripe": verify_ripe(ripe, md5, today),
        "iptoasn_v4": verify_iptoasn(iptoasn4, "v4"),
        "iptoasn_v6": verify_iptoasn(iptoasn6, "v6"),
    }
    if manifest_path is not None:
        manifest = load_manifest(manifest_path)
        for key, path in (("ripe", ripe), ("iptoasn_v4", iptoasn4), ("iptoasn_v6", iptoasn6)):
            sources[key]["last_modified"] = verify_against_manifest(
                path, manifest, today)["last_modified"]
    return sources

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


def intersect(ranges: list[Range], allowed: list[Range]) -> list[Range]:
    """The parts of `ranges` that lie inside `allowed`. Both are sorted and
    non-overlapping; the pieces keep the class of the range they come from."""
    out: list[Range] = []
    ai = 0
    for r in ranges:
        while ai < len(allowed) and allowed[ai].end < r.start:
            ai += 1
        k = ai
        while k < len(allowed) and allowed[k].start <= r.end:
            out.append(Range(max(r.start, allowed[k].start), min(r.end, allowed[k].end),
                             r.ip_class, r.priority))
            k += 1
    return out


def outside(ranges: list[Range], allowed: list[Range]) -> list[Range]:
    """The parts of `ranges` that lie outside `allowed`: what intersect() drops."""
    out: list[Range] = []
    ai = 0
    for r in ranges:
        at = r.start
        while ai < len(allowed) and allowed[ai].end < at:
            ai += 1
        k = ai
        while k < len(allowed) and allowed[k].start <= r.end:
            if allowed[k].start > at:
                out.append(Range(at, allowed[k].start - 1, r.ip_class, r.priority))
            at = max(at, allowed[k].end + 1)
            k += 1
        if at <= r.end:
            out.append(Range(at, r.end, r.ip_class, r.priority))
    return out


def build_family(role_by_asn: dict[int, list[Range]], asn_to_class: dict[int, str],
                 baseline: list[Range], baseline_class: str | None,
                 registered: dict[str, list[Range]] | None = None) -> list[Range]:
    """Combine curated-ASN role ranges (priority) with the optional country
    baseline into a sorted, non-overlapping set for one address family.
    `registered` maps a class to the address space it is confined to: what a
    curated ASN announces outside it gets no role."""
    ranges: list[Range] = []
    for asn, rs in role_by_asn.items():
        cls = asn_to_class.get(asn)
        if cls:
            mine = [Range(r.start, r.end, cls, ROLE_PRIORITY)
                    for r in sorted(rs, key=lambda r: r.start)]
            if registered and cls in registered:
                mine = intersect(mine, registered[cls])
            ranges += mine
    if baseline_class is not None:
        for r in baseline:
            ranges.append(Range(r.start, r.end, baseline_class, BASELINE_PRIORITY))
    resolved = resolve_priority(ranges)
    resolved = merge_same_class(resolved)
    resolved.sort(key=lambda r: r.start)
    return resolved


# ── Who announces a block, and where it is registered ──────────────────────
# A change in the table is a run of addresses and two class names. To judge it a
# reviewer needs two more facts, both already in the source files: which ASN
# originates those addresses in this snapshot, and in which country the registry
# has them.

_SAFE_TEXT = re.compile(r"[^A-Za-z0-9 ._-]+")


def safe_text(text: str, limit: int = 40) -> str:
    """Text from a source file made fit for a pull request body: letters,
    digits, space, dot, underscore and dash only, and no longer than `limit`.
    AS names are written by whoever registered the AS; none of it may become
    Markdown, a link or a mention."""
    out = " ".join(_SAFE_TEXT.sub(" ", text).split())
    return out if len(out) <= limit else out[:limit - 1].rstrip() + "…"


class SpanIndex:
    """Labelled address intervals, sorted and non-overlapping, with one question:
    how many addresses of a block does each label cover?"""

    def __init__(self, spans: list[tuple[int, int, str]]):
        self.spans = sorted(spans)
        self.starts = [s[0] for s in self.spans]

    def cover(self, start: int, end: int) -> dict[str | None, int]:
        """Addresses of [start, end] per label, most first; `None` counts the
        addresses no interval covers."""
        out: dict[str | None, int] = {}
        left = end - start + 1
        i = max(bisect.bisect_right(self.starts, start) - 1, 0)
        while i < len(self.spans) and self.spans[i][0] <= end:
            s, e, label = self.spans[i]
            n = min(e, end) - max(s, start) + 1
            if n > 0:
                out[label] = out.get(label, 0) + n
                left -= n
            i += 1
        if left:
            out[None] = left
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def load_origins(path: Path, family: str) -> SpanIndex:
    """IPtoASN as an index: `AS1267 ASN-WINDTRE IUNET (IT)` per announced range.
    "Not routed" rows are left out, so they count as covered by nothing."""
    addr = ipaddress.IPv4Address if family == "v4" else ipaddress.IPv6Address
    spans = []
    with open(path, errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5 or parts[2] == "0":
                continue
            label = f"AS{int(parts[2])} {safe_text(parts[4])} ({safe_text(parts[3], 2)})"
            spans.append((int(addr(parts[0])), int(addr(parts[1])), label))
    return SpanIndex(spans)


def load_registry(path: Path) -> dict[str, SpanIndex]:
    """RIPE's delegations as an index per family: the country code of every
    allocation, whatever the country."""
    spans: dict[str, list[tuple[int, int, str]]] = {"v4": [], "v6": []}
    with open(path) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) < 7 or parts[0] != "ripencc":
                continue
            cc = parts[1] if re.fullmatch(r"[A-Z]{2}", parts[1]) else "??"
            try:
                if parts[2] == "ipv4":
                    start = int(ipaddress.IPv4Address(parts[3]))
                    spans["v4"].append((start, start + int(parts[4]) - 1, cc))
                elif parts[2] == "ipv6":
                    net = ipaddress.IPv6Network(f"{parts[3]}/{parts[4]}", strict=False)
                    spans["v6"].append((int(net.network_address), int(net.broadcast_address), cc))
            except (ValueError, ipaddress.AddressValueError):
                continue
    return {family: SpanIndex(s) for family, s in spans.items()}


def format_cover(cover: dict[str | None, int], nothing: str, keep: int = 2) -> str:
    """`IT`, or `DE 60 %, FR 40 %`, or `AS1 X (IT) 75 %, not announced 25 %`:
    the labels covering a block with their share, the largest `keep` of them."""
    total = sum(cover.values())
    if not total:
        return nothing
    items = [(label if label is not None else nothing, n) for label, n in cover.items()]
    if len(items) == 1:
        return items[0][0]
    shown = [f"{label} {n / total:.0%}".replace("%", " %") for label, n in items[:keep]]
    if len(items) > keep:
        shown.append(f"{len(items) - keep} more")
    return ", ".join(shown)


class Describer:
    """What the source files say about a run of addresses."""

    def __init__(self, origins: dict[str, SpanIndex], registry: dict[str, SpanIndex]):
        self.origins, self.registry = origins, registry

    def announced_by(self, c: Change) -> str:
        return format_cover(self.origins[c.family].cover(c.start, c.end), "not announced")

    def registered_in(self, c: Change) -> str:
        return format_cover(self.registry[c.family].cover(c.start, c.end), "not in RIPE's file")

# ── Change budget ──────────────────────────────────────────────────────────
# A refresh is compared with the table it replaces. The comparison is on
# addresses, not on lines of generated Rust: one row can be a /8 or a /24.

_TABLE_ROW = re.compile(r"^\s*(cr6?)\(0x([0-9A-Fa-f]+), 0x([0-9A-Fa-f]+), IpClass::(\w+)\),")


def parse_rust_table(path: Path) -> dict[str, list[Range]]:
    """Read back a generated `data_*.rs`: {'v4': [...], 'v6': [...]}."""
    out: dict[str, list[Range]] = {"v4": [], "v6": []}
    with open(path) as f:
        for line in f:
            m = _TABLE_ROW.match(line)
            if m:
                fam = "v4" if m.group(1) == "cr" else "v6"
                out[fam].append(Range(int(m.group(2), 16), int(m.group(3), 16), m.group(4)))
    return out


@dataclass
class Change:
    """A run of addresses whose class differs between two tables. `None` is
    "not in the table" (the classifier answers `Unknown`)."""
    family: str
    start: int
    end: int
    old: str | None
    new: str | None

    @property
    def size(self) -> int:
        return self.end - self.start + 1


def diff_family(old: list[Range], new: list[Range], family: str) -> list[Change]:
    """Every run of addresses classified differently by two sorted,
    non-overlapping range lists, in address order."""
    bounds = set()
    for r in old:
        bounds.add(r.start)
        bounds.add(r.end + 1)
    for r in new:
        bounds.add(r.start)
        bounds.add(r.end + 1)
    points = sorted(bounds)
    out: list[Change] = []
    oi = ni = 0
    for i in range(len(points) - 1):
        seg_start, seg_end = points[i], points[i + 1] - 1
        while oi < len(old) and old[oi].end < seg_start:
            oi += 1
        while ni < len(new) and new[ni].end < seg_start:
            ni += 1
        a = old[oi].ip_class if oi < len(old) and old[oi].start <= seg_start else None
        b = new[ni].ip_class if ni < len(new) and new[ni].start <= seg_start else None
        if a == b:
            continue
        last = out[-1] if out else None
        if last and last.end + 1 == seg_start and last.old == a and last.new == b:
            last.end = seg_end
        else:
            out.append(Change(family, seg_start, seg_end, a, b))
    return out


def class_totals(ranges: list[Range]) -> dict[str, int]:
    """Addresses per class."""
    totals: dict[str, int] = {}
    for r in ranges:
        totals[r.ip_class] = totals.get(r.ip_class, 0) + r.end - r.start + 1
    return totals


def format_block(family: str, start: int, end: int) -> str:
    """A run of addresses as CIDR text: one prefix when it is one, else
    `first-last`."""
    addr = ipaddress.IPv4Address if family == "v4" else ipaddress.IPv6Address
    nets = list(ipaddress.summarize_address_range(addr(start), addr(end)))
    return str(nets[0]) if len(nets) == 1 else f"{addr(start)}-{addr(end)}"


def format_size(family: str, n: int) -> str:
    """An address count a person can read: addresses in IPv4, /48 sites in IPv6
    (an IPv6 /32 is 79,228,162,514,264,337,593,543,950,336 addresses, or 65,536 /48s)."""
    if family == "v4":
        return f"{n:,} addresses"
    sites = n / (1 << 80)
    if sites < 1:
        return "less than a /48"
    return "1 /48" if round(sites) == 1 else f"{sites:,.0f} /48s"


# A class may move by this share of its addresses in one refresh before a human
# has to look.
REVIEW_CLASS_SHARE = 0.02
# One run of addresses this large entering or leaving a role class is looked at
# whatever the share: a /18 in IPv4, a /32 (one provider allocation) in IPv6.
# Role classes come from what a curated ASN announces in one BGP snapshot. The
# country baseline comes from the registry and is held to the share alone.
REVIEW_BLOCK = {"v4": 1 << 14, "v6": 1 << 96}
# Past this share the refresh is refused outright: it is the signature of a
# broken input or of an edit to the curated list, not of a week of routing.
REFUSE_CLASS_SHARE = 0.20
#
# Calibration, on the nine weekly tables from 2026-08-12 to 2026-10-05: the block
# rule singles out SURF's /13 leaving GovEu, the /16 a Scaleway announcement
# turned into DatacenterEu for two weeks, and the Wind Tre and TIM blocks that
# came and went; the refusal fires once, on the week the curated list was cut
# (GovEu lost 90 % of its IPv6).


@dataclass
class Budget:
    """What a refresh changes, measured against REVIEW_* and REFUSE_*.
    `review` asks for a human look, `refuse` stops the refresh."""
    review: list[str]
    refuse: list[str]


def check_budget(old: dict[str, list[Range]], new: dict[str, list[Range]],
                 baseline_class: str | None, describer: Describer | None = None) -> Budget:
    """Compare a refreshed table with the one it replaces. With a `describer`,
    each block is followed by who announces it and where it is registered."""
    budget = Budget([], [])
    for family in ("v4", "v6"):
        before, after = class_totals(old[family]), class_totals(new[family])
        for cls in sorted(set(before) | set(after)):
            b, a = before.get(cls, 0), after.get(cls, 0)
            if b == 0:
                budget.review.append(f"IP{family} class {cls} is new "
                                     f"({format_size(family, a)})")
                continue
            share = abs(a - b) / b
            line = (f"IP{family} class {cls} goes from {format_size(family, b)} to "
                    f"{format_size(family, a)} ({(a - b) / b:+.1%})")
            if share > REFUSE_CLASS_SHARE:
                budget.refuse.append(line)
            elif share > REVIEW_CLASS_SHARE:
                budget.review.append(line)
        for c in diff_family(old[family], new[family], family):
            role = [cls for cls in (c.old, c.new) if cls is not None and cls != baseline_class]
            if role and c.size >= REVIEW_BLOCK[family]:
                line = (f"{format_block(family, c.start, c.end)} ({format_size(family, c.size)}) "
                        f"moves from {c.old or 'no class'} to {c.new or 'no class'}")
                if describer:
                    line += (f": {describer.announced_by(c)}; "
                             f"registered in {describer.registered_in(c)}")
                budget.review.append(line)
    return budget


def unannounced_asns(asn_to_class: dict[int, str], role_v4: dict[int, list[Range]]) -> list[int]:
    """Curated ASNs that originate no IPv4 range in this snapshot: either the
    ASN went quiet and its ranges are leaving the table, or it should not be on
    the list."""
    return sorted(asn for asn in asn_to_class if not role_v4.get(asn))

# ── Hysteresis ─────────────────────────────────────────────────────────────
# One snapshot says what a curated ASN announced at one moment. Prefixes are
# announced on and off, moved between the ASNs of one operator, borrowed for two
# weeks. A table that copies each snapshot labels real clients wrongly for a
# week at a time. So the published table follows the snapshots with a delay:
#
#   * a run of addresses with no class gets one after ENTER_AFTER consecutive
#     snapshots that agree on it;
#   * a run that has a class loses or changes it after LEAVE_AFTER.
#
# What has been observed and not yet published is kept in a small file next to
# the table (`data_<region>.pending.json`), committed with it: the memory of the
# pipeline is in the repository, and every refresh shows it in its diff.

ENTER_AFTER = 2
LEAVE_AFTER = 3
# Two runs count as two snapshots only this many days apart: a refresh run again
# the same day, or the day after, is the same week's observation.
MIN_SPACING_DAYS = 5

STATE_VERSION = 1


@dataclass
class Pending:
    """A run of addresses observed in a class other than the published one."""
    family: str
    start: int
    end: int
    observed: str | None
    seen: int
    first: str
    last: str

    @property
    def size(self) -> int:
        return self.end - self.start + 1

    def facts(self) -> tuple:
        return (self.observed, self.seen, self.first, self.last)


@dataclass
class Settled:
    """One family after a snapshot: the table to publish, what still waits,
    what was published now (`applied`, with how long it waited) and what stopped
    being observed before it was published (`went_back`)."""
    table: list[Range]
    pending: list[Pending]
    applied: list[Pending]
    went_back: list[Pending]


def _days_between(earlier: str, later: str) -> int:
    return (datetime.strptime(later, "%Y-%m-%d") - datetime.strptime(earlier, "%Y-%m-%d")).days


def _extend(seq: list, item, same) -> None:
    """Append `item`, or grow the last element when it touches it and `same`."""
    if seq and seq[-1].end + 1 == item.start and same(seq[-1], item):
        seq[-1].end = item.end
    else:
        seq.append(item)


def settle_family(published: list[Range], observed: list[Range], pending: list[Pending],
                  snapshot: str, family: str) -> Settled:
    """Advance one family by one snapshot. All three inputs are sorted and
    non-overlapping; every address is decided on its own, runs are only how the
    result is written down."""
    bounds = set()
    for seq in (published, observed, pending):
        for r in seq:
            bounds.add(r.start)
            bounds.add(r.end + 1)
    points = sorted(bounds)
    out = Settled([], [], [], [])
    same_class = lambda a, b: a.ip_class == b.ip_class
    same_facts = lambda a, b: a.facts() == b.facts()
    pi = oi = qi = 0
    for i in range(len(points) - 1):
        s, e = points[i], points[i + 1] - 1
        while pi < len(published) and published[pi].end < s:
            pi += 1
        while oi < len(observed) and observed[oi].end < s:
            oi += 1
        while qi < len(pending) and pending[qi].end < s:
            qi += 1
        p = published[pi].ip_class if pi < len(published) and published[pi].start <= s else None
        o = observed[oi].ip_class if oi < len(observed) and observed[oi].start <= s else None
        q = pending[qi] if qi < len(pending) and pending[qi].start <= s else None

        final = p
        if o == p:
            if q is not None:
                _extend(out.went_back, Pending(family, s, e, *q.facts()), same_facts)
        else:
            if q is not None and q.observed == o:
                fresh = _days_between(q.last, snapshot) >= MIN_SPACING_DAYS
                seen, first, last = q.seen + fresh, q.first, snapshot if fresh else q.last
            else:
                seen, first, last = 1, snapshot, snapshot
            waited = Pending(family, s, e, o, seen, first, last)
            if seen >= (ENTER_AFTER if p is None else LEAVE_AFTER):
                _extend(out.applied, waited, same_facts)
                final = o
            else:
                _extend(out.pending, waited, same_facts)
        if final is not None:
            _extend(out.table, Range(s, e, final), same_class)
    return out


def patch_family(table: list[Range], changes: list[Change]) -> list[Range]:
    """`table` with every run in `changes` set to its new class."""
    as_ranges = [Range(c.start, c.end, c.new or "", ROLE_PRIORITY) for c in changes]
    base = [Range(r.start, r.end, r.ip_class, BASELINE_PRIORITY) for r in table]
    patched = [r for r in resolve_priority(base + as_ranges) if r.ip_class]
    return merge_same_class([Range(r.start, r.end, r.ip_class) for r in patched])


def without(pending: list[Pending], changes: list[Change]) -> list[Pending]:
    """`pending` minus the addresses of `changes` (both sorted, non-overlapping)."""
    out: list[Pending] = []
    ci = 0
    for q in pending:
        at = q.start
        while ci < len(changes) and changes[ci].end < at:
            ci += 1
        k = ci
        while k < len(changes) and changes[k].start <= q.end:
            if changes[k].start > at:
                out.append(Pending(q.family, at, changes[k].start - 1, *q.facts()))
            at = max(at, changes[k].end + 1)
            k += 1
        if at <= q.end:
            out.append(Pending(q.family, at, q.end, *q.facts()))
    return out


def parse_block(family: str, text: str) -> tuple[int, int]:
    """The inverse of format_block: `a.b.c.d/len` or `first-last`."""
    addr = ipaddress.IPv4Address if family == "v4" else ipaddress.IPv6Address
    if "/" in text:
        net = ipaddress.ip_network(text, strict=True)
        return int(net.network_address), int(net.broadcast_address)
    first, last = text.split("-")
    return int(addr(first)), int(addr(last))


def load_state(path: Path, region: str) -> tuple[dict[int, str] | None, dict[str, list[Pending]]]:
    """Read `data_<region>.pending.json`: the curated list the table was last
    built with, and what waits. A missing file is an empty memory."""
    pending: dict[str, list[Pending]] = {"v4": [], "v6": []}
    if not Path(path).exists():
        return None, pending
    state = json.loads(Path(path).read_text())
    if state.get("version") != STATE_VERSION or state.get("region") != region:
        raise InputError(f"{path}: not a version-{STATE_VERSION} state file for {region!r}")
    for row in state["pending"]:
        start, end = parse_block(row["family"], row["block"])
        pending[row["family"]].append(Pending(row["family"], start, end, row["observed"],
                                              row["seen"], row["first"], row["last"]))
    for family in pending:
        pending[family].sort(key=lambda q: q.start)
    return {int(asn): cls for asn, cls in state["curated"].items()}, pending


def dump_state(region: str, snapshot: str, curated: dict[int, str],
               pending: dict[str, list[Pending]]) -> str:
    """The state file: one curated ASN and one waiting run per line, in a fixed
    order, so that a refresh shows up as a readable diff."""
    lines = [
        "{",
        f'  "version": {STATE_VERSION},',
        f'  "region": {json.dumps(region)},',
        f'  "snapshot": {json.dumps(snapshot)},',
        f'  "rule": "a run enters a class after {ENTER_AFTER} weekly snapshots, '
        f'leaves or changes class after {LEAVE_AFTER}",',
        '  "curated": {',
    ]
    asns = sorted(curated)
    lines += [f'    "{asn}": {json.dumps(curated[asn])}' + ("," if asn != asns[-1] else "")
              for asn in asns]
    lines += ["  },", '  "pending": [']
    rows = [json.dumps({"family": q.family, "block": format_block(q.family, q.start, q.end),
                        "observed": q.observed, "seen": q.seen, "first": q.first, "last": q.last})
            for family in ("v4", "v6") for q in pending[family]]
    lines += [f"    {row}" + ("," if i < len(rows) - 1 else "") for i, row in enumerate(rows)]
    lines += ["  ]", "}", ""]
    return "\n".join(lines)


def confine_family(published: list[Range], observed: list[Range],
                   registered: dict[str, list[Range]], family: str) -> list[Change]:
    """Published runs of a confined class that lie outside the space the class
    is confined to, each with the class this snapshot gives those addresses.
    No snapshot can observe them in that class again, so there is nothing to
    wait for: they change at once. This is what applies a new `registered_in`
    rule to a table built before it, and what follows a block that the registry
    moves to another country."""
    stray: list[Range] = []
    for cls, allowed in registered.items():
        stray += outside([r for r in published if r.ip_class == cls], allowed)
    stray.sort(key=lambda r: r.start)
    support = merge_same_class([Range(r.start, r.end, "") for r in stray])
    return diff_family(stray, intersect(observed, support), family)


@dataclass
class Refresh:
    """What one snapshot does to a region: the table to publish and the memory
    to keep, with what happened on the way."""
    table: dict[str, list[Range]]
    pending: dict[str, list[Pending]]
    applied: list[Pending]
    went_back: list[Pending]
    curation: list[Change]


def settle(published: dict[str, list[Range]], observed: dict[str, list[Range]],
           pending: dict[str, list[Pending]], snapshot: str,
           curation: dict[str, list[Change]] | None = None) -> Refresh:
    """Advance both families by one snapshot. `curation` holds the runs whose
    class changed because the curated list did (an ASN removed, or given another
    role): those are published at once. A removal is a correction, and making it
    wait three weeks would keep a wrong label on purpose."""
    out = Refresh({}, {}, [], [], [])
    for family in ("v4", "v6"):
        base, waiting = published[family], pending[family]
        edits = (curation or {}).get(family, [])
        if edits:
            base, waiting = patch_family(base, edits), without(waiting, edits)
            out.curation += edits
        settled = settle_family(base, observed[family], waiting, snapshot, family)
        out.table[family], out.pending[family] = settled.table, settled.pending
        out.applied += settled.applied
        out.went_back += settled.went_back
    return out

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
        '//! Sources: RIPE NCC delegated stats + IPtoASN (iptoasn.com), v4 + v6.',
        f'//! Snapshot date: {snapshot_date} (curated-ASN holders validated'
        ' against RIPEstat as-overview on this date — see the generator).',
        '//!',
        f'//! The table follows the weekly snapshots with a delay: a run of addresses enters a',
        f'//! class after {ENTER_AFTER} snapshots that agree, and leaves or changes class after {LEAVE_AFTER}. What is',
        f'//! observed and not yet published is in `{region["module"]}.pending.json`, next to this file.',
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


def _count(family: str, n: int) -> str:
    """A table cell: addresses in IPv4, /48 sites in IPv6."""
    return f"{n:,}" if family == "v4" else f"{n / (1 << 80):,.0f} /48s"


# How many changes the summary lists per family, largest first.
SUMMARY_LARGEST = {"v4": 12, "v6": 8}


def render_changes(changes: list[Change], describer: Describer | None) -> list[str]:
    """The largest changes of a refresh as Markdown tables, one per family."""
    lines = []
    for family, title in (("v4", "IPv4"), ("v6", "IPv6")):
        mine = sorted((c for c in changes if c.family == family), key=lambda c: -c.size)
        if not mine:
            continue
        shown = mine[:SUMMARY_LARGEST[family]]
        lines += [
            f"### Largest {title} changes",
            "",
            "| Block | Size | From | To | Announced by | Registered in |",
            "|---|---:|---|---|---|---|",
        ]
        for c in shown:
            size = format_size(family, c.size).replace(" addresses", "")
            lines.append(
                f"| `{format_block(family, c.start, c.end)}` | {size} "
                f"| {c.old or 'no class'} | {c.new or 'no class'} "
                f"| {describer.announced_by(c) if describer else ''} "
                f"| {describer.registered_in(c) if describer else ''} |")
        lines.append("")
        if len(mine) > len(shown):
            rest = sum(c.size for c in mine[len(shown):])
            lines += [f"{len(mine) - len(shown)} smaller {title} changes are not listed "
                      f"({format_size(family, rest)} in all).", ""]
    return lines


# How many waiting runs the summary lists per family, largest first.
SUMMARY_WAITING = {"v4": 10, "v6": 5}


def render_memory(refresh: Refresh, old: dict, describer: Describer | None) -> list[str]:
    """What the hysteresis holds back, as Markdown: the runs waiting to be
    published and the ones that went back before they were."""
    lines = []
    published = {f: SpanIndex([(r.start, r.end, r.ip_class) for r in old[f]]) for f in ("v4", "v6")}
    waiting = [q for f in ("v4", "v6") for q in refresh.pending[f]]
    if refresh.applied or refresh.curation:
        lines += [
            f"{len(refresh.applied)} runs are published now after waiting their snapshots"
            + (f"; {len(refresh.curation)} more at once: the curated ASN list changed, or a "
               f"range is outside the countries its class is confined to."
               if refresh.curation else "."),
            "",
        ]
    if waiting:
        lines += [
            "### Observed, not yet published",
            "",
            f"A run enters a class after {ENTER_AFTER} weekly snapshots that agree and leaves or "
            f"changes class after {LEAVE_AFTER}. {len(waiting)} runs are waiting; the largest:",
            "",
            "| Block | Size | Published as | Observed as | Seen | Since | Announced by | Registered in |",
            "|---|---:|---|---|---|---|---|---|",
        ]
        for family in ("v4", "v6"):
            mine = sorted((q for q in waiting if q.family == family), key=lambda q: -q.size)
            for q in mine[:SUMMARY_WAITING[family]]:
                now = format_cover(published[family].cover(q.start, q.end), "no class")
                # A run can straddle published classes, with a different wait for each.
                need = "/".join(str(n) for n in sorted({
                    ENTER_AFTER if label is None else LEAVE_AFTER
                    for label in published[family].cover(q.start, q.end)}))
                size = format_size(family, q.size).replace(" addresses", "")
                lines.append(
                    f"| `{format_block(family, q.start, q.end)}` | {size} | {now} "
                    f"| {q.observed or 'no class'} | {q.seen} of {need} | {q.first} "
                    f"| {describer.announced_by(q) if describer else ''} "
                    f"| {describer.registered_in(q) if describer else ''} |")
        lines.append("")
    if refresh.went_back:
        gone = sorted(refresh.went_back, key=lambda q: -(q.size if q.family == "v4" else q.size >> 96))
        lines += [
            "### Observed and gone again",
            "",
            f"{len(gone)} runs were waiting and are back to their published class. The table "
            "never changed for them. The largest:",
            "",
            "| Block | Size | Published as | Was observed as | Seen | First seen |",
            "|---|---:|---|---|---:|---|",
        ]
        for q in gone[:8]:
            now = format_cover(published[q.family].cover(q.start, q.end), "no class")
            size = format_size(q.family, q.size).replace(" addresses", "")
            lines.append(f"| `{format_block(q.family, q.start, q.end)}` | {size} | {now} "
                         f"| {q.observed or 'no class'} | {q.seen} | {q.first} |")
        lines.append("")
    return lines


def render_summary(region: dict, sources: dict, old: dict | None, new: dict,
                   budget: Budget, changes: list[Change] | None = None,
                   describer: Describer | None = None, refresh: Refresh | None = None) -> str:
    """The refresh in Markdown, for the pull request: what it was built from,
    what needs a look, how many addresses each class holds before and after,
    the largest blocks that change class, and what is held back."""
    ripe, v4, v6 = sources["ripe"], sources["iptoasn_v4"], sources["iptoasn_v6"]
    lines = [
        "### Built from",
        "",
        "| Source | Dated | Holds |",
        "|---|---|---|",
        f"| RIPE NCC delegated stats | {ripe['date']} | "
        f"{sum(ripe['records'].values()):,} records, counts "
        f"{'and MD5 ' if ripe.get('md5_checked') else ''}checked |",
        f"| IPtoASN IPv4 | {v4.get('last_modified', 'not recorded')} | "
        f"{v4['rows']:,} rows, {v4['asns']:,} origin ASNs |",
        f"| IPtoASN IPv6 | {v6.get('last_modified', 'not recorded')} | "
        f"{v6['rows']:,} rows, {v6['asns']:,} origin ASNs |",
        "",
    ]
    if budget.refuse:
        lines += ["### Refused", ""] + [f"- {x}" for x in budget.refuse] + [""]
    if budget.review:
        lines += ["### Needs a look before merging", ""]
        lines += [f"- {x}" for x in budget.review] + [""]
    if old is None:
        return "\n".join(lines)
    lines += [
        f"### {region['adjective']} addresses per class",
        "",
        "| Class | IPv4 before | IPv4 after | Change | IPv6 before | IPv6 after | Change |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    totals = {(f, when): class_totals(t[f])
              for f in ("v4", "v6") for when, t in (("old", old), ("new", new))}
    classes = sorted({c for t in totals.values() for c in t})
    for cls in classes:
        cells = []
        for family in ("v4", "v6"):
            b, a = totals[(family, "old")].get(cls, 0), totals[(family, "new")].get(cls, 0)
            change = f"{(a - b) / b:+.2%}" if b else "new"
            cells += [_count(family, b), _count(family, a), change]
        lines.append(f"| `{cls}` | " + " | ".join(cells) + " |")
    lines.append("")
    lines += render_changes(changes or [], describer)
    if refresh is not None:
        lines += render_memory(refresh, old, describer)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description='Generate sovereign CIDR data for Zion')
    parser.add_argument('--region', default='ita', choices=sorted(REGIONS))
    parser.add_argument('--ripe', required=True, help='Path to delegated-ripencc-latest')
    parser.add_argument('--ripe-md5', default=None,
                        help='Path to the .md5 RIPE publishes next to the file; checked if given.')
    parser.add_argument('--iptoasn', required=True, help='Path to ip2asn-v4.tsv')
    parser.add_argument('--iptoasn6', required=True, help='Path to ip2asn-v6.tsv')
    parser.add_argument('--manifest', default=None,
                        help='SOURCES.tsv from scripts/fetch_sovereign_sources.sh: the files must '
                             'match it and must not be stale.')
    parser.add_argument('--verify-only', action='store_true',
                        help='Check the source files and stop: no lookups, nothing generated.')
    parser.add_argument('--output', default=None, help='Output .rs file path')
    parser.add_argument('--previous', default=None,
                        help='Table to measure the change against (default: the file at --output).')
    parser.add_argument('--allow-over-budget', action='store_true',
                        help='Write the table even if a class moved by more than '
                             f'{round(REFUSE_CLASS_SHARE * 100)} %% (default: refuse). For a refresh that '
                             'follows an edit of the curated ASN list.')
    parser.add_argument('--state', default=None,
                        help='The memory of the hysteresis (default: next to --output, '
                             'data_<region>.pending.json). Read, then rewritten.')
    parser.add_argument('--no-hysteresis', action='store_true',
                        help='Publish this snapshot as it is and forget what was waiting. For '
                             'a regeneration by hand after a change of the rules.')
    parser.add_argument('--report', default=None, help='Write what changed as JSON here.')
    parser.add_argument('--summary', default=None,
                        help='Write what changed as Markdown here (the pull request body).')
    parser.add_argument('--allow-drift', action='store_true',
                        help='Generate even if a curated ASN drifted from its expected '
                             'holder (default: fail closed). Drifted ASNs are still emitted.')
    parser.add_argument('--snapshot-date', default=None,
                        help='Snapshot date stamped in the generated header (default: today UTC).')
    args = parser.parse_args()
    snapshot_date = args.snapshot_date or datetime.now(timezone.utc).date().isoformat()

    # The files first: they are checked offline, before any lookup, and nothing
    # is derived from a file that fails.
    try:
        sources = verify_inputs(
            Path(args.ripe), Path(args.iptoasn), Path(args.iptoasn6),
            md5=Path(args.ripe_md5) if args.ripe_md5 else None,
            manifest_path=Path(args.manifest) if args.manifest else None,
            today=snapshot_date)
    except InputError as e:
        print(f'INPUT REFUSED: {e}', file=sys.stderr)
        sys.exit(EXIT_INPUT)
    print(f'  Sources verified: RIPE {sources["ripe"]["date"]}, '
          f'IPtoASN {sources["iptoasn_v4"]["rows"]:,} v4 + {sources["iptoasn_v6"]["rows"]:,} v6 rows')
    if args.verify_only:
        return
    if not args.output:
        parser.error('--output is required unless --verify-only')

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

    # Classes confined to the space registered in some countries (see REGIONS).
    registered = {"v4": {}, "v6": {}}
    for cls, countries in region.get("registered_in", {}).items():
        space = parse_ripe_delegated(Path(args.ripe), countries)
        for f in ("v4", "v6"):
            registered[f][cls] = merge_same_class(space[f])

    def observe(roles: dict[int, str]) -> dict[str, list[Range]]:
        """The table this snapshot gives for a curated list."""
        return {f: build_family(by_asn, roles, ripe[f], region["baseline_class"], registered[f])
                for f, by_asn in (("v4", role_v4), ("v6", role_v6))}

    observed = observe(asn_to_class)
    v4, v6 = observed["v4"], observed["v6"]
    print(f'  Observed: {len(v4)} v4 + {len(v6)} v6 non-overlapping ranges')

    if not v4 and not v6:
        print('ERROR: no ranges produced', file=sys.stderr)
        sys.exit(EXIT_NO_RANGES)

    previous = Path(args.previous or args.output)
    old = parse_rust_table(previous) if previous.exists() else None
    state_path = Path(args.state) if args.state else Path(args.output).with_suffix(".pending.json")

    # The published table follows the snapshots with a delay (see "Hysteresis").
    # The first table of a region, and a regeneration by hand with
    # --no-hysteresis, are the snapshot itself.
    if old is None or args.no_hysteresis:
        refresh = Refresh(observed, {"v4": [], "v6": []}, [], [], [])
    else:
        try:
            last_curated, pending = load_state(state_path, args.region)
        except (InputError, KeyError, ValueError) as e:
            print(f'INPUT REFUSED: state file {state_path}: {e}', file=sys.stderr)
            sys.exit(EXIT_INPUT)
        curation = None
        if last_curated is not None and last_curated != asn_to_class:
            # ASNs removed from the list, or given another role, since the last
            # refresh: what they announce today is re-labelled today. An ASN that
            # was added waits like any other observation.
            kept = {asn: asn_to_class[asn] for asn in last_curated if asn in asn_to_class}
            before, after = observe(last_curated), observe(kept)
            curation = {f: diff_family(before[f], after[f], f) for f in ("v4", "v6")}
            print(f'  Curated list changed: {sum(len(c) for c in curation.values())} runs '
                  f're-labelled at once')
        # A published range of a confined class outside its registered space
        # does not wait either (see confine_family).
        strays = {f: confine_family(old[f], observed[f], registered[f], f) for f in ("v4", "v6")}
        if any(strays.values()):
            print(f'  Outside their registered space: {sum(len(c) for c in strays.values())} '
                  f'runs re-labelled at once')
        base = {f: patch_family(old[f], strays[f]) for f in ("v4", "v6")}
        pending = {f: without(pending[f], strays[f]) for f in ("v4", "v6")}
        refresh = settle(base, observed, pending, snapshot_date, curation)
        refresh.curation = [c for f in ("v4", "v6") for c in strays[f]] + refresh.curation
        print(f'  Hysteresis: {len(refresh.applied)} runs published after waiting, '
              f'{sum(len(q) for q in refresh.pending.values())} waiting, '
              f'{len(refresh.went_back)} went back')
    new = refresh.table
    v4, v6 = new["v4"], new["v6"]
    print(f'  To publish: {len(v4)} v4 + {len(v6)} v6 ranges')
    describer = Describer(
        {"v4": load_origins(Path(args.iptoasn), "v4"), "v6": load_origins(Path(args.iptoasn6), "v6")},
        load_registry(Path(args.ripe)))
    changes = ([c for f in ("v4", "v6") for c in diff_family(old[f], new[f], f)]
               if old else [])
    budget = (check_budget(old, new, region["baseline_class"], describer)
              if old else Budget([], []))
    for asn in unannounced_asns(asn_to_class, role_v4):
        budget.review.append(f"AS{asn} ({asn_to_expected[asn]}) is curated as "
                             f"{asn_to_class[asn]} and originates no IPv4 range in this snapshot")
    refused = bool(budget.refuse) and not args.allow_over_budget

    if args.report:
        Path(args.report).write_text(json.dumps({
            "region": args.region,
            "snapshot_date": snapshot_date,
            "sources": sources,
            "review": budget.review,
            "refuse": budget.refuse,
            "changes": [{
                "family": c.family, "block": format_block(c.family, c.start, c.end),
                "addresses": c.size, "from": c.old, "to": c.new,
                "announced_by": describer.announced_by(c),
                "registered_in": describer.registered_in(c),
            } for c in changes],
            "waiting": sum(len(q) for q in refresh.pending.values()),
            "published_after_waiting": len(refresh.applied),
            "went_back": len(refresh.went_back),
            "relabelled_by_curation": len(refresh.curation),
            "needs_review": bool(budget.review or budget.refuse),
            "refused": refused,
        }, indent=2) + "\n")
    if args.summary:
        Path(args.summary).write_text(render_summary(
            region, sources, old, new, budget, changes, describer,
            refresh if old is not None else None))

    for line in budget.review:
        print(f'  REVIEW: {line}')
    if budget.refuse:
        print('\nOVER BUDGET: the refresh moves a class by more than '
              f'{REFUSE_CLASS_SHARE:.0%}:', file=sys.stderr)
        for line in budget.refuse:
            print(f'  {line}', file=sys.stderr)
        if refused:
            print('\nRefusing to write the table. If the curated ASN list was edited, this '
                  'is expected: rerun by hand with --allow-over-budget and review the result.',
                  file=sys.stderr)
            sys.exit(EXIT_OVER_BUDGET)
        print('\n--allow-over-budget set: writing it anyway.', file=sys.stderr)

    Path(args.output).write_text(generate_rust(v4, v6, region, snapshot_date))
    state_path.write_text(dump_state(args.region, snapshot_date, asn_to_class, refresh.pending))
    print(f'  Written to {args.output} and {state_path}')


if __name__ == '__main__':
    main()
