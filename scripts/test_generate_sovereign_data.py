#!/usr/bin/env python3
"""Offline unit tests for the sovereign data generator.

Network-free ON PURPOSE: the live RIPEstat call runs only in the scheduled
generation job. These tests pin, without touching the network:

  * the holder matcher, against RECORDED holder fixtures (accent handling,
    noise words, drift detection);
  * the input integrity checks, against small source files built here with
    each fault a download can have;
  * the address-level diff of two tables and the change budget.

Addresses and ASNs in the fixtures are the documentation ones (RFC 5737,
RFC 3849, RFC 5398) wherever the checks leave a choice.

    python3 scripts/test_generate_sovereign_data.py     (or pytest)
"""

import contextlib
import hashlib
import io
import ipaddress
import json
import random
import tempfile
import importlib.util
import pathlib
import sys

# Load the generator as a module (its name matters for @dataclass under
# `from __future__ import annotations`, hence the sys.modules registration).
_PATH = pathlib.Path(__file__).with_name("generate_sovereign_data.py")
_spec = importlib.util.spec_from_file_location("generate_sovereign_data", _PATH)
gsd = importlib.util.module_from_spec(_spec)
sys.modules["generate_sovereign_data"] = gsd
_spec.loader.exec_module(gsd)

# Recorded RIPEstat `data.holder` values (snapshot 2026-08-31) — fixtures, so
# the matcher is exercised without the network.
LIVE = {
    3269: "ASN-IBSNAZ Telecom Italia S.p.A.",
    3352: "Telefonica_de_EspaNa TELEFONICA DE ESPANA S.A.U.",
    137: "ASGARR Consortium GARR",
    30722: "VODAFONE-IT-ASN Fastweb SpA",
    31034: "ARUBA-ASN Aruba S.p.A.",
    # Drifted — the live holder no longer matches the old curated name:
    21479: "ROSTOV-TELEGRAF-AS PJSC Rostelecom",  # curated Iliad → Russia
    47541: "VKONTAKTE-SPB-AS LLC VK",  # curated VHosting → Russia
    5535: "Food And Agriculture Organization of the United Nations",  # Lepida → FAO
    41336: "HITRONET-AS Financijska agencija",  # PosteMobile → Croatia gov
}


def test_legit_holders_match():
    assert gsd.holder_matches("Telecom Italia", LIVE[3269])
    assert gsd.holder_matches("Telefonica", LIVE[3352])  # accent + case folded
    assert gsd.holder_matches("GARR", LIVE[137])
    assert gsd.holder_matches("Aruba", LIVE[31034])
    assert gsd.holder_matches("Vodafone", LIVE[30722])  # matches the AS-name token


def test_drifted_holders_do_not_match():
    assert not gsd.holder_matches("Iliad Italia", LIVE[21479])
    assert not gsd.holder_matches("VHosting", LIVE[47541])
    assert not gsd.holder_matches("Lepida", LIVE[5535])
    assert not gsd.holder_matches("PosteMobile", LIVE[41336])


def test_require_all_rejects_partial_overlap():
    # The match requires EVERY significant expected token. Two holders that share
    # only one token do NOT match — this is what stops a reassignment from
    # validating on a coincidental overlap.
    # Different IT holders sharing only "italia":
    assert not gsd.holder_matches("Vodafone Italia", "Fastweb Italia S.p.A.")
    # A generic distinctive token is not enough on its own: a curated
    # "Telecom Italia" must not validate against an unrelated "Telecom X".
    assert not gsd.holder_matches("Telecom Italia", "Telecom Argentina S.A.")
    # The full expected name in the live holder does match.
    assert gsd.holder_matches("Telecom Italia", "ASN-IBSNAZ Telecom Italia S.p.A.")
    assert gsd.holder_matches("A1 Telekom Austria", "A1TELEKOM-AT A1 Telekom Austria AG")


def test_empty_expected_never_matches():
    # An expected name that reduces to no significant tokens (all noise) is a
    # curation error — it must fail closed, never trivially pass.
    assert not gsd.holder_matches("S.p.A.", "Anything Holder Ltd")


def test_accent_and_legal_form_are_normalized():
    assert gsd._tokens("Telefónica") == gsd._tokens("TELEFONICA")
    # Legal-form suffixes carry no identity.
    assert gsd._tokens("Aruba S.p.A.") == {"aruba"}


# ── Fixtures for the source files ────────────────────────────────────────────

V4, V6 = ipaddress.IPv4Address, ipaddress.IPv6Address


@contextlib.contextmanager
def workdir():
    with tempfile.TemporaryDirectory() as d:
        yield pathlib.Path(d)


@contextlib.contextmanager
def patched(**values):
    """Set attributes of the generator module for the length of a test."""
    saved = {k: getattr(gsd, k) for k in values}
    for k, v in values.items():
        setattr(gsd, k, v)
    try:
        yield
    finally:
        for k, v in saved.items():
            setattr(gsd, k, v)


def small_tables():
    """Lift the full-table floors: the fixtures have a handful of rows."""
    return patched(IPTOASN_MIN_ROWS={"v4": 1, "v6": 1}, IPTOASN_MIN_ASNS={"v4": 1, "v6": 1})


def refused(fn, *args, **kwargs) -> str:
    """The message of the InputError `fn` raises; fails if it raises none."""
    try:
        fn(*args, **kwargs)
    except gsd.InputError as e:
        return str(e)
    raise AssertionError(f"{fn.__name__} accepted a file it must refuse")


RIPE_RECORDS = [
    "ripencc|IT|ipv4|192.0.2.0|256|20100101|allocated",
    "ripencc|FR|ipv4|198.51.100.0|256|20100101|assigned",
    "ripencc|IT|ipv6|2001:db8::|32|20100101|allocated",
    "ripencc|DE|asn|64496|1|20100101|allocated",
]


def ripe_text(records=RIPE_RECORDS, date="20261004", declared=None, summary=None):
    count = {k: sum(1 for r in records if r.split("|")[2] == k) for k in ("ipv4", "asn", "ipv6")}
    count.update(summary or {})
    total = len(records) if declared is None else declared
    return "\n".join([
        f"2|ripencc|1791151199|{total}|19700101|{date}|+0200",
        f"ripencc|*|ipv4|*|{count['ipv4']}|summary",
        f"ripencc|*|asn|*|{count['asn']}|summary",
        f"ripencc|*|ipv6|*|{count['ipv6']}|summary",
        *records,
    ]) + "\n"


def iptoasn_text(rows, addr):
    return "".join(f"{addr(s)}\t{addr(e)}\t{asn}\tZZ\tfixture\n" for s, e, asn in rows)


def v4_rows():
    """A whole IPv4 table in five rows: 1.0.0.0 to 223.255.254.255, no hole."""
    cut = [int(V4(x)) for x in ("1.0.0.0", "192.0.2.0", "192.0.3.0", "198.51.100.0",
                                "198.51.101.0", "223.255.255.0")]
    asns = [0, 64496, 0, 64497, 0]
    return [(cut[i], cut[i + 1] - 1, asns[i]) for i in range(5)]


def v6_rows():
    """A whole IPv6 table: the reserved low space with its hole, then 2000::/3
    onwards to the end with no hole."""
    return [
        (0, 1, 0),
        (int(V6("64:ff9b::1:0:0")), int(V6("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff")), 0),
        (int(V6("2001:db8::")), int(V6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")), 64496),
        (int(V6("2001:db9::")), (1 << 128) - 1, 0),
    ]


# ── RIPE delegated stats ─────────────────────────────────────────────────────

def test_ripe_sound_file_reports_its_date_and_counts():
    with workdir() as d:
        (d / "ripe").write_text(ripe_text())
        got = gsd.verify_ripe(d / "ripe", today="2026-10-05")
    assert got == {"date": "2026-10-04", "records": {"ipv4": 2, "ipv6": 1, "asn": 1},
                   "md5_checked": False}


def test_ripe_error_page_is_refused():
    with workdir() as d:
        (d / "ripe").write_text("<html><body>503 Service Unavailable</body></html>\n")
        assert "not a version-2 ripencc header" in refused(gsd.verify_ripe, d / "ripe")
        (d / "ripe").write_text("")
        assert "no header" in refused(gsd.verify_ripe, d / "ripe")


def test_ripe_truncated_file_is_refused_by_its_own_counts():
    whole = ripe_text()
    with workdir() as d:
        # The last record is gone: the summary still announces it.
        (d / "ripe").write_text(whole[:whole.rindex("ripencc|DE|asn")])
        assert "0 asn records, the file's own summary says 1" in refused(
            gsd.verify_ripe, d / "ripe", today="2026-10-05")
        # Cut in the middle of a record.
        (d / "ripe").write_text(whole[:-20])
        assert "is not a record" in refused(gsd.verify_ripe, d / "ripe", today="2026-10-05")


def test_ripe_header_must_be_a_version_2_ripencc_one():
    with workdir() as d:
        for bad in (("2|ripencc|", "3|ripencc|"), ("2|ripencc|", "2|arin|")):
            (d / "ripe").write_text(ripe_text().replace(*bad))
            assert "not a version-2 ripencc header" in refused(
                gsd.verify_ripe, d / "ripe", today="2026-10-05")


def test_ripe_header_total_must_match():
    with workdir() as d:
        (d / "ripe").write_text(ripe_text(declared=5))
        assert "4 records, the header says 5" in refused(
            gsd.verify_ripe, d / "ripe", today="2026-10-05")
        (d / "ripe").write_text(ripe_text(declared=3))
        assert "4 records, the header says 3" in refused(
            gsd.verify_ripe, d / "ripe", today="2026-10-05")
        # Fewer records than a summary line announces, and more.
        (d / "ripe").write_text(ripe_text(summary={"ipv6": 2}))
        assert "1 ipv6 records" in refused(gsd.verify_ripe, d / "ripe", today="2026-10-05")
        (d / "ripe").write_text(ripe_text(summary={"ipv4": 1}))
        assert "2 ipv4 records, the file's own summary says 1" in refused(
            gsd.verify_ripe, d / "ripe", today="2026-10-05")


def test_ripe_md5_is_checked_when_given():
    text = ripe_text()
    digest = hashlib.md5(text.encode()).hexdigest()
    with workdir() as d:
        (d / "ripe").write_text(text)
        # RIPE's own format, and a bare digest.
        for published in (f"MD5 (delegated-ripencc-latest) = {digest}", digest + "\n"):
            (d / "md5").write_text(published)
            gsd.verify_ripe(d / "ripe", d / "md5", today="2026-10-05")
        # One country code changed: every count still adds up, the digest does not.
        (d / "ripe").write_text(text.replace("|FR|", "|IT|"))
        gsd.verify_ripe(d / "ripe", today="2026-10-05")
        assert "MD5 is" in refused(gsd.verify_ripe, d / "ripe", d / "md5", today="2026-10-05")
        (d / "md5").write_text("no digest here")
        assert "holds no MD5" in refused(gsd.verify_ripe, d / "ripe", d / "md5")


def test_ripe_older_than_a_week_is_refused():
    with workdir() as d:
        (d / "ripe").write_text(ripe_text(date="20261004"))
        gsd.verify_ripe(d / "ripe", today="2026-10-11")  # 7 days: still accepted
        assert "8 days before 2026-10-12" in refused(
            gsd.verify_ripe, d / "ripe", today="2026-10-12")
        (d / "ripe").write_text(ripe_text(date="tomorrow"))
        assert "is not a date" in refused(gsd.verify_ripe, d / "ripe", today="2026-10-05")


# ── IPtoASN ──────────────────────────────────────────────────────────────────

def check_v4(rows):
    with workdir() as d:
        (d / "v4").write_text(iptoasn_text(rows, V4))
        return gsd.verify_iptoasn(d / "v4", "v4")


def check_v6(rows):
    with workdir() as d:
        (d / "v6").write_text(iptoasn_text(rows, V6))
        return gsd.verify_iptoasn(d / "v6", "v6")


def test_iptoasn_whole_tables_pass():
    with small_tables():
        assert check_v4(v4_rows()) == {"rows": 5, "asns": 2}
        # The hole below 2000::/3 is how the real file is built.
        assert check_v6(v6_rows()) == {"rows": 4, "asns": 1}


def test_iptoasn_truncated_table_is_refused():
    with small_tables():
        assert "before 223.0.0.0/8 (truncated)" in refused(check_v4, v4_rows()[:-1])
        assert "not at the end of the address space" in refused(check_v6, v6_rows()[:-1])
        assert "empty file" in refused(check_v4, [])
        # Reaching 223.0.0.0 is enough: the file ends at its last announced prefix.
        rows = v4_rows()
        rows[-1] = (rows[-1][0], int(V4("223.0.0.0")), 0)
        check_v4(rows)
        rows[-1] = (rows[-1][0], int(V4("222.255.255.255")), 0)
        assert "truncated" in refused(check_v4, rows)


def test_iptoasn_missing_head_is_refused():
    with small_tables():
        assert "not inside 1.0.0.0/8" in refused(check_v4, v4_rows()[1:])
        assert "not at ::" in refused(check_v6, v6_rows()[1:])


def test_iptoasn_hole_is_refused():
    with small_tables():
        rows = v4_rows()
        assert "192.0.2.0 to 192.0.2.255 is missing" in refused(check_v4, rows[:1] + rows[2:])
        rows = v6_rows()
        assert "2001:db8:: to 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff is missing" in refused(
            check_v6, rows[:2] + rows[3:])
        # A hole that reaches into 2000::/3 from below is not the built-in one.
        rows = v6_rows()
        rows[1] = (rows[1][0], int(V6("1fff::")), 0)
        assert "is missing" in refused(check_v6, rows)


def test_iptoasn_disorder_and_garbage_are_refused():
    with small_tables():
        rows = v4_rows()
        assert "out of order" in refused(check_v4, rows[:2] + rows[1:])  # a row twice
        refused(check_v4, [rows[0], rows[2], rows[1]] + rows[3:])        # two rows swapped
        rows = v4_rows()
        rows[1] = (rows[1][0] - 1, rows[1][1], 64496)  # overlaps the row before
        assert "overlaps" in refused(check_v4, rows)
        rows = v4_rows()
        rows[1] = (rows[1][1], rows[1][0], 64496)
        assert "ends before it starts" in refused(check_v4, rows)
    with small_tables(), workdir() as d:
        text = iptoasn_text(v4_rows(), V4)
        (d / "v4").write_text(text.replace("\t64497\t", "\tAS64497\t"))
        assert "line 4 does not parse" in refused(gsd.verify_iptoasn, d / "v4", "v4")
        (d / "v4").write_text(text.replace("\tZZ\tfixture\n", "\n", 1))
        assert "fewer than 5 columns" in refused(gsd.verify_iptoasn, d / "v4", "v4")
        (d / "v4").write_text("<html>503</html>\n")
        assert "line 1 does not parse" in refused(gsd.verify_iptoasn, d / "v4", "v4")


def test_iptoasn_well_formed_but_small_table_is_refused():
    # The real floors: a table that is whole in shape and far too small.
    assert "fewer than 300000 (not a full table)" in refused(check_v4, v4_rows())
    assert "fewer than 100000 (not a full table)" in refused(check_v6, v6_rows())
    with patched(IPTOASN_MIN_ROWS={"v4": 1, "v6": 1}):
        assert "2 origin ASNs, fewer than 60000" in refused(check_v4, v4_rows())
    with patched(IPTOASN_MIN_ROWS={"v4": 5, "v6": 1}, IPTOASN_MIN_ASNS={"v4": 2, "v6": 1}):
        check_v4(v4_rows())  # exactly at the floors


# ── The manifest of the download ─────────────────────────────────────────────

def manifest_row(path, modified="Mon, 05 Oct 2026 19:52:59 GMT"):
    raw = path.read_bytes()
    return f"{path.name}\thttps://example.net/{path.name}\t{modified}\t{len(raw)}\t" \
           f"{hashlib.sha256(raw).hexdigest()}\n"


def test_manifest_pins_the_downloaded_file():
    with workdir() as d:
        f = d / "ip2asn-v4.tsv"
        f.write_text("data\n")
        (d / "SOURCES.tsv").write_text(manifest_row(f))
        m = gsd.load_manifest(d / "SOURCES.tsv")
        assert gsd.verify_against_manifest(f, m, "2026-10-05")["bytes"] == 5
        f.write_text("dat4\n")  # same size, other content
        assert "not the file the manifest describes" in refused(
            gsd.verify_against_manifest, f, m, "2026-10-05")
        f.write_text("data\nmore\n")
        assert "not the file the manifest describes" in refused(
            gsd.verify_against_manifest, f, m, "2026-10-05")
        assert "no entry for other.tsv" in refused(
            gsd.verify_against_manifest, d / "other.tsv", m, "2026-10-05")
        (d / "SOURCES.tsv").write_text("three\tcolumns\tonly\n")
        assert "not five columns" in refused(gsd.load_manifest, d / "SOURCES.tsv")


def test_manifest_refuses_a_stale_file():
    with workdir() as d:
        f = d / "ip2asn-v4.tsv"
        f.write_text("data\n")
        (d / "SOURCES.tsv").write_text(manifest_row(f))
        m = gsd.load_manifest(d / "SOURCES.tsv")
        gsd.verify_against_manifest(f, m, "2026-10-12")  # 7 days
        assert "8 days before 2026-10-13" in refused(
            gsd.verify_against_manifest, f, m, "2026-10-13")
        # A server that sent no Last-Modified leaves the column empty.
        (d / "SOURCES.tsv").write_text(manifest_row(f, modified=""))
        m = gsd.load_manifest(d / "SOURCES.tsv")
        assert "no usable Last-Modified" in refused(
            gsd.verify_against_manifest, f, m, "2026-10-05")


# ── Reading a table back, and the diff of two tables ─────────────────────────

CLASSES = ["GovIta", "ResidentialIta", "DatacenterIta"]


def random_table(rng, space=400, classes=CLASSES, merged=True):
    """Sorted, non-overlapping ranges over 0..space. `merged` joins adjacent
    ranges of one class, as the generator emits them; without it a class can
    run across several touching rows, as in a table written by hand."""
    out, at = [], rng.randrange(0, 20)
    while at < space:
        end = min(space, at + rng.randrange(0, 30))
        out.append(gsd.Range(at, end, rng.choice(classes)))
        at = end + 1 + rng.randrange(0, 2) * rng.randrange(1, 25)
    return gsd.merge_same_class(out) if merged else out


def class_at(table, ip):
    return next((r.ip_class for r in table if r.start <= ip <= r.end), None)


def test_generated_table_reads_back_identical():
    rng = random.Random(568)
    region = gsd.REGIONS["ita"]
    for _ in range(20):
        v4 = random_table(rng)
        v6 = [gsd.Range(r.start << 100, (r.end << 100) | ((1 << 100) - 1), r.ip_class)
              for r in random_table(rng)]
        with workdir() as d:
            (d / "t.rs").write_text(gsd.generate_rust(v4, v6, region, "2026-10-05"))
            got = gsd.parse_rust_table(d / "t.rs")
        key = lambda t: [(r.start, r.end, r.ip_class) for r in t]
        assert key(got["v4"]) == key(v4) and key(got["v6"]) == key(v6)


def test_diff_agrees_with_a_brute_force_comparison():
    rng = random.Random(2026)
    for i in range(400):
        merged = i % 2 == 0
        old, new = random_table(rng, merged=merged), random_table(rng, merged=merged)
        changes = gsd.diff_family(old, new, "v4")
        covered = {}
        for c in changes:
            assert c.old != c.new and c.start <= c.end
            for ip in range(c.start, c.end + 1):
                assert ip not in covered
                covered[ip] = (c.old, c.new)
        for ip in range(0, 440):
            a, b = class_at(old, ip), class_at(new, ip)
            assert covered.get(ip) == ((a, b) if a != b else None), (ip, a, b)
        # In address order, and no two neighbours that should have been one.
        for x, y in zip(changes, changes[1:]):
            assert x.end < y.start
            assert not (x.end + 1 == y.start and (x.old, x.new) == (y.old, y.new))


def test_diff_of_a_table_with_itself_is_empty():
    rng = random.Random(1)
    t = random_table(rng)
    assert gsd.diff_family(t, t, "v4") == []
    assert gsd.diff_family([], [], "v4") == []
    assert [(c.start, c.end, c.old, c.new) for c in gsd.diff_family([], t[:1], "v4")] == [
        (t[0].start, t[0].end, None, t[0].ip_class)]


def test_blocks_and_sizes_read_like_a_person_writes_them():
    assert gsd.format_block("v4", int(V4("145.152.0.0")), int(V4("145.159.255.255"))) \
        == "145.152.0.0/13"
    assert gsd.format_block("v4", int(V4("90.88.0.0")), int(V4("90.88.191.255"))) \
        == "90.88.0.0-90.88.191.255"
    assert gsd.format_block("v6", int(V6("2001:db8::")),
                            int(V6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"))) == "2001:db8::/32"
    assert gsd.format_size("v4", 524288) == "524,288 addresses"
    assert gsd.format_size("v6", 1 << 96) == "65,536 /48s"
    assert gsd.format_size("v6", 1 << 64) == "less than a /48"


# ── The change budget ────────────────────────────────────────────────────────

def table(*ranges):
    return {"v4": [gsd.Range(*r) for r in ranges], "v6": []}


BIG = 100_000_000  # a class large enough that one block is a small share of it


def test_a_quiet_refresh_is_within_budget():
    old = table((0, BIG - 1, "ResidentialIta"))
    b = gsd.check_budget(old, old, None)
    assert b.review == [] and b.refuse == []
    # A /19 comes and goes without a word.
    new = table((0, BIG - 1 - (1 << 13), "ResidentialIta"))
    b = gsd.check_budget(old, new, None)
    assert b.review == [] and b.refuse == []


def test_a_class_moving_by_more_than_two_percent_needs_a_look():
    old = table((0, 9_999, "GovIta"))
    assert gsd.check_budget(old, table((0, 9_799, "GovIta")), None).review == []  # -2.0 %
    b = gsd.check_budget(old, table((0, 9_798, "GovIta")), None)
    assert b.refuse == [] and b.review == [
        "IPv4 class GovIta goes from 10,000 addresses to 9,799 addresses (-2.0%)"]
    b = gsd.check_budget(old, table((0, 10_200, "GovIta")), None)  # growth counts too
    assert len(b.review) == 1 and "+2.0%" in b.review[0]


def test_a_class_moving_by_more_than_a_fifth_is_refused():
    old = table((0, 9_999, "GovIta"))
    b = gsd.check_budget(old, table((0, 7_999, "GovIta")), None)  # -20.0 %: review
    assert b.refuse == [] and len(b.review) == 1
    b = gsd.check_budget(old, table((0, 7_998, "GovIta")), None)
    assert b.refuse == ["IPv4 class GovIta goes from 10,000 addresses to 7,999 addresses (-20.0%)"]
    # A class that vanishes, and one that doubles.
    assert len(gsd.check_budget(old, table(), None).refuse) == 1
    assert len(gsd.check_budget(old, table((0, 19_999, "GovIta")), None).refuse) == 1


def test_a_new_class_needs_a_look():
    old = table((0, 9_999, "GovIta"))
    new = table((0, 9_999, "GovIta"), (20_000, 20_099, "DatacenterIta"))
    b = gsd.check_budget(old, new, None)
    assert b.refuse == [] and b.review == ["IPv4 class DatacenterIta is new (100 addresses)"]


def test_a_large_block_entering_or_leaving_a_role_class_needs_a_look():
    s = int(V4("145.152.0.0"))
    old = table((0, BIG - 1, "Eu"), (s, s + (1 << 14) - 1, "GovEu"), (s + (1 << 20), s + (1 << 25), "GovEu"))
    # A /18 falls back to the baseline.
    new = table((0, BIG - 1, "Eu"), (s, s + (1 << 14) - 1, "Eu"), (s + (1 << 20), s + (1 << 25), "GovEu"))
    b = gsd.check_budget({"v4": gsd.merge_same_class(old["v4"]), "v6": []},
                         {"v4": gsd.merge_same_class(new["v4"]), "v6": []}, "Eu")
    assert b.review == ["145.152.0.0/18 (16,384 addresses) moves from GovEu to Eu"], b.review
    # The same block in the other direction.
    b = gsd.check_budget({"v4": gsd.merge_same_class(new["v4"]), "v6": []},
                         {"v4": gsd.merge_same_class(old["v4"]), "v6": []}, "Eu")
    assert b.review == ["145.152.0.0/18 (16,384 addresses) moves from Eu to GovEu"]
    # One address short of a /18 is not a block.
    short = table((0, BIG - 1, "Eu"), (s, s, "GovEu"), (s + 1, s + (1 << 14) - 1, "Eu"),
                  (s + (1 << 20), s + (1 << 25), "GovEu"))
    b = gsd.check_budget({"v4": gsd.merge_same_class(old["v4"]), "v6": []},
                         {"v4": gsd.merge_same_class(short["v4"]), "v6": []}, "Eu")
    assert b.review == []


def test_the_registry_baseline_is_held_to_the_share_only():
    # A /16 leaves the EU baseline for no class: registry data, not one BGP
    # snapshot. It is 0.07 % of the class and passes.
    old = table((0, BIG - 1, "Eu"))
    new = table((0, BIG - 1 - (1 << 16), "Eu"))
    assert gsd.check_budget(old, new, "Eu").review == []
    # Without a baseline (the Italian table) every class is a role class.
    assert gsd.check_budget(table((0, BIG - 1, "GovIta")),
                            table((0, BIG - 1 - (1 << 16), "GovIta")), None).review == [
        "5.244.225.0-5.245.224.255 (65,536 addresses) moves from GovIta to no class"]


def test_the_block_rule_in_ipv6_is_a_slash_32():
    base = int(V6("2a00::"))
    big = (base, base + (1 << 110) - 1, "DatacenterEu")
    hole = int(V6("2a0f:e204::"))
    old = {"v4": [], "v6": [gsd.Range(*big)]}
    new = {"v4": [], "v6": [gsd.Range(*big), gsd.Range(hole, hole + (1 << 96) - 1, "DatacenterEu")]}
    assert gsd.check_budget(old, new, "Eu").review == [
        "2a0f:e204::/32 (65,536 /48s) moves from no class to DatacenterEu"]
    new = {"v4": [], "v6": [gsd.Range(*big), gsd.Range(hole, hole + (1 << 95) - 1, "DatacenterEu")]}
    assert gsd.check_budget(old, new, "Eu").review == []


def test_curated_asns_that_announce_nothing_are_named():
    roles = {64496: "GovIta", 64497: "ResidentialIta", 64498: "DatacenterIta"}
    announced = {64496: [gsd.Range(0, 255, "Unknown")], 64498: []}
    assert gsd.unannounced_asns(roles, announced) == [64497, 64498]


# ── The generator, end to end ────────────────────────────────────────────────

TEST_REGION = {
    "module": "data_ita", "adjective": "Italian", "countries": {"IT"},
    "baseline_class": None,
    "asn_roles": [({64496: "Example"}, "GovIta"), ({64497: "Example"}, "ResidentialIta")],
}


def write_sources(d, ripe=None, v4=None, v6=None):
    (d / "ripe").write_text(ripe or ripe_text())
    (d / "v4").write_text(iptoasn_text(v4 or v4_rows(), V4))
    (d / "v6").write_text(iptoasn_text(v6 or v6_rows(), V6))


def run_generator(d, *extra, write=True, **sources):
    """Run main() on fixture files in `d`. Returns (exit code, stderr, lookups)."""
    if write:
        write_sources(d, **sources)
    lookups = []

    def holder(asn, timeout=15):
        lookups.append(asn)
        return "EXAMPLE-AS Example Org"

    argv = ["gen", "--region", "ita", "--ripe", str(d / "ripe"), "--iptoasn", str(d / "v4"),
            "--iptoasn6", str(d / "v6"), "--snapshot-date", "2026-10-05", *extra]
    err, code = io.StringIO(), 0
    with small_tables(), patched(REGIONS={"ita": TEST_REGION}, fetch_holder=holder), \
            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        saved, sys.argv = sys.argv, argv
        saved_sleep, gsd.time.sleep = gsd.time.sleep, lambda s: None
        try:
            gsd.main()
        except SystemExit as e:
            code = e.code
        finally:
            sys.argv, gsd.time.sleep = saved, saved_sleep
    return code, err.getvalue(), lookups


def test_generator_writes_table_report_and_summary():
    with workdir() as d:
        out, rep, summ = d / "data.rs", d / "report.json", d / "summary.md"
        code, _, lookups = run_generator(d, "--output", str(out), "--report", str(rep),
                                         "--summary", str(summ))
        assert code == 0 and lookups == [64496, 64497]
        got = gsd.parse_rust_table(out)
        assert [(str(V4(r.start)), r.ip_class) for r in got["v4"]] == [
            ("192.0.2.0", "GovIta"), ("198.51.100.0", "ResidentialIta")]
        report = json.loads(rep.read_text())
        assert report["refused"] is False and report["needs_review"] is False
        assert report["sources"]["ripe"]["date"] == "2026-10-04"
        assert "| 4 records, counts checked |" in summ.read_text()  # no --ripe-md5 here
        # A second run on the same sources changes nothing and says so.
        code, _, _ = run_generator(d, "--output", str(out), "--report", str(rep),
                                   "--summary", str(summ))
        report = json.loads(rep.read_text())
        assert code == 0 and report["review"] == [] and "| `GovIta` | 256 | 256 | +0.00% |" in summ.read_text()


def test_generator_refuses_a_refresh_over_budget_and_keeps_the_old_table():
    with workdir() as d:
        out, rep = d / "data.rs", d / "report.json"
        assert run_generator(d, "--output", str(out))[0] == 0
        before = out.read_text()
        # AS64497 stops announcing: its class empties.
        rows = [(s, e, 0 if asn == 64497 else asn) for s, e, asn in v4_rows()]
        code, err, _ = run_generator(d, "--output", str(out), "--report", str(rep), v4=rows)
        assert code == gsd.EXIT_OVER_BUDGET and "OVER BUDGET" in err
        assert out.read_text() == before
        report = json.loads(rep.read_text())
        assert report["refused"] is True and report["needs_review"] is True
        assert report["refuse"] == [
            "IPv4 class ResidentialIta goes from 256 addresses to 0 addresses (-100.0%)"]
        assert report["review"] == [
            "AS64497 (Example) is curated as ResidentialIta and originates no IPv4 range "
            "in this snapshot"]
        # By hand, with the flag, it is written.
        code, _, _ = run_generator(d, "--output", str(out), "--allow-over-budget", v4=rows)
        assert code == 0 and out.read_text() != before


def test_generator_checks_the_files_before_any_lookup():
    damaged = [
        {"v4": v4_rows()[:-1]},
        {"v6": v6_rows()[:-1]},
        {"ripe": ripe_text(declared=9)},
    ]
    for sources in damaged:
        with workdir() as d:
            out = d / "data.rs"
            code, err, lookups = run_generator(d, "--output", str(out), **sources)
            assert code == gsd.EXIT_INPUT and "INPUT REFUSED" in err, sources
            assert lookups == [] and not out.exists()


def test_generator_checks_the_md5_and_the_manifest_it_is_given():
    with workdir() as d:
        write_sources(d)
        (d / "ripe.md5").write_text(hashlib.md5((d / "ripe").read_bytes()).hexdigest())
        (d / "SOURCES.tsv").write_text("".join(manifest_row(d / n) for n in ("ripe", "v4", "v6")))
        args = ["--output", str(d / "data.rs"), "--report", str(d / "report.json"),
                "--ripe-md5", str(d / "ripe.md5"), "--manifest", str(d / "SOURCES.tsv")]
        assert run_generator(d, *args, write=False)[0] == 0
        report = json.loads((d / "report.json").read_text())
        assert report["sources"]["iptoasn_v6"]["last_modified"] == "Mon, 05 Oct 2026 19:52:59 GMT"
        assert report["sources"]["ripe"]["md5_checked"] is True

        # Each file is held to its manifest row.
        for name in ("ripe", "v4", "v6"):
            rows = [manifest_row(d / n) for n in ("ripe", "v4", "v6")]
            (d / "SOURCES.tsv").write_text("".join(
                r.replace("05 Oct 2026", "21 Sep 2026") if r.startswith(name + "\t") else r
                for r in rows))
            code, err, _ = run_generator(d, *args, write=False)
            assert code == gsd.EXIT_INPUT and f"{name}: last modified 2026-09-21" in err, err
        (d / "SOURCES.tsv").write_text("".join(manifest_row(d / n) for n in ("ripe", "v4", "v6")))

        (d / "ripe.md5").write_text("0" * 32)
        code, err, _ = run_generator(d, *args, write=False)
        assert code == gsd.EXIT_INPUT and "MD5 is" in err


def test_help_prints():
    # argparse expands `%` in help strings: an unescaped one crashes --help.
    out = io.StringIO()
    saved, sys.argv = sys.argv, ["gen", "--help"]
    try:
        with contextlib.redirect_stdout(out):
            gsd.main()
    except SystemExit as e:
        assert e.code == 0
    finally:
        sys.argv = saved
    text = " ".join(out.getvalue().split())  # argparse wraps the lines
    assert "--allow-over-budget" in text and "more than 20 % (default: refuse)" in text


def test_verify_only_generates_nothing_and_looks_nothing_up():
    with workdir() as d:
        code, _, lookups = run_generator(d, "--verify-only")
        assert code == 0 and lookups == [] and sorted(p.name for p in d.iterdir()) == [
            "ripe", "v4", "v6"]
        code, err, _ = run_generator(d, "--verify-only", v4=v4_rows()[1:])
        assert code == gsd.EXIT_INPUT


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
