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
import datetime
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


# ── Lookups that fail, and ASNs registered in the wrong country ──────────────

@contextlib.contextmanager
def ripestat(answers):
    """Replace the live lookup: `answers[asn]` is a list consumed one item per
    attempt, each a holder name or an exception. Yields (attempts, waits)."""
    attempts, waits = [], []

    def holder(asn, timeout=15):
        attempts.append(asn)
        got = answers[asn].pop(0) if len(answers[asn]) > 1 else answers[asn][0]
        if isinstance(got, Exception):
            raise got
        return got

    saved = gsd.time.sleep
    gsd.time.sleep = waits.append
    try:
        with patched(fetch_holder=holder):
            yield attempts, waits
    finally:
        gsd.time.sleep = saved


def outcome(fn, *args, **kwargs):
    """(exit code or None, stderr) of a call that may sys.exit."""
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        try:
            fn(*args, **kwargs)
        except SystemExit as e:
            return e.code, err.getvalue()
    return None, err.getvalue()


def test_a_lookup_is_tried_again_before_it_counts_as_failed():
    down = TimeoutError("timed out")
    with ripestat({1: ["Example"]}) as (attempts, waits):
        assert gsd.fetch_holder_patiently(1) == "Example" and attempts == [1] and waits == []
    with ripestat({1: [down, down, "Example"]}) as (attempts, waits), \
            contextlib.redirect_stderr(io.StringIO()) as err:
        assert gsd.fetch_holder_patiently(1) == "Example"
        assert attempts == [1, 1, 1] and waits == [2, 6]
        assert "AS1: lookup failed (TimeoutError), trying again in 2 s" in err.getvalue()
    with ripestat({1: [down]}) as (attempts, waits), contextlib.redirect_stderr(io.StringIO()):
        try:
            gsd.fetch_holder_patiently(1)
            raise AssertionError("four failures must raise")
        except TimeoutError:
            pass
        assert attempts == [1, 1, 1, 1] and waits == [2, 6, 20]


def test_an_unreachable_lookup_is_not_called_a_drift():
    wanted = {64496: "Example", 64497: "Example"}
    down = TimeoutError("timed out")
    # One ASN answers after two failures, the other answers at once: no problem at all.
    with ripestat({64496: [down, down, "EXAMPLE-AS Example Org"], 64497: ["Example Ltd"]}):
        code, err = outcome(gsd.validate_holders, wanted)
        assert code is None and "DRIFT" not in err and "LOOKUP FAILED" not in err
    # RIPEstat down for one ASN: its own exit code, and no talk of fixing the list.
    with ripestat({64496: [down], 64497: ["Example Ltd"]}):
        code, err = outcome(gsd.validate_holders, wanted)
        assert code == gsd.EXIT_LOOKUP == 5
        assert "HOLDER LOOKUP FAILED" in err and "HOLDER DRIFT" not in err
        assert "AS64496   (Example): TimeoutError: timed out" in err
        assert "tried 4 times. This is not a drift" in err
    # A real drift: exit 2, as before.
    with ripestat({64496: ["Somebody Else"], 64497: ["Example Ltd"]}):
        code, err = outcome(gsd.validate_holders, wanted)
        assert code == gsd.EXIT_HOLDER_DRIFT == 2
        assert "HOLDER DRIFT" in err and "LOOKUP FAILED" not in err
    # Both at once: the drift decides the exit code, and both are listed.
    with ripestat({64496: ["Somebody Else"], 64497: [down]}):
        code, err = outcome(gsd.validate_holders, wanted)
        assert code == gsd.EXIT_HOLDER_DRIFT and "HOLDER DRIFT" in err and "LOOKUP FAILED" in err
    # --allow-drift carries on, and names what it carried.
    with ripestat({64496: ["Somebody Else"], 64497: [down]}), \
            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert gsd.validate_holders(wanted, allow_drift=True) == {64496, 64497}


def test_the_country_of_each_asn_is_read_from_the_bgp_table():
    with workdir() as d:
        (d / "v4").write_text("192.0.2.0\t192.0.2.255\t64496\tIT\tExample\n"
                              "192.0.3.0\t192.0.3.255\t0\tNone\tNot routed\n"
                              "198.51.100.0\t198.51.100.255\t64497\tFR\tOther\n"
                              "short\n")
        (d / "v6").write_text("2001:db8::\t2001:db8::ffff\t64498\tDE\tThird\n")
        assert gsd.asn_countries([d / "v4", d / "v6"]) == {64496: "IT", 64497: "FR", 64498: "DE"}


def test_a_curated_asn_registered_elsewhere_is_a_drift():
    ita = {"asn_countries": {"IT"}, "asn_country_exceptions": {16276: "FR"}}
    wanted = {137: "GARR", 3215: "Orange", 16276: "OVH", 99: "Silent"}
    # GARR in Italy and OVH in France are as curated; AS99 announces nothing.
    assert gsd.misplaced_asns(wanted, {137: "IT", 16276: "FR", 3215: "IT"}, ita) == []
    # The name still says Orange, the registry says Mali.
    assert gsd.misplaced_asns(wanted, {137: "IT", 16276: "FR", 3215: "ML"}, ita) == [
        (3215, "Orange", "registered in ML, expected IT")]
    # The exception names one country, not "anything foreign".
    assert gsd.misplaced_asns(wanted, {16276: "DE"}, ita) == [
        (16276, "OVH", "registered in DE, expected FR")]
    eu = {"asn_countries": gsd.EU27, "asn_country_exceptions": {}}
    assert gsd.misplaced_asns(wanted, {137: "IT", 3215: "FR", 16276: "FR"}, eu) == []
    assert gsd.misplaced_asns(wanted, {3215: "GB"}, eu) == [
        (3215, "Orange", "registered in GB, expected an EU-27 country")]
    # A region that names no country checks none.
    assert gsd.misplaced_asns(wanted, {3215: "ML"}, {}) == []
    # It stops the refresh as a drift does.
    with ripestat({a: [n] for a, n in wanted.items()}):
        code, err = outcome(gsd.validate_holders, wanted,
                            misplaced=gsd.misplaced_asns(wanted, {3215: "ML"}, ita))
        assert code == gsd.EXIT_HOLDER_DRIFT
        assert "AS3215    expected ~ 'Orange'   →   registered in ML, expected IT" in err


def test_the_real_lists_expect_the_countries_they_are_made_of():
    assert gsd.REGIONS["ita"]["asn_countries"] == {"IT"}
    assert gsd.REGIONS["ita"]["asn_country_exceptions"] == {16276: "FR"}
    assert gsd.REGIONS["eu"]["asn_countries"] == gsd.EU27
    # Every exception is an ASN on the list.
    for region in gsd.REGIONS.values():
        curated = {asn for asns, _ in region["asn_roles"] for asn in asns}
        assert set(region["asn_country_exceptions"]) <= curated


def test_coverage_counts_what_the_curated_list_leaves_out():
    # Registered at home: 0-999 and 2000-2999. Abroad: 1000-1999.
    registry = gsd.SpanIndex([(0, 999, "IT"), (1000, 1999, "FR"), (2000, 2999, "IT")])
    origins = gsd.SpanIndex([
        (0, 499, "AS1 CURATED (IT)"),
        (500, 1499, "AS2 BIG-STRANGER (IT)"),     # 500 at home, 500 abroad
        (2000, 2099, "AS3 SMALL-STRANGER (IT)"),
        (2100, 2199, "AS1 CURATED (IT)"),
        (2500, 2799, "AS4 MID-STRANGER (NL)"),
    ])
    c = gsd.curated_coverage(origins, registry, {"IT"}, {1})
    assert (c.curated, c.announced) == (600, 1500)
    assert c.missing == [("AS2 BIG-STRANGER (IT)", 500), ("AS4 MID-STRANGER (NL)", 300),
                         ("AS3 SMALL-STRANGER (IT)", 100)]
    assert gsd.curated_coverage(origins, registry, {"IT"}, {1}, keep=1).missing == [
        ("AS2 BIG-STRANGER (IT)", 500)]
    # Another country, another answer; and a country with nothing announced.
    assert gsd.curated_coverage(origins, registry, {"FR"}, {1}).announced == 500
    empty = gsd.curated_coverage(origins, registry, {"ES"}, {1})
    assert (empty.curated, empty.announced, empty.missing) == (0, 0, [])
    assert gsd.render_coverage(gsd.REGIONS["ita"], empty) == []

    lines = gsd.render_coverage(gsd.REGIONS["ita"], c)
    assert lines[0] == "### What the curated ASN list leaves out"
    assert lines[2] == ("Of the announced IPv4 addresses registered in the region, 40% are "
                        "originated by a curated ASN (600 of 1,500). The rest is not in the "
                        "table. The largest origins that are not on the list:")
    assert "| AS2 BIG-STRANGER (IT) | 500 |" in lines
    assert "The rest is `Eu`, with no role." in gsd.render_coverage(gsd.REGIONS["eu"], c)[2]


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


def test_generated_file_carries_its_date_and_its_curated_list():
    region = gsd.REGIONS["ita"]
    text = gsd.generate_rust([gsd.Range(1 << 24, (1 << 24) + 255, "GovIta")], [], region,
                             "2026-10-06")
    assert 'pub const SNAPSHOT_DATE: &str = "2026-10-06";' in text
    # Every curated ASN once, with its role, in ascending order.
    rows = [l.strip() for l in text.split("pub const CURATED_ASNS")[1].split("];")[0].splitlines()
            if l.strip().startswith("(")]
    want = sorted((asn, cls) for asns, cls in region["asn_roles"] for asn in asns)
    assert rows == [f"({asn}, IpClass::{cls})," for asn, cls in want]
    assert "(137, IpClass::GovIta)," in rows and "(31034, IpClass::DatacenterIta)," in rows
    # The table rows are still the only thing read back.
    with workdir() as d:
        (d / "t.rs").write_text(text)
        assert key(gsd.parse_rust_table(d / "t.rs")["v4"]) == [(1 << 24, (1 << 24) + 255, "GovIta")]
    for name in ("every_entry_ends_at_or_after_its_start", "no_entry_touches_reserved_space",
                 "snapshot_date_is_a_date"):
        assert f"fn {name}()" in text


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
    assert gsd.format_size("v6", 1 << 80) == "1 /48"
    assert gsd.format_size("v6", 1 << 81) == "2 /48s"


# ── Who announces a block, and where it is registered ────────────────────────

def test_span_index_agrees_with_a_brute_force_count():
    rng = random.Random(579)
    for _ in range(200):
        spans = [(r.start, r.end, r.ip_class) for r in random_table(rng, merged=False)]
        rng.shuffle(spans)  # the index sorts
        index = gsd.SpanIndex(spans)
        for _ in range(20):
            start = rng.randrange(0, 440)
            end = start + rng.randrange(0, 60)
            want = {}
            for ip in range(start, end + 1):
                label = next((l for s, e, l in spans if s <= ip <= e), None)
                want[label] = want.get(label, 0) + 1
            got = index.cover(start, end)
            assert got == want, (start, end)
            assert list(got.values()) == sorted(got.values(), reverse=True)
    assert gsd.SpanIndex([]).cover(5, 9) == {None: 5}


def test_text_from_a_source_file_cannot_become_markdown():
    assert gsd.safe_text("ASN-WINDTRE IUNET") == "ASN-WINDTRE IUNET"
    hostile = "x | [click](https://evil.example) @maintainer <img src=x> `code` **b**"
    cleaned = gsd.safe_text(hostile, limit=200)
    assert cleaned == "x click https evil.example maintainer img src x code b"
    assert not set(cleaned) & set("|[]()@<>`*:/")
    assert gsd.safe_text("a" * 60) == "a" * 39 + "…"
    assert gsd.safe_text("a" * 40) == "a" * 40
    assert gsd.safe_text("  spaced \t out\n") == "spaced out"


def test_cover_reads_as_a_sentence():
    assert gsd.format_cover({"IT": 256}, "nowhere") == "IT"
    assert gsd.format_cover({None: 256}, "not announced") == "not announced"
    assert gsd.format_cover({}, "not announced") == "not announced"
    assert gsd.format_cover({"DE": 60, "FR": 40}, "x") == "DE 60 %, FR 40 %"
    assert gsd.format_cover({"AS1 X (IT)": 75, None: 25}, "not announced") \
        == "AS1 X (IT) 75 %, not announced 25 %"
    assert gsd.format_cover({"A": 5, "B": 3, "C": 1, "D": 1}, "x") == "A 50 %, B 30 %, 2 more"


def describer_for(d):
    """A Describer over the fixture files written in `d`."""
    return gsd.Describer(
        {"v4": gsd.load_origins(d / "v4", "v4"), "v6": gsd.load_origins(d / "v6", "v6")},
        gsd.load_registry(d / "ripe"))


def test_a_block_is_described_by_its_origin_and_its_registry():
    with workdir() as d:
        write_sources(d)
        who = describer_for(d)
    block = lambda a, b, fam="v4": gsd.Change(
        fam, int((V4 if fam == "v4" else V6)(a)), int((V4 if fam == "v4" else V6)(b)), "X", None)
    c = block("192.0.2.0", "192.0.2.255")
    assert who.announced_by(c) == "AS64496 fixture (ZZ)" and who.registered_in(c) == "IT"
    # Half announced, half not; half registered in France, half nowhere in the file.
    c = block("198.51.100.128", "198.51.101.127")
    assert who.announced_by(c) == "AS64497 fixture (ZZ) 50 %, not announced 50 %"
    assert who.registered_in(c) == "FR 50 %, not in RIPE's file 50 %"
    # The address after the last one of a delegation belongs to nobody.
    c = block("192.0.2.255", "192.0.3.0")
    assert who.registered_in(c) == "IT 50 %, not in RIPE's file 50 %"
    assert who.announced_by(c) == "AS64496 fixture (ZZ) 50 %, not announced 50 %"
    c = block("203.0.113.0", "203.0.113.255")
    assert who.announced_by(c) == "not announced" and who.registered_in(c) == "not in RIPE's file"
    c = block("2001:db8::", "2001:db8::ffff", "v6")
    assert who.announced_by(c) == "AS64496 fixture (ZZ)" and who.registered_in(c) == "IT"


def test_registry_and_origin_labels_are_cleaned_on_load():
    with workdir() as d:
        (d / "ripe").write_text(ripe_text([
            "ripencc|it|ipv4|192.0.2.0|256|20100101|allocated",   # not a country code
            "ripencc|FR|ipv4|not-an-address|256|20100101|allocated",
        ]))
        (d / "v4").write_text("192.0.2.0\t192.0.2.255\t64496\tI|T\tEvil [x](y) | @you\n"
                              "short row\n")
        reg = gsd.load_registry(d / "ripe")
        assert reg["v4"].cover(int(V4("192.0.2.0")), int(V4("192.0.2.255"))) == {"??": 256}
        org = gsd.load_origins(d / "v4", "v4")
        assert list(org.cover(int(V4("192.0.2.0")), int(V4("192.0.2.9")))) == [
            "AS64496 Evil x y you (I…)"]


def test_review_lines_and_summary_say_who_and_where():
    s = int(V4("198.18.0.0"))  # RFC 2544 benchmarking space, aligned on a /18
    old = {"v4": [gsd.Range(0, BIG - 1, "Eu")], "v6": []}
    new = {"v4": [gsd.Range(0, BIG - 1, "Eu"), gsd.Range(s, s + (1 << 14) - 1, "GovEu")], "v6": []}
    who = gsd.Describer(
        {"v4": gsd.SpanIndex([(s, s + (1 << 14) - 1, "AS64496 Example (IT)")]), "v6": gsd.SpanIndex([])},
        {"v4": gsd.SpanIndex([(s, s + (1 << 13) - 1, "IT")]), "v6": gsd.SpanIndex([])})
    b = gsd.check_budget(old, new, "Eu", who)
    assert b.review == [
        "IPv4 class GovEu is new (16,384 addresses)",
        "198.18.0.0/18 (16,384 addresses) moves from no class to GovEu: "
        "AS64496 Example (IT); registered in IT 50 %, not in RIPE's file 50 %"], b.review
    # Without a describer the line stops at the classes.
    assert gsd.check_budget(old, new, "Eu").review[1] == \
        "198.18.0.0/18 (16,384 addresses) moves from no class to GovEu"
    changes = gsd.diff_family(old["v4"], new["v4"], "v4")
    lines = gsd.render_changes(changes, who)
    assert lines[0] == "### Largest IPv4 changes"
    assert lines[4] == ("| `198.18.0.0/18` | 16,384 | no class | GovEu | AS64496 Example (IT) "
                        "| IT 50 %, not in RIPE's file 50 % |")
    assert not any("IPv6" in l for l in lines)


def test_summary_lists_the_largest_changes_and_counts_the_rest():
    # Twenty separate /24s enter a class: twelve are listed, eight are counted.
    changes = [gsd.Change("v4", i << 16, (i << 16) + 255 + i, None, "GovIta") for i in range(20)]
    lines = gsd.render_changes(changes, None)
    rows = [l for l in lines if l.startswith("| `")]
    assert len(rows) == 12 and rows[0].startswith("| `0.19.0.0-0.19.1.18` | 275 |")
    assert "8 smaller IPv4 changes are not listed (2,076 addresses in all)." in lines
    assert gsd.render_changes([], None) == []


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


# ── A class confined to the space registered in a country ────────────────────

def test_intersect_agrees_with_a_brute_force_comparison():
    rng = random.Random(14)
    for _ in range(300):
        ranges = random_table(rng, merged=False)
        allowed = gsd.merge_same_class([gsd.Range(r.start, r.end, "x") for r in random_table(rng)])
        inside = {ip for r in allowed for ip in range(r.start, r.end + 1)}
        want = {ip: c for ip, c in as_map(ranges, space=10**6).items() if ip in inside}
        got = gsd.intersect(ranges, allowed)
        assert as_map(got, space=10**6) == want
        for a, b in zip(got, got[1:]):
            assert a.end < b.start
    assert gsd.intersect([gsd.Range(0, 9, "A")], []) == []
    assert gsd.intersect([], [gsd.Range(0, 9, "x")]) == []


def test_a_confined_class_stops_at_the_registry_border():
    # AS64496 (datacenter) announces 0-199; only 100-149 is registered at home.
    # AS64497 (residential) announces 300-399 and is not confined.
    by_asn = {64496: [gsd.Range(0, 199, "Unknown")], 64497: [gsd.Range(300, 399, "Unknown")]}
    roles = {64496: "DatacenterIta", 64497: "ResidentialIta"}
    home = {"DatacenterIta": [gsd.Range(100, 149, "Unknown")]}
    assert key(gsd.build_family(by_asn, roles, [], None)) == [
        (0, 199, "DatacenterIta"), (300, 399, "ResidentialIta")]
    assert key(gsd.build_family(by_asn, roles, [], None, home)) == [
        (100, 149, "DatacenterIta"), (300, 399, "ResidentialIta")]
    # With a country baseline, what falls outside the rule falls back to it.
    baseline = [gsd.Range(0, 119, "Unknown")]
    assert key(gsd.build_family(by_asn, roles, baseline, "Eu", home)) == [
        (0, 99, "Eu"), (100, 149, "DatacenterIta"), (300, 399, "ResidentialIta")]
    # Rows of an ASN in any order, and home space in two pieces.
    by_asn[64496] = [gsd.Range(120, 199, "Unknown"), gsd.Range(0, 119, "Unknown")]
    home = {"DatacenterIta": [gsd.Range(10, 19, "Unknown"), gsd.Range(100, 149, "Unknown")]}
    assert key(gsd.build_family(by_asn, roles, [], None, home)) == [
        (10, 19, "DatacenterIta"), (100, 149, "DatacenterIta"), (300, 399, "ResidentialIta")]


def test_outside_is_what_intersect_drops():
    rng = random.Random(15)
    for _ in range(300):
        ranges = random_table(rng, merged=False)
        allowed = gsd.merge_same_class([gsd.Range(r.start, r.end, "x") for r in random_table(rng)])
        inside = {ip for r in allowed for ip in range(r.start, r.end + 1)}
        whole = as_map(ranges, space=10**6)
        got = gsd.outside(ranges, allowed)
        assert as_map(got, space=10**6) == {ip: c for ip, c in whole.items() if ip not in inside}
        for a, b in zip(got, got[1:]):
            assert a.end < b.start
    assert key(gsd.outside([gsd.Range(0, 9, "A")], [])) == [(0, 9, "A")]


def test_published_ranges_outside_their_registered_space_are_found():
    published = [gsd.Range(0, 99, "DatacenterIta"), gsd.Range(100, 199, "ResidentialIta"),
                 gsd.Range(300, 399, "DatacenterIta")]
    home = {"DatacenterIta": [gsd.Range(50, 349, "Unknown")]}
    # Outside: 0-49 and 350-399. This snapshot calls 0-19 residential.
    observed = [gsd.Range(0, 19, "ResidentialIta"), gsd.Range(50, 99, "DatacenterIta")]
    got = gsd.confine_family(published, observed, home, "v4")
    assert [(c.start, c.end, c.old, c.new) for c in got] == [
        (0, 19, "DatacenterIta", "ResidentialIta"), (20, 49, "DatacenterIta", None),
        (350, 399, "DatacenterIta", None)]
    # A class that is not confined is left alone wherever it is...
    far = published + [gsd.Range(500, 599, "ResidentialIta")]
    assert gsd.confine_family(far, observed, home, "v4") == got
    # ...and so is a table inside its space.
    assert gsd.confine_family(published, observed, {}, "v4") == []
    assert gsd.confine_family(published[1:2], observed, home, "v4") == []


def test_the_italian_datacenter_class_is_confined_to_italy():
    assert gsd.REGIONS["ita"]["registered_in"] == {"DatacenterIta": {"IT"}}


def test_the_eu_role_classes_are_confined_to_the_eu_27():
    assert gsd.REGIONS["eu"]["registered_in"] == {
        "GovEu": gsd.EU27, "ResidentialEu": gsd.EU27, "DatacenterEu": gsd.EU27}
    # The baseline is the registry itself and needs no such rule.
    assert "Eu" not in gsd.REGIONS["eu"]["registered_in"]
    assert len(gsd.EU27) == 27 and "GB" not in gsd.EU27 and "CH" not in gsd.EU27


def test_the_curated_lists_after_the_october_2026_review():
    ita = {asn for asns, _ in gsd.REGIONS["ita"]["asn_roles"] for asn in asns}
    assert 24608 in gsd.RESIDENTIAL_ASNS and gsd.RESIDENTIAL_ASNS[24608] == "Wind Tre"
    assert 24940 not in ita                    # Hetzner: off the Italian list...
    assert 24940 in gsd.DATACENTER_EU_ASNS     # ...and still on the EU one
    assert gsd.holder_matches("Wind Tre", "WINDTRE-AS WIND TRE S.P.A.")


# ── Hysteresis ───────────────────────────────────────────────────────────────

def as_map(table, space=440):
    """A table as {address: class}, for the brute-force models."""
    return {ip: r.ip_class for r in table for ip in range(r.start, min(r.end, space) + 1)}


def as_table(mapping):
    """{address: class} back to sorted, merged ranges."""
    out = []
    for ip in sorted(mapping):
        if out and out[-1].end + 1 == ip and out[-1].ip_class == mapping[ip]:
            out[-1].end = ip
        else:
            out.append(gsd.Range(ip, ip, mapping[ip]))
    return out


def key(table):
    return [(r.start, r.end, r.ip_class) for r in table]


def per_address(pending):
    return {ip: q.facts() for q in pending for ip in range(q.start, q.end + 1)}


def model_step(published, waiting, observed, day):
    """One snapshot, one address at a time, with no notion of runs: the rule as
    a person would state it."""
    applied, went_back = {}, {}
    for ip in set(published) | set(observed) | set(waiting):
        p, o, q = published.get(ip), observed.get(ip), waiting.get(ip)
        if o == p:
            if q:
                went_back[ip] = waiting.pop(ip)
            continue
        if q and q[0] == o:
            fresh = gsd._days_between(q[3], day) >= gsd.MIN_SPACING_DAYS
            q = (o, q[1] + 1, q[2], day) if fresh else q
        else:
            q = (o, 1, day, day)
        if q[1] >= (gsd.ENTER_AFTER if p is None else gsd.LEAVE_AFTER):
            applied[ip] = q
            waiting.pop(ip, None)
            if o is None:
                del published[ip]
            else:
                published[ip] = o
        else:
            waiting[ip] = q
    return applied, went_back


def test_settle_agrees_with_a_per_address_model():
    rng = random.Random(568)
    for _ in range(120):
        table = random_table(rng)
        pending = []
        m_pub, m_wait = as_map(table), {}
        observed = random_table(rng)
        day = datetime.date(2026, 8, 10)
        for _ in range(9):
            day += datetime.timedelta(days=rng.choice([0, 1, 4, 5, 7, 7, 7, 9]))
            if rng.random() < 0.45:
                observed = random_table(rng)  # otherwise the same observation again
            got = gsd.settle_family(table, observed, pending, day.isoformat(), "v4")
            applied, went_back = model_step(m_pub, m_wait, as_map(observed), day.isoformat())
            assert key(got.table) == key(as_table(m_pub))
            assert per_address(got.pending) == m_wait
            assert per_address(got.applied) == applied
            assert per_address(got.went_back) == went_back
            # Written down as sorted runs that do not touch needlessly.
            for seq in (got.table, got.pending, got.applied, got.went_back):
                for a, b in zip(seq, seq[1:]):
                    assert a.end < b.start
            for a, b in zip(got.pending, got.pending[1:]):
                assert not (a.end + 1 == b.start and a.facts() == b.facts())
            table, pending = got.table, got.pending


def weeks(n, start=datetime.date(2026, 10, 5)):
    return [(start + datetime.timedelta(weeks=i)).isoformat() for i in range(n)]


def run_snapshots(table, observations):
    """Feed (day, observed) pairs through settle_family; the table after each."""
    pending, tables = [], []
    for day, observed in observations:
        got = gsd.settle_family(table, observed, pending, day, "v4")
        table, pending = got.table, got.pending
        tables.append((key(table), got))
    return tables


def test_a_run_enters_a_class_after_two_weekly_snapshots():
    new = [gsd.Range(100, 199, "GovIta")]
    w = weeks(3)
    steps = run_snapshots([], [(w[0], new), (w[1], new)])
    assert steps[0][0] == [] and [q.seen for q in steps[0][1].pending] == [1]
    assert steps[1][0] == [(100, 199, "GovIta")] and steps[1][1].pending == []
    assert [(q.seen, q.first, q.last) for q in steps[1][1].applied] == [(2, w[0], w[1])]


def test_a_run_leaves_or_changes_class_after_three():
    table = [gsd.Range(100, 199, "GovIta")]
    w = weeks(4)
    for observed in ([], [gsd.Range(100, 199, "ResidentialIta")]):
        steps = run_snapshots(table, [(d, observed) for d in w[:3]])
        assert steps[0][0] == steps[1][0] == [(100, 199, "GovIta")]
        assert [q.seen for q in steps[1][1].pending] == [2]
        assert steps[2][0] == key(observed) and steps[2][1].pending == []


def test_runs_on_the_same_day_are_one_snapshot():
    new = [gsd.Range(100, 199, "GovIta")]
    steps = run_snapshots([], [("2026-10-05", new), ("2026-10-05", new), ("2026-10-06", new),
                               ("2026-10-09", new), ("2026-10-10", new)])
    # Four days after the first sighting is still the same week...
    assert [s[0] for s in steps[:4]] == [[]] * 4
    assert [q.seen for q in steps[3][1].pending] == [1]
    # ...five days after is the next one.
    assert steps[4][0] == [(100, 199, "GovIta")]


def test_a_flap_is_never_published():
    table = [gsd.Range(0, 999, "ResidentialIta")]
    gone = [gsd.Range(0, 499, "ResidentialIta"), gsd.Range(600, 999, "ResidentialIta")]
    w = weeks(6)
    # Away one week, back; away two weeks, back.
    steps = run_snapshots(table, [(w[0], gone), (w[1], table), (w[2], gone), (w[3], gone),
                                  (w[4], table), (w[5], table)])
    assert all(s[0] == [(0, 999, "ResidentialIta")] for s in steps)
    assert [(q.start, q.end, q.seen) for q in steps[1][1].went_back] == [(500, 599, 1)]
    assert [(q.start, q.end, q.seen) for q in steps[4][1].went_back] == [(500, 599, 2)]
    assert steps[5][1].went_back == [] and steps[5][1].pending == []


def test_a_different_observation_starts_the_count_again():
    table = [gsd.Range(0, 99, "GovIta")]
    res, dc = [gsd.Range(0, 99, "ResidentialIta")], [gsd.Range(0, 99, "DatacenterIta")]
    w = weeks(5)
    steps = run_snapshots(table, [(w[0], res), (w[1], res), (w[2], dc), (w[3], dc), (w[4], dc)])
    assert [s[0] for s in steps[:4]] == [[(0, 99, "GovIta")]] * 4
    assert [(q.observed, q.seen, q.first) for q in steps[2][1].pending] == [("DatacenterIta", 1, w[2])]
    assert steps[2][1].went_back == []
    assert steps[4][0] == [(0, 99, "DatacenterIta")]


def test_a_steady_observation_is_reached_and_then_nothing_moves():
    rng = random.Random(3)
    for _ in range(40):
        table, observed = random_table(rng), random_table(rng)
        steps = run_snapshots(table, [(d, observed) for d in weeks(5)])
        assert steps[2][0] == key(observed)          # three snapshots are always enough
        for _, got in steps[3:]:
            assert key(got.table) == key(observed)
            assert got.pending == got.applied == got.went_back == []


def test_patching_a_table_and_cutting_the_waiting_list():
    rng = random.Random(11)
    for _ in range(150):
        table, other = random_table(rng), random_table(rng)
        changes = [c for c in gsd.diff_family(table, other, "v4") if rng.random() < 0.5]
        want = as_map(table)
        for c in changes:
            for ip in range(c.start, c.end + 1):
                if c.new is None:
                    want.pop(ip, None)
                else:
                    want[ip] = c.new
        assert key(gsd.patch_family(table, changes)) == key(as_table(want))

        pending = [gsd.Pending("v4", r.start, r.end, r.ip_class, 1, "2026-10-05", "2026-10-05")
                   for r in random_table(rng, merged=False)]
        cut = {ip for c in changes for ip in range(c.start, c.end + 1)}
        kept = gsd.without(pending, changes)
        assert per_address(kept) == {ip: f for ip, f in per_address(pending).items() if ip not in cut}
        for a, b in zip(kept, kept[1:]):
            assert a.end < b.start


def test_a_curated_list_edit_is_published_at_once():
    table = {"v4": [gsd.Range(0, 99, "GovIta"), gsd.Range(200, 299, "ResidentialIta")], "v6": []}
    # The ASN behind 0-99 was removed from the list; 300-399 is a new ASN's.
    observed = {"v4": [gsd.Range(200, 399, "ResidentialIta")], "v6": []}
    waiting = {"v4": [gsd.Pending("v4", 50, 99, None, 2, "2026-09-21", "2026-09-28"),
                      gsd.Pending("v4", 200, 249, None, 2, "2026-09-21", "2026-09-28")], "v6": []}
    edits = {"v4": [gsd.Change("v4", 0, 99, "GovIta", None)]}
    got = gsd.settle(table, observed, waiting, "2026-10-05", edits)
    # 0-99 is gone today, and what waited on those addresses is settled with it.
    # 200-249 was waiting to leave and is observed again: it went back. 300-399
    # is new and waits like any other.
    assert key(got.table["v4"]) == [(200, 299, "ResidentialIta")]
    assert [(c.start, c.end, c.old, c.new) for c in got.curation] == [(0, 99, "GovIta", None)]
    assert [(q.start, q.end, q.observed, q.seen) for q in got.pending["v4"]] == [
        (300, 399, "ResidentialIta", 1)]
    assert [(q.start, q.end) for q in got.went_back] == [(200, 249)]
    assert got.applied == []
    # Without the edit the removal waits its three snapshots like anything else.
    got = gsd.settle(table, observed, {"v4": [], "v6": []}, "2026-10-05")
    assert key(got.table["v4"]) == key(table["v4"]) and got.curation == []


def test_state_file_round_trip():
    rng = random.Random(7)
    curated = {137: "GovIta", 3269: "ResidentialIta", 31034: "DatacenterIta"}
    for _ in range(30):
        pending = {
            "v4": [gsd.Pending("v4", r.start << 8, (r.end << 8) | 255, rng.choice(CLASSES + [None]),
                               rng.randrange(1, 3), "2026-09-28", "2026-10-05")
                   for r in random_table(rng, merged=False)],
            "v6": [gsd.Pending("v6", r.start << 90, (r.end << 90) | ((1 << 90) - 1), "GovIta",
                               1, "2026-10-05", "2026-10-05") for r in random_table(rng)],
        }
        text = gsd.dump_state("ita", "2026-10-05", curated, pending)
        with workdir() as d:
            (d / "s.json").write_text(text)
            got_curated, got = gsd.load_state(d / "s.json", "ita")
            assert got_curated == curated and got == pending
            assert gsd.dump_state("ita", "2026-10-05", got_curated, got) == text
            assert "not a version-1 state file for 'eu'" in refused(gsd.load_state, d / "s.json", "eu")
        assert json.loads(text)["snapshot"] == "2026-10-05"
    with workdir() as d:
        assert gsd.load_state(d / "missing.json", "ita") == (None, {"v4": [], "v6": []})
        (d / "s.json").write_text(gsd.dump_state("ita", "2026-10-05", curated,
                                                 {"v4": [], "v6": []}).replace('"version": 1', '"version": 2'))
        assert "not a version-1 state file" in refused(gsd.load_state, d / "s.json", "ita")


def test_state_file_is_one_item_per_line():
    pending = {"v4": [gsd.Pending("v4", int(V4("2.159.128.0")), int(V4("2.159.191.255")), None,
                                  1, "2026-10-06", "2026-10-06")], "v6": []}
    text = gsd.dump_state("ita", "2026-10-06", {1267: "ResidentialIta", 137: "GovIta"}, pending)
    assert text.splitlines()[6:11] == [
        '    "137": "GovIta",',
        '    "1267": "ResidentialIta"',
        '  },',
        '  "pending": [',
        '    {"family": "v4", "block": "2.159.128.0/18", "observed": null, "seen": 1, '
        '"first": "2026-10-06", "last": "2026-10-06"}',
    ]


def test_blocks_parse_back():
    rng = random.Random(5)
    for family, bits in (("v4", 32), ("v6", 128)):
        for _ in range(300):
            start = rng.randrange(0, 1 << bits)
            end = min((1 << bits) - 1, start + rng.randrange(0, 1 << rng.randrange(1, bits)))
            if rng.random() < 0.5:  # an aligned prefix
                size = 1 << rng.randrange(0, bits)
                start -= start % size
                end = start + size - 1
            assert gsd.parse_block(family, gsd.format_block(family, start, end)) == (start, end)


# ── The generator, end to end ────────────────────────────────────────────────

TEST_REGION = {
    "module": "data_ita", "adjective": "Italian", "countries": {"IT"},
    "baseline_class": None,
    "asn_roles": [({64496: "Example"}, "GovIta"), ({64497: "Example"}, "ResidentialIta")],
}


def write_sources(d, ripe=None, v4=None, v6=None, day="2026-10-05"):
    # RIPE's file is dated the day before the run, as the real one is.
    dated = (datetime.date.fromisoformat(day) - datetime.timedelta(days=1)).strftime("%Y%m%d")
    (d / "ripe").write_text(ripe or ripe_text(date=dated))
    (d / "v4").write_text(iptoasn_text(v4 or v4_rows(), V4))
    (d / "v6").write_text(iptoasn_text(v6 or v6_rows(), V6))


def run_generator(d, *extra, write=True, day="2026-10-05", region=None, answer=None, **sources):
    """Run main() on fixture files in `d`. Returns (exit code, stderr, lookups).
    `answer(asn)` stands in for RIPEstat: a holder name, or an exception to raise."""
    if write:
        write_sources(d, day=day, **sources)
    lookups = []

    def holder(asn, timeout=15):
        lookups.append(asn)
        got = answer(asn) if answer else "EXAMPLE-AS Example Org"
        if isinstance(got, Exception):
            raise got
        return got

    argv = ["gen", "--region", "ita", "--ripe", str(d / "ripe"), "--iptoasn", str(d / "v4"),
            "--iptoasn6", str(d / "v6"), "--snapshot-date", day, *extra]
    err, code = io.StringIO(), 0
    with small_tables(), patched(REGIONS={"ita": region or TEST_REGION}, fetch_holder=holder), \
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


def without_as64497():
    """The IPv4 fixture with AS64497 announcing nothing."""
    return [(s, e, 0 if asn == 64497 else asn) for s, e, asn in v4_rows()]


def test_generator_holds_a_change_back_until_it_has_been_seen_enough():
    with workdir() as d:
        out, rep, summ = d / "data.rs", d / "report.json", d / "summary.md"
        state = d / "data.pending.json"
        args = ["--output", str(out), "--report", str(rep), "--summary", str(summ)]
        assert run_generator(d, *args, day="2026-10-05")[0] == 0
        first = out.read_text()
        assert json.loads(state.read_text())["pending"] == []
        assert json.loads(state.read_text())["curated"] == {"64496": "GovIta", "64497": "ResidentialIta"}

        # AS64497 stops announcing. One week: the table keeps its /24.
        gone = without_as64497()
        assert run_generator(d, *args, day="2026-10-12", v4=gone)[0] == 0
        assert key(gsd.parse_rust_table(out)["v4"]) == key(
            [gsd.Range(int(V4("192.0.2.0")), int(V4("192.0.2.255")), "GovIta"),
             gsd.Range(int(V4("198.51.100.0")), int(V4("198.51.100.255")), "ResidentialIta")])
        assert json.loads(state.read_text())["pending"] == [
            {"family": "v4", "block": "198.51.100.0/24", "observed": None, "seen": 1,
             "first": "2026-10-12", "last": "2026-10-12"}]
        report = json.loads(rep.read_text())
        assert (report["waiting"], report["changes"], report["needs_review"]) == (1, [], True)
        assert ("| `198.51.100.0/24` | 256 | ResidentialIta | no class | 1 of 3 | 2026-10-12 "
                "| not announced | FR |") in summ.read_text()

        # The same snapshot run again two days later is not a second sighting.
        assert run_generator(d, *args, day="2026-10-14", v4=gone)[0] == 0
        assert json.loads(state.read_text())["pending"][0]["seen"] == 1

        # It comes back: nothing ever changed, and the summary says it was seen.
        assert run_generator(d, *args, day="2026-10-19")[0] == 0
        assert json.loads(state.read_text())["pending"] == []
        assert json.loads(rep.read_text())["went_back"] == 1
        assert "| `198.51.100.0/24` | 256 | ResidentialIta | no class | 1 | 2026-10-12 |" \
            in summ.read_text()
        assert out.read_text() == first.replace("2026-10-05", "2026-10-19")


def test_generator_refuses_a_refresh_over_budget_and_keeps_table_and_memory():
    with workdir() as d:
        out, rep, state = d / "data.rs", d / "report.json", d / "data.pending.json"
        args = ["--output", str(out), "--report", str(rep)]
        assert run_generator(d, *args, day="2026-10-05")[0] == 0
        gone = without_as64497()
        assert run_generator(d, *args, day="2026-10-12", v4=gone)[0] == 0
        assert run_generator(d, *args, day="2026-10-19", v4=gone)[0] == 0
        before, memory = out.read_text(), state.read_text()
        assert json.loads(memory)["pending"][0]["seen"] == 2

        # Third week: the /24 would leave, and with it the whole class.
        code, err, _ = run_generator(d, *args, day="2026-10-26", v4=gone)
        assert code == gsd.EXIT_OVER_BUDGET and "OVER BUDGET" in err
        assert out.read_text() == before and state.read_text() == memory
        report = json.loads(rep.read_text())
        assert report["refused"] is True and report["needs_review"] is True
        assert report["refuse"] == [
            "IPv4 class ResidentialIta goes from 256 addresses to 0 addresses (-100.0%)"]
        assert report["review"] == [
            "AS64497 (Example) is curated as ResidentialIta and originates no IPv4 range "
            "in this snapshot"]
        assert report["changes"] == [{
            "family": "v4", "block": "198.51.100.0/24", "addresses": 256,
            "from": "ResidentialIta", "to": None,
            "announced_by": "not announced", "registered_in": "FR"}]
        # By hand, with the flag, it is written, and the summary shows the block.
        summ = d / "summary.md"
        code, _, _ = run_generator(d, *args, "--allow-over-budget", "--summary", str(summ),
                                   day="2026-10-26", v4=gone)
        assert code == 0 and out.read_text() != before
        assert "| `198.51.100.0/24` | 256 | ResidentialIta | no class | not announced | FR |" \
            in summ.read_text()
        assert "1 runs are published now after waiting their snapshots." in summ.read_text()
        assert json.loads(state.read_text())["pending"] == []


def test_no_hysteresis_publishes_the_snapshot_and_forgets():
    with workdir() as d:
        out, state = d / "data.rs", d / "data.pending.json"
        args = ["--output", str(out)]
        assert run_generator(d, *args, day="2026-10-05")[0] == 0
        gone = without_as64497()
        assert run_generator(d, *args, day="2026-10-12", v4=gone)[0] == 0
        assert len(json.loads(state.read_text())["pending"]) == 1
        code, _, _ = run_generator(d, *args, "--no-hysteresis", "--allow-over-budget",
                                   day="2026-10-13", v4=gone)
        assert code == 0
        assert [r.ip_class for r in gsd.parse_rust_table(out)["v4"]] == ["GovIta"]
        assert json.loads(state.read_text())["pending"] == []


def test_an_asn_taken_off_the_curated_list_loses_its_ranges_at_once():
    with workdir() as d:
        out, state, summ = d / "data.rs", d / "data.pending.json", d / "summary.md"
        args = ["--output", str(out), "--summary", str(summ), "--allow-over-budget"]
        assert run_generator(d, *args, day="2026-10-05")[0] == 0
        # AS64497 is removed from the list (say its holder changed); it still announces.
        edited = dict(TEST_REGION, asn_roles=[({64496: "Example"}, "GovIta")])
        code, _, lookups = run_generator(d, *args, day="2026-10-12", region=edited)
        assert code == 0 and lookups == [64496]
        assert [r.ip_class for r in gsd.parse_rust_table(out)["v4"]] == ["GovIta"]
        state_now = json.loads(state.read_text())
        assert state_now["curated"] == {"64496": "GovIta"} and state_now["pending"] == []
        assert ("1 more at once: the curated ASN list changed, or a range is outside the "
                "countries its class is confined to.") in summ.read_text()

        # Put back, it is an addition: it waits its two snapshots.
        assert run_generator(d, *args, day="2026-10-19")[0] == 0
        assert [r.ip_class for r in gsd.parse_rust_table(out)["v4"]] == ["GovIta"]
        assert json.loads(state.read_text())["pending"][0]["observed"] == "ResidentialIta"
        assert run_generator(d, *args, day="2026-10-26")[0] == 0
        assert [r.ip_class for r in gsd.parse_rust_table(out)["v4"]] == ["GovIta", "ResidentialIta"]


def test_a_class_confined_to_a_country_drops_what_is_outside_at_once():
    # The fixture: 192.0.2.0/24 registered in IT (AS64496, GovIta) and
    # 198.51.100.0/24 registered in FR (AS64497, ResidentialIta).
    confined = dict(TEST_REGION, registered_in={"ResidentialIta": {"IT"}})
    # Both ASNs silent in IPv4: another, uncurated one announces their blocks.
    quiet = [(s, e, 64511 if asn else 0) for s, e, asn in v4_rows()]
    with workdir() as d:
        out, state, summ, rep = (d / "data.rs", d / "data.pending.json", d / "summary.md",
                                 d / "report.json")
        assert run_generator(d, "--output", str(out), day="2026-10-05")[0] == 0
        # A week later both are silent: both /24s start waiting to leave.
        assert run_generator(d, "--output", str(out), day="2026-10-12", v4=quiet)[0] == 0
        assert [r.ip_class for r in gsd.parse_rust_table(out)["v4"]] == ["GovIta", "ResidentialIta"]
        waiting = json.loads(state.read_text())["pending"]
        assert [(q["block"], q["seen"]) for q in waiting] == [
            ("192.0.2.0/24", 1), ("198.51.100.0/24", 1)]

        # The rule arrives: ResidentialIta must be registered in Italy. The class
        # empties, so the refresh is refused until someone says it is meant.
        code, err, _ = run_generator(d, "--output", str(out), day="2026-10-13", v4=quiet,
                                     region=confined)
        assert code == gsd.EXIT_OVER_BUDGET
        code, _, _ = run_generator(d, "--output", str(out), "--summary", str(summ),
                                   "--report", str(rep), "--allow-over-budget",
                                   day="2026-10-13", v4=quiet, region=confined)
        assert code == 0
        # The French /24 lost its class today, and is no longer waiting for
        # anything; the Italian one still waits, at 1.
        assert [(str(V4(r.start)), r.ip_class) for r in gsd.parse_rust_table(out)["v4"]] == [
            ("192.0.2.0", "GovIta")]
        assert json.loads(state.read_text())["pending"] == waiting[:1]
        report = json.loads(rep.read_text())
        assert (report["relabelled_by_curation"], report["went_back"], report["waiting"]) == (1, 0, 1)
        assert "Observed and gone again" not in summ.read_text()
        assert "0 runs are published now after waiting their snapshots; 1 more at once" \
            in summ.read_text()
        # And it stays out: the next snapshots do not bring it back.
        assert run_generator(d, "--output", str(out), day="2026-10-20", region=confined)[0] == 0
        assert run_generator(d, "--output", str(out), day="2026-10-27", region=confined)[0] == 0
        assert [(str(V4(r.start)), r.ip_class) for r in gsd.parse_rust_table(out)["v4"]] == [
            ("192.0.2.0", "GovIta")]
        assert json.loads(state.read_text())["pending"] == []


def test_generator_tells_an_unreachable_lookup_from_a_drift_and_checks_countries():
    with workdir() as d:
        out, summ = d / "data.rs", d / "summary.md"
        # RIPEstat down for one ASN: exit 5, nothing written.
        code, err, lookups = run_generator(
            d, "--output", str(out),
            answer=lambda asn: TimeoutError("timed out") if asn == 64497 else "Example Org")
        assert code == gsd.EXIT_LOOKUP and "HOLDER LOOKUP FAILED" in err and not out.exists()
        assert lookups == [64496] + [64497] * 4
        # The fixture's ASNs are registered in "ZZ": a region that expects Italy refuses them.
        strict = dict(TEST_REGION, asn_countries={"IT"}, asn_country_exceptions={64497: "ZZ"})
        code, err, _ = run_generator(d, "--output", str(out), region=strict)
        assert code == gsd.EXIT_HOLDER_DRIFT and not out.exists()
        assert "AS64496   expected ~ 'Example'   →   registered in ZZ, expected IT" in err
        assert "AS64497" not in err  # the exception holds
        # As curated, it runs, and the summary says what the list leaves out.
        relaxed = dict(TEST_REGION, asn_countries={"ZZ"})
        assert run_generator(d, "--output", str(out), "--summary", str(summ), region=relaxed)[0] == 0
        text = summ.read_text()
        assert "### What the curated ASN list leaves out" in text
        assert "100% are originated by a curated ASN (256 of 256)" in text
        # And on every later refresh, after the comparison with the table it replaces.
        assert run_generator(d, "--output", str(out), "--summary", str(summ), region=relaxed)[0] == 0
        text = summ.read_text()
        assert text.index("### Italian addresses per class") < text.index(
            "### What the curated ASN list leaves out")


def test_a_damaged_state_file_stops_the_refresh():
    with workdir() as d:
        out, state = d / "data.rs", d / "data.pending.json"
        assert run_generator(d, "--output", str(out))[0] == 0
        before = out.read_text()
        for damage in ("{", '{"version": 1, "region": "ita"}',
                       state.read_text().replace('"region": "ita"', '"region": "eu"')):
            state.write_text(damage)
            code, err, _ = run_generator(d, "--output", str(out), day="2026-10-12")
            assert code == gsd.EXIT_INPUT and "state file" in err, damage
            assert out.read_text() == before
        # A missing one is an empty memory, not an error.
        state.unlink()
        assert run_generator(d, "--output", str(out), day="2026-10-12")[0] == 0


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
