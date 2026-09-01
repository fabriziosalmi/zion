#!/usr/bin/env python3
"""Offline unit tests for the sovereign holder-validation matcher.

Network-free ON PURPOSE: the live RIPEstat call runs only in the scheduled
generation job. These tests pin the token-matching logic against RECORDED
holder fixtures, so the matcher (accent handling, noise words, drift detection)
is covered by `python3 scripts/test_generate_sovereign_data.py` — or pytest —
without touching the network.

    python3 scripts/test_generate_sovereign_data.py
"""

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


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
