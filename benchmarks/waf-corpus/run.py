#!/usr/bin/env python3
"""Fire the WAF corpus at a protected zion route and measure detection + FP.

Each payload is sent in BOTH vectors — query string (`?q=`) and JSON body
(`{"q": ...}`) — and counts as *detected* if EITHER returns HTTP 400 (the WAF
block). Detection rate is on the malicious set; false-positive rate is on the
benign set (legit traffic that must NOT be blocked).

Usage:  python3 run.py [base_url] [label]
        base_url default https://127.0.0.1:4431 ; route /api/v1/data must have waf=true.
Exit:   non-zero if any benign payload is blocked (a false positive is a hard fail).
"""
import json, ssl, sys, urllib.parse, urllib.request, urllib.error, collections
from pathlib import Path

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:4431"
LABEL = sys.argv[2] if len(sys.argv) > 2 else "zion"
URL = BASE + "/api/v1/data"
CORPUS = json.loads((Path(__file__).parent / "corpus.json").read_text())
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE


def fire(method, payload):
    try:
        if method == "GET":
            req = urllib.request.Request(URL + "?q=" + urllib.parse.quote(payload, safe=""), method="GET")
        else:
            req = urllib.request.Request(URL, data=json.dumps({"q": payload}).encode(),
                                         method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, context=CTX, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{type(e).__name__}"


by_cat = collections.defaultdict(lambda: [0, 0])
fn, fp = [], []
for e in CORPUS:
    sq, sb = fire("GET", e["payload"]), fire("POST", e["payload"])
    blocked = (sq == 400) or (sb == 400)
    if e["kind"] == "mal":
        by_cat[e["category"]][1] += 1
        if blocked:
            by_cat[e["category"]][0] += 1
        else:
            fn.append((e["category"], e["payload"], sq, sb))
    elif blocked:
        fp.append((e["payload"], sq, sb))

det = sum(v[0] for v in by_cat.values()); tot = sum(v[1] for v in by_cat.values())
ben = sum(1 for e in CORPUS if e["kind"] == "benign")
print(f"WAF corpus vs {LABEL} — {tot} malicious / {ben} benign, both vectors → {URL}\n")
print("── detection by class (malicious) ──")
for cat in sorted(by_cat):
    d, t = by_cat[cat]
    bar = "█" * round(10 * d / t) + "·" * (10 - round(10 * d / t))
    print(f"  {cat:9} {bar} {d:2}/{t:<2} {100*d//t:3}%")
print(f"\nDETECTION : {det}/{tot} = {100*det/tot:.1f}%")
print(f"FALSE POS : {len(fp)}/{ben} = {100*len(fp)/ben:.1f}%")
if fn:
    print(f"\n── missed ({len(fn)} false negatives) ──")
    for cat, p, sq, sb in fn:
        print(f"  [{cat}] q={sq} b={sb}  {p[:72]}")
if fp:
    print(f"\n── FALSE POSITIVES ({len(fp)} benign blocked — should be 0) ──")
    for p, sq, sb in fp:
        print(f"  q={sq} b={sb}  {p[:72]}")
sys.exit(1 if fp else 0)
