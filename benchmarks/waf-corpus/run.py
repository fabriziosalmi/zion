#!/usr/bin/env python3
"""Fire the WAF corpus at a protected zion route and measure detection + FP.

Each payload is sent in BOTH vectors — query string (`?q=`) and JSON body
(`{"q": ...}`) — and counts as *detected* if EITHER returns HTTP 400 (the WAF
block). Detection rate is on the malicious set; false-positive rate is on the
benign set (legit traffic that must NOT be blocked).

Two regression gates:
  * false positives — ANY benign payload blocked is a hard fail (precision).
  * detection ratchet — if a committed baseline exists ($WAF_BASELINE), the
    per-class detected COUNT must not drop below its baseline (recall). This
    closes the historical gap where recall could rot to zero with CI green.
The ratchet is on integer counts, not percentages: detection is deterministic
for a fixed corpus + engine, so a drop is a real regression, never noise. When
recall genuinely improves, refresh the baseline with --emit-baseline.

Usage:  python3 run.py [base_url] [label]
        base_url default https://127.0.0.1:4431 ; route /api/v1/data must have waf=true.
Env:    WAF_CORPUS    corpus file (default corpus.json; v2 = corpus-v2.json)
        WAF_BASELINE  path to a per-class baseline json; enables the recall gate
        WAF_EMIT_BASELINE  path to WRITE the current counts as a new baseline
Exit:   1 if any benign payload is blocked, OR any class regresses below baseline.
"""
import json, ssl, sys, urllib.parse, urllib.request, urllib.error, collections
from pathlib import Path

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:4431"
LABEL = sys.argv[2] if len(sys.argv) > 2 else "zion"
URL = BASE + "/api/v1/data"
# Corpus file: $WAF_CORPUS (default v1). v2 is the larger sourced set.
import os
CORPUS_FILE = os.environ.get("WAF_CORPUS", "corpus.json")
BASELINE_FILE = os.environ.get("WAF_BASELINE")
EMIT_BASELINE = os.environ.get("WAF_EMIT_BASELINE")
CORPUS = json.loads((Path(__file__).parent / CORPUS_FILE).read_text())
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

# Emit mode: write the current per-class counts as a fresh baseline and exit
# (still honoring the FP hard-fail). Use after a genuine recall improvement.
current = {cat: {"detected": by_cat[cat][0], "total": by_cat[cat][1]} for cat in by_cat}
if EMIT_BASELINE:
    payload = {"corpus": CORPUS_FILE,
               "overall": {"detected": det, "total": tot},
               "by_class": current}
    Path(EMIT_BASELINE).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"\nwrote baseline → {EMIT_BASELINE} (overall {det}/{tot})")

# Recall ratchet: no class may detect fewer than its baseline count.
regressions = []
if BASELINE_FILE:
    base = json.loads(Path(BASELINE_FILE).read_text())
    if base.get("corpus") not in (None, CORPUS_FILE):
        print(f"\n::warning:: baseline is for corpus '{base.get('corpus')}', running '{CORPUS_FILE}'")
    for cat, b in base.get("by_class", {}).items():
        got = current.get(cat, {}).get("detected", 0)
        if got < b["detected"]:
            regressions.append((cat, got, b["detected"]))
    base_overall = base.get("overall", {}).get("detected")
    if base_overall is not None and det < base_overall:
        regressions.append(("OVERALL", det, base_overall))
    if regressions:
        print(f"\n── RECALL REGRESSION ({len(regressions)} class(es) below baseline) ──")
        for cat, got, want in regressions:
            print(f"  {cat:9} detected {got} < baseline {want}")
        print("  detection dropped — this is a silent-WAF-regression gate. If the")
        print("  drop is intentional, refresh with WAF_EMIT_BASELINE=<file>.")
    else:
        print(f"\nrecall ratchet OK vs {Path(BASELINE_FILE).name}")

sys.exit(1 if (fp or regressions) else 0)
