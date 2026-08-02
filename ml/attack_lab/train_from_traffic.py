# SPDX-License-Identifier: Apache-2.0
"""Train the WAF scorer on REAL captured tool traffic (attack.jsonl from
sqlmap + SecLists replay; benign.jsonl from the benign generator), then report
honest in-distribution metrics AND the cross-source result on the real CSIC
sample — the test that the synthetic model failed (0/9).

    python3 ml/attack_lab/train_from_traffic.py
"""

from __future__ import annotations

import json
import os
import sys

import numpy as np
import torch

HERE = os.path.dirname(os.path.abspath(__file__))
ML = os.path.join(HERE, "..")
sys.path.insert(0, ML)

from features import extract_features  # noqa: E402
from train import Scorer, metrics  # noqa: E402  (reuse the model + metric code)

TRAFFIC = os.path.join(ML, "corpus", "traffic")
CSIC = os.path.join(ML, "corpus", "csic")


def load_jsonl(path: str):
    return [json.loads(l) for l in open(path, encoding="utf-8")] if os.path.exists(path) else []


def featurize(recs):
    return np.array([extract_features(r["method"], r["uri"], [tuple(h) for h in r["headers"]])
                     for r in recs], dtype=np.float32)


def parse_csic(path: str):
    import urllib.parse
    METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
    reqs, cur = [], None
    for line in open(path, encoding="latin-1"):
        line = line.rstrip("\r\n")
        toks = line.split(" ")
        if toks and toks[0] in METHODS and len(toks) > 1:
            if cur:
                reqs.append(cur)
            p = urllib.parse.urlsplit(toks[1])
            uri = (p.path + ("?" + p.query if p.query else "")) or "/"
            cur = {"method": toks[0], "uri": uri, "headers": []}
        elif cur is not None and ":" in line and not line.startswith(" "):
            k, _, v = line.partition(":")
            cur["headers"].append((k.strip(), v.strip()))
    if cur:
        reqs.append(cur)
    return reqs


def main() -> None:
    rng = np.random.default_rng(1337)
    torch.manual_seed(1337)

    atk = load_jsonl(os.path.join(TRAFFIC, "attack.jsonl"))
    ben = load_jsonl(os.path.join(TRAFFIC, "benign.jsonl"))
    print(f"  loaded: {len(atk)} attack, {len(ben)} benign")

    # Balance by downsampling the majority class.
    k = min(len(atk), len(ben))
    atk = [atk[i] for i in rng.permutation(len(atk))[:k]]
    ben = [ben[i] for i in rng.permutation(len(ben))[:k]]

    X = np.vstack([featurize(atk), featurize(ben)])
    y = np.array([1] * len(atk) + [0] * len(ben), dtype=np.float32)
    perm = rng.permutation(len(y))
    X, y = X[perm], y[perm]
    cut = int(0.8 * len(y))
    Xtr, ytr, Xte, yte = X[:cut], y[:cut], X[cut:], y[cut:]

    model = Scorer(16, 24)
    opt = torch.optim.Adam(model.parameters(), lr=2e-3, weight_decay=1e-5)
    lossf = torch.nn.BCELoss()
    ds = torch.utils.data.TensorDataset(torch.from_numpy(Xtr), torch.from_numpy(ytr).unsqueeze(1))
    dl = torch.utils.data.DataLoader(ds, batch_size=256, shuffle=True)
    model.train()
    for ep in range(120):
        for xb, yb in dl:
            opt.zero_grad()
            loss = lossf(model(xb), yb)
            loss.backward()
            opt.step()

    model.eval()
    with torch.no_grad():
        pte = model(torch.from_numpy(Xte)).squeeze(1).numpy()
    m = metrics(yte, pte)
    print(f"\n  IN-DISTRIBUTION (held-out real traffic): auc={m['auc']:.4f} "
          f"f1={m['f1']:.4f} prec={m['precision']:.4f} rec={m['recall']:.4f}")

    out = os.path.join(ML, "waf-scorer-traffic.onnx")
    torch.onnx.export(model, torch.zeros(1, 16), out,
                      input_names=["features"], output_names=["score"], opset_version=13)
    print(f"  exported → {out}")

    # ── The real test: cross-source on the CSIC sample ──
    def score_np(recs):
        with torch.no_grad():
            return model(torch.from_numpy(featurize(recs))).squeeze(1).numpy()

    print("\n  ══ CROSS-SOURCE on real CSIC sample (the synthetic model got 0/9) ══")
    for label, fname in (("normal", "normal_sample.txt"), ("anomalous", "anomalous_sample.txt")):
        p = os.path.join(CSIC, fname)
        if not os.path.exists(p):
            continue
        recs = parse_csic(p)
        if not recs:
            continue
        s = np.clip(score_np(recs), 0, 1)
        hi = int((s >= 0.5).sum())
        print(f"    {label:<10} n={len(recs):<4} mean={s.mean():.3f}  scored≥0.5: {hi}/{len(recs)} ({100*hi/len(recs):.0f}%)")


if __name__ == "__main__":
    main()
