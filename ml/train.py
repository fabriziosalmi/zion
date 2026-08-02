# SPDX-License-Identifier: Apache-2.0
"""Train a tiny MLP attack-scorer and export it to ONNX for tract.

Deliberately small — the model runs on Zion's WAF hot path under a 200µs p99
budget (waf_ml.rs), so it's a 16→H→1 net using only Gemm/Relu/Sigmoid (all
well-supported by tract-onnx). Input shape (1,16) f32, single f32 output in
[0,1], matching waf_ml::score (reads result[0], clamps [0,1]).

    python3 ml/train.py --corpus ml/corpus/dataset.npz --out ml/waf-scorer.onnx

Metrics are printed on a held-out split. NOTE: on the SYNTHETIC corpus these
numbers reflect separability of the generator's templates, not real-world
robustness — see the ADR. Nothing is shipped from here automatically.
"""

from __future__ import annotations

import argparse
import os

import numpy as np
import torch
import torch.nn as nn


class Scorer(nn.Module):
    def __init__(self, in_dim: int = 16, hidden: int = 24):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, hidden // 2),
            nn.ReLU(),
            nn.Linear(hidden // 2, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x)


def metrics(y_true: np.ndarray, y_prob: np.ndarray, thr: float = 0.5) -> dict:
    pred = (y_prob >= thr).astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    # ROC-AUC via rank statistic (no sklearn).
    order = np.argsort(y_prob)
    ranks = np.empty_like(order, dtype=float)
    ranks[order] = np.arange(1, len(y_prob) + 1)
    n_pos, n_neg = int(y_true.sum()), int((1 - y_true).sum())
    auc = ((ranks[y_true == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)
           if n_pos and n_neg else 0.0)
    return {"precision": prec, "recall": rec, "f1": f1, "auc": auc,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "corpus", "dataset.npz"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "waf-scorer.onnx"))
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--hidden", type=int, default=24)
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    data = np.load(args.corpus, allow_pickle=True)
    X, y = data["X"].astype(np.float32), data["y"].astype(np.float32)

    # Stratified-ish split 80/20 by a seeded permutation.
    rng = np.random.default_rng(args.seed)
    perm = rng.permutation(len(y))
    X, y = X[perm], y[perm]
    cut = int(0.8 * len(y))
    Xtr, ytr, Xte, yte = X[:cut], y[:cut], X[cut:], y[cut:]

    model = Scorer(16, args.hidden)
    opt = torch.optim.Adam(model.parameters(), lr=2e-3, weight_decay=1e-5)
    lossf = nn.BCELoss()
    Xtr_t, ytr_t = torch.from_numpy(Xtr), torch.from_numpy(ytr).unsqueeze(1)

    # Mini-batch training — full-batch gradient descent barely moves a net this
    # size in a few dozen steps; SGD over shuffled batches actually converges.
    ds = torch.utils.data.TensorDataset(Xtr_t, ytr_t)
    dl = torch.utils.data.DataLoader(ds, batch_size=256, shuffle=True)
    model.train()
    for ep in range(args.epochs):
        last = 0.0
        for xb, yb in dl:
            opt.zero_grad()
            loss = lossf(model(xb), yb)
            loss.backward()
            opt.step()
            last = loss.item()
        if (ep + 1) % 20 == 0:
            print(f"  epoch {ep+1:>3}  loss {last:.4f}")

    model.eval()
    with torch.no_grad():
        prob_te = model(torch.from_numpy(Xte)).squeeze(1).numpy()
        prob_tr = model(Xtr_t).squeeze(1).numpy()
    m_te = metrics(yte, prob_te)
    m_tr = metrics(ytr, prob_tr)
    print(f"\n  TRAIN  auc={m_tr['auc']:.4f} f1={m_tr['f1']:.4f} "
          f"prec={m_tr['precision']:.4f} rec={m_tr['recall']:.4f}")
    print(f"  TEST   auc={m_te['auc']:.4f} f1={m_te['f1']:.4f} "
          f"prec={m_te['precision']:.4f} rec={m_te['recall']:.4f}  "
          f"(tp={m_te['tp']} tn={m_te['tn']} fp={m_te['fp']} fn={m_te['fn']})")

    # Export ONNX — fixed (1,16) input, matching waf_ml::score.
    dummy = torch.zeros(1, 16, dtype=torch.float32)
    torch.onnx.export(
        model, dummy, args.out,
        input_names=["features"], output_names=["score"],
        opset_version=13, dynamic_axes=None,
    )
    print(f"\n  exported ONNX → {args.out}  ({os.path.getsize(args.out)} bytes)")


if __name__ == "__main__":
    main()
