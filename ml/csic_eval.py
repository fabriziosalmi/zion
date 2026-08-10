# SPDX-License-Identifier: Apache-2.0
"""Cross-source reality check: score REAL CSIC-2010-format requests with the
model trained on our SYNTHETIC corpus. If the synthetic model transfers, real
attacks score high and real-normal scores low. If it doesn't, that quantifies
how much the synthetic model overfit template artifacts (ADR-0023).

The CSIC raw format is one request per block:
    <METHOD> http://host:port/path?query [HTTP/x]
    Header: value
    ...
    <blank line>
    [body for POST]

NOTE: the sample here is a small fragment (mirror limitation), and our feature
set is URI+headers only — CSIC puts many payloads in the POST *body*, which the
16 features do not see (body-aware features are a known follow-up). Read the
numbers as directional, not a verdict.

    python3 ml/csic_eval.py --model ml/waf-scorer.onnx --dir ml/corpus/csic
"""

from __future__ import annotations

import argparse
import glob
import os
import urllib.parse

import numpy as np
import onnxruntime as ort

from features import extract_features

METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")


def parse_csic(path: str):
    """Yield (method, uri, headers) from a CSIC raw dump."""
    reqs = []
    cur = None
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            line = line.rstrip("\n").rstrip("\r")
            first = line.split(" ", 1)[0]
            if first in METHODS and ("http://" in line or line.split(" ")[1:2] and line.split(" ")[1].startswith("/")):
                if cur:
                    reqs.append(cur)
                parts = line.split(" ")
                url = parts[1] if len(parts) > 1 else "/"
                # strip scheme://host → path?query (the request-target)
                p = urllib.parse.urlsplit(url)
                uri = p.path + (("?" + p.query) if p.query else "")
                cur = {"method": parts[0], "uri": uri or "/", "headers": []}
            elif cur is not None and ":" in line and line and not line.startswith(" "):
                k, _, v = line.partition(":")
                cur["headers"].append((k.strip(), v.strip()))
            # blank lines / body ignored (features are URI+headers only)
    if cur:
        reqs.append(cur)
    return reqs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.path.join(os.path.dirname(__file__), "waf-scorer.onnx"))
    ap.add_argument("--dir", default=os.path.join(os.path.dirname(__file__), "corpus", "csic"))
    args = ap.parse_args()

    sess = ort.InferenceSession(args.model, providers=["CPUExecutionProvider"])
    iname = sess.get_inputs()[0].name

    def score(r):
        x = np.asarray(extract_features(r["method"], r["uri"], r["headers"]),
                       dtype=np.float32).reshape(1, 16)
        return float(np.clip(sess.run(None, {iname: x})[0].ravel()[0], 0, 1))

    for label, pat in (("normal", "*normal*"), ("anomalous", "*anomal*")):
        files = glob.glob(os.path.join(args.dir, pat))
        reqs = [r for f in files for r in parse_csic(f)]
        if not reqs:
            print(f"  {label}: no requests parsed from {pat}")
            continue
        s = np.array([score(r) for r in reqs])
        hi = int((s >= 0.5).sum())
        print(f"  {label:<10} n={len(reqs):<4} mean={s.mean():.3f} "
              f"median={np.median(s):.3f}  scored≥0.5: {hi}/{len(reqs)} ({100*hi/len(reqs):.0f}%)")
        for r in reqs[:3]:
            print(f"      {score(r):.3f}  {r['method']} {r['uri'][:64]}")


if __name__ == "__main__":
    main()
