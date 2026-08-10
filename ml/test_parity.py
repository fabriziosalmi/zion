# SPDX-License-Identifier: Apache-2.0
"""Cross-language parity: assert ``features.py`` reproduces, to f32 precision,
the vectors Zion's Rust extractor produced for the same inputs.

The golden file is emitted by the Rust generator:

    cargo test --features ml-waf gen_golden_features -- --ignored --nocapture

Run:  python3 ml/test_parity.py   (also discoverable by pytest)
"""

import json
import os

from features import FEATURE_DIM, extract_features

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "testdata", "golden_features.json")

# Rust computes in f32, Python in f64; the ops are simple divisions + a log2
# entropy sum, so the two agree well under this bound. Tightening it below ~1e-6
# would start flagging pure f32-vs-f64 rounding, not real drift.
TOL = 1e-5


def test_parity() -> None:
    with open(GOLDEN) as fh:
        records = json.load(fh)
    assert records, "golden file is empty — regenerate it (see module docstring)"

    max_err = 0.0
    for rec in records:
        headers = [(h[0], h[1]) for h in rec["headers"]]
        got = extract_features(rec["method"], rec["uri"], headers)
        exp = rec["features"]
        assert len(got) == len(exp) == FEATURE_DIM
        for i, (g, e) in enumerate(zip(got, exp)):
            err = abs(g - e)
            max_err = max(max_err, err)
            assert err < TOL, (
                f"mismatch at feature[{i}] for {rec['method']} {rec['uri']!r}: "
                f"python={g!r} rust={e!r} (|Δ|={err:.2e} ≥ {TOL})"
            )
    print(f"parity OK — {len(records)} records × {FEATURE_DIM} features, "
          f"max |Δ| = {max_err:.2e}")


if __name__ == "__main__":
    test_parity()
