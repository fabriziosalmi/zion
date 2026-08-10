# SPDX-License-Identifier: Apache-2.0
"""Body-aware feature extension for the ML-WAF scorer.

The shipped 16 features (features.py) see only method+URI+headers — blind to POST
bodies, where much real injection/tampering lives. This adds 6 STRUCTURAL body
features (the same shapes as the URI ones, so a future Rust port is mechanical):

   16  body_len_norm       len / 8192, clamp 1
   17  body_entropy        byte entropy / 8
   18  body_special_chars  <>'"\\;() count / len
   19  body_pct_encoded    '%' count / len
   20  body_digits_ratio   ascii-digit count / len
   21  body_unprintable    non-printable bytes / len

=> a 22-dim vector. Deliberately structural (no keyword lists — that's the rule
engine's job); the ML learns shape, not signatures.
"""

from __future__ import annotations

import os
import sys
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from features import FEATURE_DIM, _SPECIAL, byte_entropy, extract_features  # noqa: E402

BODY_DIM = 6
EXT_DIM = FEATURE_DIM + BODY_DIM  # 22


def body_features(body) -> List[float]:
    bb = body.encode("utf-8", "replace") if isinstance(body, str) else (body or b"")
    n = len(bb)
    f = [0.0] * BODY_DIM
    f[0] = min(n / 8192.0, 1.0)
    f[1] = byte_entropy(bb) / 8.0
    if n:
        spec = pct = dig = unp = 0
        for b in bb:
            if b in _SPECIAL:
                spec += 1
            if b == 0x25:
                pct += 1
            if 0x30 <= b <= 0x39:
                dig += 1
            if not (b == 0x09 or 0x20 <= b <= 0x7E):
                unp += 1
        f[2] = min(spec / n, 1.0)
        f[3] = min(pct / n, 1.0)
        f[4] = dig / n
        f[5] = unp / n
    return f


def extract_ext(method: str, uri: str, headers, body) -> List[float]:
    """22-dim: the 16 URI+header features + 6 body features."""
    return list(extract_features(method, uri, headers)) + body_features(body)
