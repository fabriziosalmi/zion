# SPDX-License-Identifier: Apache-2.0
"""16-dim WAF feature extractor — an exact port of Zion's Rust
``waf_ml::extract_features`` (``src/waf_ml.rs``).

Training features MUST equal inference features, byte-for-byte, or a model
trained here scores garbage in production. This port is therefore pinned by
``ml/test_parity.py`` against golden vectors emitted from the Rust code itself
(``cargo test --features ml-waf gen_golden_features -- --ignored``).

Index map — keep in lockstep with ``src/waf_ml.rs``::

    0  uri_len_norm       len / 4096, clamp 1
    1  uri_entropy        byte entropy / 8
    2  uri_pct_encoded    '%' count / len, clamp 1
    3  uri_special_chars  <>'"\\;() count / len, clamp 1
    4  uri_digits_ratio   ascii-digit count / len
    5  uri_path_depth     '/' count / 16, clamp 1
    6  is_post            method in {POST, PUT, PATCH}
    7  header_count_norm  header count / 64, clamp 1
    8  total_header_bytes sum(value byte lens) / 8192, clamp 1
    9  has_user_agent
   10  has_referer
   11  has_cookie
   12  has_auth
   13  ua_entropy         User-Agent byte entropy / 8 (0 if absent)
   14  has_content_type
   15  unprintable_ratio  non-printable bytes / len
"""

from __future__ import annotations

import math
from typing import Iterable, List, Optional, Sequence, Tuple

FEATURE_DIM = 16

# Rust: b'<' | b'>' | b'\'' | b'"' | b'\\' | b';' | b'(' | b')'
_SPECIAL = frozenset(b"<>'\"\\;()")

Headers = Sequence[Tuple[str, str]]


def byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte; 0.0 on empty input (mirrors byte_entropy)."""
    if not data:
        return 0.0
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    n = len(data)
    h = 0.0
    for c in hist:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _has(headers: Headers, name: str) -> bool:
    return any(k.lower() == name for k, _ in headers)


def _get(headers: Headers, name: str) -> Optional[str]:
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def extract_features(method: str, uri: str, headers: Headers) -> List[float]:
    """Return the 16-dim feature vector for a request.

    ``headers`` is a sequence of ``(name, value)`` string pairs (order and
    duplicates preserved, exactly like the Rust ``HeaderMap`` iteration).
    """
    f = [0.0] * FEATURE_DIM
    ub = uri.encode("utf-8")  # the Rust &str's bytes are its UTF-8 encoding
    n = len(ub)

    f[0] = min(n / 4096.0, 1.0)
    f[1] = byte_entropy(ub) / 8.0

    pct = special = digits = slashes = unprintable = 0
    for b in ub:
        if b == 0x25:  # '%'
            pct += 1
        if b in _SPECIAL:
            special += 1
        if 0x30 <= b <= 0x39:  # ASCII digit
            digits += 1
        if b == 0x2F:  # '/'
            slashes += 1
        if not (b == 0x09 or 0x20 <= b <= 0x7E):  # not tab / printable ASCII
            unprintable += 1
    if n > 0:
        f[2] = min(pct / n, 1.0)
        f[3] = min(special / n, 1.0)
        f[4] = digits / n
        f[15] = unprintable / n
    f[5] = min(slashes / 16.0, 1.0)

    f[6] = 1.0 if method in ("POST", "PUT", "PATCH") else 0.0

    f[7] = min(len(headers) / 64.0, 1.0)
    total_hdr = sum(len(v.encode("utf-8")) for _, v in headers)
    f[8] = min(total_hdr / 8192.0, 1.0)

    f[9] = 1.0 if _has(headers, "user-agent") else 0.0
    f[10] = 1.0 if _has(headers, "referer") else 0.0
    f[11] = 1.0 if _has(headers, "cookie") else 0.0
    f[12] = 1.0 if _has(headers, "authorization") else 0.0
    ua = _get(headers, "user-agent")
    if ua is not None:
        f[13] = byte_entropy(ua.encode("utf-8")) / 8.0
    f[14] = 1.0 if _has(headers, "content-type") else 0.0

    return f


def batch(rows: Iterable[Tuple[str, str, Headers]]) -> List[List[float]]:
    """Featurize an iterable of (method, uri, headers) into a list of vectors."""
    return [extract_features(m, u, h) for (m, u, h) in rows]
