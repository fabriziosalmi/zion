# SPDX-License-Identifier: Apache-2.0
"""Synthetic labeled request corpus for the ML-WAF scorer.

Attacks (label 1) are seeded from Zion's OWN WAF signature vocabulary
(``ml/testdata/waf_signatures.json``, dumped from ``waf.rs``) embedded into
varied request shapes — so the model learns to agree with, and generalize
around, the deployed rule engine. Benign (label 0) come from realistic
API / static / page templates with real User-Agents and header sets.

Everything is deterministic (seeded) and 100% synthetic — NO captured traffic,
ever. Each row is featurized with the parity-verified extractor in features.py.

    python3 ml/generate_corpus.py --n 6000 --seed 1337 --out ml/corpus/dataset.npz

Outputs the featurized dataset (X: float32 [N,16], y: int [N], plus the raw
requests) and prints a review summary (class balance, per-class feature means,
sample requests). The .npz is regenerable and gitignored; the generator source
+ the summary are the review material.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import urllib.parse
from typing import List, Tuple

import numpy as np

from features import FEATURE_DIM, extract_features

Headers = List[Tuple[str, str]]
Request = Tuple[str, str, Headers]  # (method, uri, headers)

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNATURES = os.path.join(HERE, "testdata", "waf_signatures.json")

# ── Realistic building blocks (benign) ──────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "okhttp/4.11.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "kube-probe/1.28",
]
RESOURCES = ["users", "orders", "products", "invoices", "sessions", "carts",
             "articles", "comments", "events", "tickets", "projects", "files"]
CATEGORIES = ["electronics", "books", "clothing", "home-garden", "toys", "sports"]
SLUGS = ["getting-started", "release-notes-v2", "why-rust", "scaling-to-1m-rps",
         "a-guide-to-tls", "observability-101"]
STATIC_EXT = ["js", "css", "png", "jpg", "svg", "woff2", "webp", "ico"]
BENIGN_WORDS = ["laptop", "running shoes", "coffee maker", "wireless mouse",
                "office chair", "phone case", "water bottle", "yoga mat",
                "invoice 2024", "quarterly report", "team offsite"]
ACCEPTS = ["text/html,application/xhtml+xml", "application/json", "*/*",
           "text/css,*/*;q=0.1"]


def _rand_hash(rng: random.Random, n: int = 8) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def benign_request(rng: random.Random) -> Request:
    """One realistic, attack-free request."""
    kind = rng.choices(
        ["api_get", "api_list", "static", "page", "search", "health", "api_write", "rich_query"],
        weights=[24, 16, 20, 11, 7, 6, 8, 8],
    )[0]
    ua = rng.choice(USER_AGENTS)
    headers: Headers = [("user-agent", ua), ("accept", rng.choice(ACCEPTS))]

    if kind == "rich_query":
        # Benign but structurally rich: RAW special chars + parens/commas in a
        # legitimate filter, so the model can't treat "<>()" as attack-only.
        expr = rng.choice([
            "price>100", "(sale)", "size:large,red", 'name="acme"',
            "rating>=4", "a & b", "cost<50", "(new)&(featured)",
        ])
        keep = '<>()=&,"'  # leave benign special chars RAW (not %-encoded)
        uri = f"/api/v1/{rng.choice(RESOURCES)}?filter={urllib.parse.quote(expr, safe=keep)}"
        return ("GET", uri, headers)

    if kind == "api_get":
        uri = f"/api/v1/{rng.choice(RESOURCES)}/{rng.randint(1, 999999)}"
        if rng.random() < 0.4:
            headers.append(("authorization", f"Bearer {_rand_hash(rng, 24)}"))
    elif kind == "api_list":
        uri = (f"/api/v1/{rng.choice(RESOURCES)}"
               f"?page={rng.randint(1, 50)}&limit={rng.choice([10, 20, 50, 100])}"
               f"&sort={rng.choice(['created_at', '-updated_at', 'name'])}")
    elif kind == "static":
        ext = rng.choice(STATIC_EXT)
        uri = f"/static/{rng.choice(['app', 'vendor', 'main', 'chunk'])}.{_rand_hash(rng)}.{ext}"
        headers.append(("accept-encoding", rng.choice(["gzip, deflate, br", "gzip"])))
    elif kind == "page":
        uri = rng.choice(["/", "/about", "/pricing", "/contact",
                          f"/products/{rng.choice(CATEGORIES)}",
                          f"/blog/{rng.choice(SLUGS)}"])
        if rng.random() < 0.5:
            headers.append(("cookie", f"sid={_rand_hash(rng, 32)}; theme=dark"))
        if rng.random() < 0.3:
            headers.append(("referer", "https://www.google.com/"))
    elif kind == "search":
        q = urllib.parse.quote(rng.choice(BENIGN_WORDS))
        uri = f"/search?q={q}&page={rng.randint(1, 5)}"
    elif kind == "health":
        return (rng.choice(["GET"]), rng.choice(["/healthz", "/metrics", "/api/status", "/ready"]),
                [("user-agent", rng.choice(["kube-probe/1.28", "Prometheus/2.48"]))])
    else:  # api_write
        method = rng.choice(["POST", "PUT", "PATCH", "DELETE"])
        uri = f"/api/v1/{rng.choice(RESOURCES)}"
        if method != "POST":
            uri += f"/{rng.randint(1, 9999)}"
        headers.append(("content-type", "application/json"))
        headers.append(("authorization", f"Bearer {_rand_hash(rng, 24)}"))
        return (method, uri, headers)

    return ("GET", uri, headers)


# ── Attack shaping (seeded from real signatures) ────────────────────────────

def load_signatures() -> List[str]:
    with open(SIGNATURES) as fh:
        doc = json.load(fh)
    # De-dupe while preserving the two lists' union.
    seen, out = set(), []
    for p in doc["balanced"] + doc["aggressive"]:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def attack_request(rng: random.Random, payload: str) -> Request:
    """Embed a signature payload into a plausible malicious request."""
    ua = rng.choice(USER_AGENTS + ["sqlmap/1.7", "() { :;}; /bin/bash", "-"])
    enc = urllib.parse.quote(payload, safe="") if rng.random() < 0.45 else payload

    def base() -> Headers:
        # An attacker's request looks like anyone's: it can carry a session
        # cookie or a stolen/valid Bearer token. Not tying auth/cookie to the
        # benign class stops the model learning "has_auth ⇒ safe" (evadable).
        h: Headers = [("user-agent", ua)]
        if rng.random() < 0.30:
            h.append(("authorization", f"Bearer {_rand_hash(rng, 24)}"))
        if rng.random() < 0.30:
            h.append(("cookie", f"sid={_rand_hash(rng, 32)}"))
        return h

    shape = rng.choices(
        ["query", "path", "api_query", "nested", "ua", "referer", "cookie", "post_login"],
        weights=[24, 14, 18, 10, 8, 8, 8, 10],
    )[0]

    if shape == "query":
        return ("GET", f"/search?q={enc}", base())
    if shape == "path":
        return ("GET", f"/{enc}", base())
    if shape == "api_query":
        param = rng.choice(["id", "filter", "user", "file", "redirect", "cmd"])
        return ("GET", f"/api/v1/{rng.choice(RESOURCES)}?{param}={enc}", base())
    if shape == "nested":
        return ("GET", f"/app/{enc}/view", base())
    if shape == "ua":
        # payload smuggled in the UA header; benign-looking path
        return ("GET", "/", [("user-agent", payload)])
    if shape == "referer":
        return ("GET", "/dashboard", [("user-agent", ua), ("referer", f"https://evil.example/{enc}")])
    if shape == "cookie":
        return ("GET", "/account", [("user-agent", ua), ("cookie", f"sid={enc}")])
    # post_login
    return ("POST", f"/api/login?u={enc}",
            [("user-agent", ua), ("content-type", "application/x-www-form-urlencoded")])


# ── Corpus assembly ─────────────────────────────────────────────────────────

def build(n: int, seed: int, benign_frac: float) -> Tuple[np.ndarray, np.ndarray, List[Request]]:
    rng = random.Random(seed)
    sigs = load_signatures()
    n_benign = int(round(n * benign_frac))
    n_attack = n - n_benign

    reqs: List[Request] = []
    for _ in range(n_benign):
        reqs.append(benign_request(rng))
    for _ in range(n_attack):
        reqs.append(attack_request(rng, rng.choice(sigs)))
    labels = [0] * n_benign + [1] * n_attack

    # Shuffle in lockstep.
    idx = list(range(len(reqs)))
    rng.shuffle(idx)
    reqs = [reqs[i] for i in idx]
    labels = [labels[i] for i in idx]

    X = np.array([extract_features(m, u, h) for (m, u, h) in reqs], dtype=np.float32)
    y = np.array(labels, dtype=np.int64)
    return X, y, reqs


def summarize(X: np.ndarray, y: np.ndarray, reqs: List[Request]) -> None:
    n = len(y)
    n_atk = int(y.sum())
    print(f"\n=== corpus: {n} requests — {n - n_atk} benign / {n_atk} attack "
          f"({100 * n_atk / n:.1f}% attack) ===")
    names = ["uri_len", "uri_entropy", "pct_enc", "special", "digits", "depth",
             "is_post", "hdr_cnt", "hdr_bytes", "has_ua", "has_ref", "has_cookie",
             "has_auth", "ua_entropy", "has_ct", "unprint"]
    bmean = X[y == 0].mean(axis=0)
    amean = X[y == 1].mean(axis=0)
    print(f"\n  {'feature':<12} {'benign μ':>9} {'attack μ':>9}  Δ")
    for i, nm in enumerate(names):
        d = amean[i] - bmean[i]
        flag = "  <== " if abs(d) > 0.05 else ""
        print(f"  {nm:<12} {bmean[i]:>9.4f} {amean[i]:>9.4f}  {d:+.4f}{flag}")

    print("\n  sample BENIGN:")
    benign_reqs = [r for r, l in zip(reqs, y) if l == 0]
    for m, u, h in benign_reqs[:4]:
        print(f"    {m:<6} {u[:70]}")
    print("  sample ATTACK:")
    attack_reqs = [r for r, l in zip(reqs, y) if l == 1]
    for m, u, h in attack_reqs[:6]:
        hint = f"  [UA={h[0][1][:30]}]" if u in ("/", "/dashboard", "/account") else ""
        print(f"    {m:<6} {u[:70]}{hint}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--benign-frac", type=float, default=0.55)
    ap.add_argument("--out", default=os.path.join(HERE, "corpus", "dataset.npz"))
    args = ap.parse_args()

    X, y, reqs = build(args.n, args.seed, args.benign_frac)
    summarize(X, y, reqs)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    raw = json.dumps([{"method": m, "uri": u, "headers": h} for (m, u, h) in reqs])
    np.savez_compressed(args.out, X=X, y=y, raw=raw)
    print(f"\nwrote {len(y)} rows → {args.out}")


if __name__ == "__main__":
    main()
