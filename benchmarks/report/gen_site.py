#!/usr/bin/env python3
"""Generate the example site every release report serves as its origin.

The site is a stand-in for a small production web property: a landing page and 40
document pages (compressible text), a JS/CSS bundle with content-hashed names, three
fonts, 60 photos (incompressible), 120 small JSON API documents and one 10 MiB
download. The sizes follow a typical single-page-app deployment; the point is that
the mix is fixed, not that it is anybody's real site.

It is deterministic to the byte. The generator uses its own PRNG (SplitMix64) and no
`random` module, no clock and no environment, so the same SEED gives the same tree on
any Python 3.8+. `manifest.json` lists every file with its size and sha256, and
`SITE_SHA256` (printed, and written to `site.sha256`) is the hash of that manifest: a
report states it, and a reader can regenerate the site and check they measured the same
bytes.

    gen_site.py OUTDIR [--seed N]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SEED = 0x5A10_0000_2026_1008
MASK = (1 << 64) - 1


class Rng:
    """SplitMix64: tiny, fast, and specified by its reference implementation."""

    def __init__(self, seed: int):
        self.s = seed & MASK

    def next(self) -> int:
        self.s = (self.s + 0x9E3779B97F4A7C15) & MASK
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return z ^ (z >> 31)

    def below(self, n: int) -> int:
        return self.next() % n

    def between(self, lo: int, hi: int) -> int:
        return lo + self.below(hi - lo + 1)

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out += self.next().to_bytes(8, "little")
        return bytes(out[:n])


SYLLABLES = ["ka", "to", "ri", "ne", "so", "lu", "ma", "vi", "de", "po", "an", "el",
             "or", "is", "ba", "gu", "chi", "sta", "pre", "con", "tra", "ver", "mon", "dis"]


def vocabulary(rng: Rng) -> list[str]:
    words = []
    for _ in range(600):
        words.append("".join(SYLLABLES[rng.below(len(SYLLABLES))] for _ in range(rng.between(1, 4))))
    return words


def prose(rng: Rng, vocab: list[str], size: int) -> str:
    """Text of about `size` bytes with a skewed word distribution, so it compresses
    the way prose does (roughly 3:1) and not like random bytes."""
    out, n = [], 0
    while n < size:
        # square the draw: low indexes (common words) come up far more often
        i = (rng.below(len(vocab)) * rng.below(len(vocab))) // len(vocab)
        w = vocab[i]
        out.append(w)
        n += len(w) + 1
        if rng.below(14) == 0:
            out.append(".")
    return " ".join(out)


def html_page(title: str, body: str, links: list[str], assets: dict[str, str]) -> bytes:
    nav = "".join(f'<li><a href="{h}">{h}</a></li>' for h in links)
    paras = "".join(f"<p>{p}</p>\n" for p in body.split(". "))
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{title}</title>"
        f'<link rel="stylesheet" href="{assets["css"]}">'
        f'<link rel="preload" href="{assets["font"]}" as="font" crossorigin>'
        f'<script src="{assets["vendor"]}" defer></script><script src="{assets["app"]}" defer></script>'
        f"</head><body><nav><ul>{nav}</ul></nav><main><h1>{title}</h1>\n{paras}</main></body></html>\n"
    ).encode()


def json_doc(rng: Rng, vocab: list[str], i: int, size: int) -> bytes:
    items, n = [], 0
    while n < size:
        it = {"id": rng.below(10**9), "name": vocab[rng.below(len(vocab))],
              "score": rng.below(10**6) / 1000, "tags": [vocab[rng.below(len(vocab))] for _ in range(3)],
              "active": rng.below(2) == 1}
        s = json.dumps(it, separators=(",", ":"))
        items.append(it)
        n += len(s) + 1
    return json.dumps({"id": i, "items": items}, separators=(",", ":")).encode()


def build(out: Path, seed: int) -> dict:
    rng = Rng(seed)
    vocab = vocabulary(rng)
    files: dict[str, bytes] = {}

    def put(path: str, data: bytes) -> str:
        files[path] = data
        return "/" + path

    js_app = prose(rng, vocab, 380_000).encode()
    js_vendor = prose(rng, vocab, 1_100_000).encode()
    css = prose(rng, vocab, 96_000).encode()
    h = lambda b: hashlib.sha256(b).hexdigest()[:8]  # noqa: E731
    assets = {
        "app": put(f"assets/app.{h(js_app)}.js", js_app),
        "vendor": put(f"assets/vendor.{h(js_vendor)}.js", js_vendor),
        "css": put(f"assets/style.{h(css)}.css", css),
    }
    for w in (400, 600, 700):
        p = put(f"fonts/inter-{w}.woff2", rng.bytes(48_000))
        assets.setdefault("font", p)
    for i in range(1, 61):
        put(f"img/photo-{i:02d}.jpg", rng.bytes(rng.between(16_000, 420_000)))
    for i in range(1, 121):
        put(f"api/item-{i:03d}.json", json_doc(rng, vocab, i, rng.between(1_000, 8_000)))
    put("download/archive-10m.bin", rng.bytes(10 << 20))
    put("favicon.ico", rng.bytes(4_286))
    put("robots.txt", b"User-agent: *\nAllow: /\n")

    pages = [f"docs/page-{i:02d}.html" for i in range(1, 41)]
    for p in pages:
        put(p, html_page(f"Page {p[-7:-5]}", prose(rng, vocab, rng.between(6_000, 64_000)),
                         ["/index.html"] + ["/" + q for q in pages[:6]], assets))
    put("index.html", html_page("Example site", prose(rng, vocab, 24_000),
                                ["/" + q for q in pages], assets))

    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for path in sorted(files):
        data = files[path]
        dest = out / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        manifest.append({"path": "/" + path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    body = json.dumps({"seed": seed, "files": manifest}, indent=1, sort_keys=True) + "\n"
    (out / "manifest.json").write_text(body)
    return {"manifest": body, "files": len(manifest), "bytes": sum(m["bytes"] for m in manifest)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--seed", type=int, default=SEED)
    a = ap.parse_args()
    r = build(a.outdir, a.seed)
    digest = hashlib.sha256(r["manifest"].encode()).hexdigest()
    (a.outdir / "site.sha256").write_text(digest + "\n")
    print(f"{r['files']} files, {r['bytes']} bytes", file=sys.stderr)
    print(digest)


if __name__ == "__main__":
    main()
