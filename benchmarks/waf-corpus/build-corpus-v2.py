#!/usr/bin/env python3
"""Build corpus-v2.json from public attack corpora → a higher-cardinality WAF
regression set than the hand-curated v1.

Malicious payloads are DERIVED (extracted + deduped + capped) from:
  * OWASP CRS regression tests   (Apache-2.0)  github.com/coreruleset/coreruleset
  * PayloadsAllTheThings         (MIT)         github.com/swisskyrepo/PayloadsAllTheThings
Benign payloads are hand-curated legit-but-spicy traffic (the false-positive set).

Clone both next to this script's `corpora/` dir, then run. Re-running with the
same source revisions is deterministic (sorted + capped). Pin the source commits
in the README when you cut a versioned corpus.

Usage: python3 build-corpus-v2.py [corpora_dir]   →  corpus-v2.json
"""
import sys, re, json, glob, hashlib, collections
from pathlib import Path

HERE = Path(__file__).parent
CORPORA = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "corpora"
CRS = CORPORA / "coreruleset" / "tests" / "regression" / "tests"
PATT = CORPORA / "PayloadsAllTheThings"
PER_CLASS_CAP = 130          # keep classes balanced; total malicious ~1.2k
MAXLEN = 400                 # drop pathologically long blobs

# CRS rule-dir prefix → our class
CRS_CLASS = {
    "REQUEST-941": "xss", "REQUEST-942": "sqli", "REQUEST-932": "cmdi",
    "REQUEST-930": "path", "REQUEST-931": "ssrf", "REQUEST-933": "php",
    "REQUEST-934": "generic", "REQUEST-944": "java", "REQUEST-921": "crlf",
}
# PayloadsAllTheThings dir → our class
PATT_CLASS = {
    "Command Injection": "cmdi", "SQL Injection": "sqli", "XSS Injection": "xss",
    "NoSQL Injection": "nosql", "Insecure Deserialization": "deser",
    "Server Side Template Injection": "ssti", "LDAP Injection": "ldap",
    "XPATH Injection": "xpath", "GraphQL Injection": "graphql",
    "CRLF Injection": "crlf", "Directory Traversal": "path",
    "Client Side Path Traversal": "path", "Server Side Request Forgery": "ssrf",
    "XML External Entity": "xxe", "Server Side Include Injection": "ssi",
}

buckets = collections.defaultdict(set)   # class -> set(payload)


_BENIGN_URL = re.compile(r"^https?://(example\.(com|org|net)|[\w.-]+)/?$", re.I)
_PURE_WORD = re.compile(r"^[A-Za-z0-9_-]{1,14}$")   # bare short token, no special chars


def clean(p):
    p = p.strip()
    if not p or len(p) > MAXLEN:
        return None
    if p.startswith(("#", "//", "<!--")):              # comments / headings
        return None
    if not any(33 <= ord(c) < 127 or ord(c) > 127 for c in p):
        return None
    # Drop CRS/test noise that isn't an attack: bare benign URLs + short
    # alpha-only tokens (`test`, `aint-pizza`, lone event-handler names).
    if _BENIGN_URL.match(p) or _PURE_WORD.match(p):
        return None
    return p


# ── CRS: parse regression YAMLs ─────────────────────────────────────────────
try:
    import yaml
    for d, cls in CRS_CLASS.items():
        for yf in glob.glob(str(CRS / f"{d}-*" / "**" / "*.yaml"), recursive=True):
            try:
                doc = yaml.safe_load(Path(yf).read_text(errors="replace"))
            except Exception:
                continue
            for t in (doc or {}).get("tests", []):
                for st in t.get("stages", []):
                    stage = st.get("stage", st)
                    inp = stage.get("input") or {}
                    out = stage.get("output") or {}
                    # Only positive-detection tests: a stage that EXPECTS a rule
                    # to fire is a real attack; negative/benign baselines are not.
                    expect = (out.get("log") or {}).get("expect_ids") or out.get("expect_ids")
                    if not expect:
                        continue
                    # body payload
                    data = inp.get("data")
                    if isinstance(data, list):
                        data = "\n".join(map(str, data))
                    if data and (c := clean(str(data))):
                        buckets[cls].add(c)
                    # query-string value(s) from the uri
                    uri = inp.get("uri", "")
                    if isinstance(uri, str) and "?" in uri:
                        q = uri.split("?", 1)[1]
                        for kv in q.split("&"):
                            v = kv.split("=", 1)[1] if "=" in kv else kv
                            if (c := clean(v)):
                                buckets[cls].add(c)
except ImportError:
    print("warn: PyYAML missing — skipping CRS", file=sys.stderr)

# ── PayloadsAllTheThings: Intruder/*.txt (one payload per line) ──────────────
for dirname, cls in PATT_CLASS.items():
    base = PATT / dirname
    if not base.exists():
        continue
    for txt in glob.glob(str(base / "**" / "*.txt"), recursive=True):
        for line in Path(txt).read_text(errors="replace").splitlines():
            if (c := clean(line)):
                buckets[cls].add(c)

# ── balance + assemble ──────────────────────────────────────────────────────
corpus = []
for cls, payloads in sorted(buckets.items()):
    # deterministic sample: sort, then cap (stable hash tie-break keeps variety)
    ordered = sorted(payloads, key=lambda p: (hashlib.md5(p.encode()).hexdigest(), p))
    for p in ordered[:PER_CLASS_CAP]:
        corpus.append({"category": cls, "kind": "mal", "payload": p})

# ── benign (false-positive testers) — hand-curated legit-but-spicy ──────────
BENIGN = [
 "SELECT a plan that fits your team", "I'll alert you the moment it's ready",
 "the union of designers and engineers", "price > 100 AND rating < 5 stars",
 "1=1 is a tautology we cover in math class", "O'Brien", "D'Angelo & Sons, Inc.",
 "user@example.com", "https://maps.example.com/?q=cafe+near+me", "function() { return total * 1.2; }",
 "<b>Bold</b> and <i>italic</i> text", "path/to/my/report.2024.json", "drop me an email when you can",
 "a great script for the school play", "SELECT-O-MATIC vacuum, model X", "comment count: 42; likes: 1337",
 "2 * 7 = 14 and 7 * 7 = 49", "order by date, then by name please", "the cat sat on the mat",
 "{\"name\":\"Acme\",\"qty\":3,\"price\":9.99}", "search: best practices for REST APIs", "passwd reset link requested",
 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abc", "git commit -m 'fix the parser'",
 "let x = a && b || c;", "the script kiddie movie was fun", "100% organic & fair-trade",
 "regex: ^[a-z]+$ matches lowercase", "a < b and b > c", "<!-- this is an HTML comment -->",
 "SELECT * is an anti-pattern, avoid it", "alert: low disk space on /var", "the password must be 12+ chars",
 "Q1 revenue grew 7*7 percent (kidding)", "DROP-DOWN menu styling", "use UNION types in TypeScript",
 "../docs/readme.md relative link", "cmd+shift+p opens the palette", "{{ user.name }} in a Jinja template doc",
 "$HOME/.config/app.toml", "exec summary attached", "id: 12345, name: Acme Corp",
 "onclick handlers should be CSP-safe", "the order by which we ship matters", "select your seat from the map",
 "I command the room when I present", "traverse the directory tree carefully", "inject some humor into the deck",
 "a template for the quarterly review", "evaluate the proposal by Friday", "concatenate the two reports",
 "https://en.wikipedia.org/wiki/SQL_injection", "the article explains XSS for beginners",
 "our LDAP directory lists 400 staff", "the GraphQL schema has 30 types", "deserialize the JSON into a struct",
 "char limit is 280 like old Twitter", "true && ready to ship", "x = y == z ? 1 : 0",
 "the union meeting is at 5pm", "drop the puck — hockey starts!", "ping me on Slack",
 "curl up with a good book", "the cat command prints files", "we use bash for our scripts",
 "ls of attendees attached", "echo chamber of opinions", "rm stands for 'remove' in Unix class",
 "a 1' golf putt", "she said \"hello\" and waved", "co-op & condo listings",
 "name: O'Reilly Media", "the file is at C:/Users/me/doc.txt", "rate: 5 > 4 > 3 stars",
 "100 OR more attendees expected", "AND/OR logic gates lecture", "the SELECT committee meets Tuesday",
 "<h1>Welcome</h1> to our site", "<a href=\"https://example.com\">link</a>", "markdown **bold** and _italic_",
 "the proto file defines the API", "constructor of the class takes 2 args", "an object with id and name fields",
 "system design interview prep", "process the queue in order", "runtime is O(n log n)",
 "the template literal `${name}` in JS docs", "use && to chain commands in the tutorial",
 "café, naïve, résumé — accented words", "emoji test: rocket and sparkles", "Tokyo, Japan — 35.6N",
 "two plus two equals four", "the quick brown fox jumps", "lorem ipsum dolor sit amet",
 "version 1.2.3 released today", "ticket #4567 is resolved", "discount code SAVE20 applied",
 "meeting notes: action items below", "the API returns 200 on success", "HTTP 404 means not found",
 "JSON over HTTPS is standard", "OAuth2 bearer token in header", "rate limit: 100 req/min",
 "the cache TTL is 3600 seconds", "gzip compression enabled", "CDN edge in eu-west-1",
 "select all that apply", "union square is in NYC", "the drop ceiling needs repair",
 "command line interface basics", "path of least resistance", "template ready for review",
 "we evaluate vendors quarterly", "the script for episode 3", "alert fatigue is real",
 "inject confidence into the team", "traverse from A to B", "a benign query: products?sort=price",
 "search?q=rust+web+framework", "filter by category=books", "page=2&limit=20",
 "user-agent: Mozilla/5.0 normal browser", "referer from our own domain", "accept: application/json",
 "the form has name and email fields", "upload a profile picture", "comment posted successfully",
 "shopping cart has 3 items", "checkout total is $49.99", "shipping to 90210",
 "the README explains setup", "see CONTRIBUTING.md for guidelines", "license is Apache-2.0",
 "stack trace truncated for brevity", "log level set to INFO", "debug mode is off in prod",
]

for p in BENIGN:
    corpus.append({"category": "benign", "kind": "benign", "payload": p})

mal = sum(1 for c in corpus if c["kind"] == "mal")
ben = sum(1 for c in corpus if c["kind"] == "benign")
(HERE / "corpus-v2.json").write_text(json.dumps(corpus, ensure_ascii=False, indent=1))
print(f"wrote corpus-v2.json — {len(corpus)} entries ({mal} malicious / {ben} benign)")
print("per-class:", dict(sorted(collections.Counter(c["category"] for c in corpus if c["kind"]=="mal").items())))
