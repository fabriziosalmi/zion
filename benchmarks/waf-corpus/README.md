# WAF corpus — detection / false-positive regression baseline

Stop *asserting* WAF coverage, start *measuring* it. This fires a fixed,
versioned corpus of attack + benign payloads at a WAF-protected zion route and
reports **detection rate** (recall on the malicious set) and **false-positive
rate** (benign traffic wrongly blocked). It is a **regression baseline**, not an
authoritative WAF score — a hand-curated starting point to improve against.

## Corpus

`corpus.json` — **200 entries**: 150 malicious across 15 attack classes (SQLi,
XSS, command injection, path traversal, SSRF, Log4Shell/JNDI, SSTI, XXE, NoSQL,
LDAP, CRLF/response-splitting, open-redirect, deserialization/proto-pollution,
GraphQL, header injection) + 50 **benign-but-spicy** payloads (legit traffic
that *looks* attack-ish: `O'Brien`, `SELECT a plan`, `the union of…`, `1=1
tautology`, `<b>bold</b>`, JWT-like blobs, code snippets, unicode) — the
false-positive testers.

It is **stable on purpose**: keep v1 intact for cross-version comparability.
Regenerate from the authoring source with `python3 build-corpus.py`. Grow it to a
higher-cardinality v2 by sourcing from public corpora (OWASP CRS regression
suite, PayloadsAllTheThings, fuzzdb) rather than inventing payloads.

## Run

Start a zion with a WAF-protected `/api/*` route (block = HTTP 400), then:

```bash
# balanced (default): ZION_CONFIG=benchmarks/zion-bench-tls-waf.toml ./target/release/zion
python3 benchmarks/waf-corpus/run.py https://127.0.0.1:4431 "zion balanced"
```

Each payload is fired in **both** vectors (query string + JSON body); a payload
counts as detected if **either** is blocked. `run.py` exits non-zero if any
benign payload is blocked — **a false positive is a hard fail** (precision is the
non-negotiable; recall is the thing we improve).

## Baseline — bench #0 (v0.4.3, balanced ~100 / aggressive ~190 patterns)

| Profile | Detection | False positives |
|---|--:|--:|
| **balanced** (default) | **50.0%** (75/150) | **0.0%** (0/50) |
| **aggressive** | **64.7%** (97/150) | **0.0%** (0/50) |

Per-class recall is uneven — strong on XSS (100% aggressive), path, XXE, CRLF;
weak on **command injection (~33%)**, deserialization, header injection, and
internal SSRF. **Zero false positives** on the benign set in both profiles: the
high-precision posture the design claims, now measured.

The point of #0: every WAF-pattern change can now be scored as a Δ in detection
**at constant 0% FP**, instead of asserted. Plug the holes, re-run, watch the
number move.
