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
number move. (v1 + the cmdi/ssrf/deser/sqli rounds landed aggressive at **85.3%**
against this hand-curated set.)

## corpus-v2 — sourced from public corpora (the honest set)

`corpus-v2.json` — **~1,060 malicious** payloads extracted (deduped, balanced,
capped per class) from **OWASP CRS** regression tests (Apache-2.0, positive-
detection stages only) and **PayloadsAllTheThings** (MIT) `Intruder/*.txt`, plus
**136 benign**. Regenerate with `build-corpus-v2.py` (clone both repos under
`corpora/` first). Run it: `WAF_CORPUS=corpus-v2.json python3 run.py …`.

### Scoreboard (aggressive profile)

| State | Detection | False positives |
|---|--:|--:|
| v0.4.4 baseline | 30.9% (327/1058) | **0.0%** (0/136) |
| **+ one targeted round (v0.4.5)** | **40.6%** (430/1058) | **0.0%** (0/136) |

balanced is unchanged at **16.8%** (178/1058, 0% FP) — the round touched only the
aggressive set.

**This is the number that matters.** v1 was a textbook set and flattered the WAF
(85%); against ~1k real-world payloads the substring scanner started at **~31%**.
One FP-checked round of high-frequency literals (PHP tags/funcs `<?php`,
`system(`; Java gadget classes `java.lang.process`, `java.io.`; SSRF schemes
`file://`, `jar:`; Windows cmdi `net view`; ORM lookups `__startswith`) lifted it
to **40.6%** — java 16→45%, ssrf 12→44%, php 17→33%, generic 15→35% — at an
unchanged **0% false positives**. The gap *is* the finding: a fast zero-regex
gate, not a comprehensive WAF.

**Why we stop adding literals here.** The residual misses are no longer cheap
wins — they are base64-encoded gadget chains, `${'a'}('id')`-style PHP
variable-function obfuscation, exotic IPv6 / decimal / overlong-UTF-8 evasions,
and `while(true)` DoS probes. Enumerating patterns has sharp diminishing returns
against infinite encodings, and each broad literal risks a false positive. The
high-leverage work from here is **normalization** (the double-decode loop already
defeats `%252e%252e` and `%253Cscript%253E`; the next frontier is base64 and
bracket/char-insertion forms) and, beyond that, semantic/positive-security
analysis. Track v2 aggressive as the real regression number.
