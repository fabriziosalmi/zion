# WAF Pipeline

Zion's WAF is a 5-gate pipeline. Each gate is fail-fast: the first denial terminates inspection and returns `400 Bad Request` (or `413` for size violations). No gate uses regex; pattern matching uses the [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) algorithm — a deterministic finite automaton, no backtracking, immune to ReDoS by construction.

The Aho-Corasick automaton has two pattern sets, selected per-profile via `mode = "balanced" | "aggressive"`. See [WAF Configuration → Detection Modes](../config/waf.md#detection-modes) for the full breakdown of what lives in each set.

## Gate Architecture

```
Request Body
    │
    ▼
┌─ Gate 1: Body Size ──────────────────────────────┐
│  body.len() > max_body_mb × 1MB → DENY           │
│  Applied to all methods                          │
└──────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 2: Content-Type Validation ────────────────┐
│  Case-insensitive byte prefix match with         │
│    delimiter check ("application/jsonFOO" no     │
│    longer accepted as "application/json").       │
│  Missing Content-Type on POST/PUT/PATCH → DENY   │
│  Unknown type + deny_unknown = true → DENY       │
└──────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 3: Aho-Corasick Injection Scanner ─────────┐
│  Pattern set selected by profile mode:           │
│    balanced   → ~100 high-precision patterns     │
│    aggressive → ~240 (balanced + ~140 broad-     │
│                  substring patterns)              │
│  Two passes: raw body, then iteratively-         │
│    normalised body (URL-decode, SQL comment      │
│    strip, JSON unicode), up to 3 decode passes   │
│  Case-insensitive ASCII; built once per process  │
│    via `scanner_for(mode)` (OnceLock-cached)     │
└──────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 4: Entropy Analysis ───────────────────────┐
│  Shannon entropy. Default threshold: 6.5         │
│    bits/byte (configurable per profile).         │
│  For application/json: computed only on bytes    │
│    inside string literals, so structure /        │
│    numbers don't dilute the signal.              │
│  Skipped for bodies < 256 bytes, and when        │
│    `entropy_check = false`.                      │
└──────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 5: JSON Structural Validation ─────────────┐
│  simd-json structural validation                 │
│  Nesting depth check (manual byte scan)          │
│  String length check (keys + values)             │
│  Only applied when Content-Type = application/json│
└──────────────────────────────────────────────────┘
    │ ALLOW
    ▼
  ALLOW → Forward to upstream
```

GET, HEAD, OPTIONS skip Gates 2–5 (no body to inspect). DELETE bodies are inspected — RFC 9110 permits them and some APIs use them.

Earlier versions of this page advertised a sixth "fixed-length profiling" gate and a SIMD pre-filter using `memchr3`. Neither was ever implemented; the descriptions have been removed to keep docs and code in lock-step.

## Pattern Categories (Gate 3)

The exact pattern lists are in [`src/waf.rs`](https://github.com/fabriziosalmi/zion/blob/master/src/waf.rs) (`BALANCED_PATTERNS` and `AGGRESSIVE_EXTRA_PATTERNS`). Summary by family:

| Family | In `balanced` | Aggressive adds |
|---|---|---|
| SQL injection | Anchored quote/keyword combos: `' or '1'='1`, `union select`, `'; drop table`, `waitfor delay`, `information_schema` | Function calls / token reads: `sleep(`, `benchmark(`, `into outfile`, `load_file(`, `@@version`, `char(0x` |
| XSS | Tag-anchored + high-signal handlers: `<script`, `<iframe`, `<svg onload`, `onerror=`, `onload=`, `srcdoc=`, `javascript:` | Generic event handlers (`onclick=`, `onmouseover=`, `oninput=`, …) and JS API sinks (`alert(`, `eval(`, `document.cookie`, `innerhtml`, `expression(`, `fromcharcode`) |
| Command injection | Anchored on `;`, `|`, `$(`, backtick, newline + binary; `/etc/passwd`, `/etc/shadow` | `cmd.exe`, `powershell` |
| Path traversal | `../../`, `..\..\`, `%2e%2e%2f`, `....//`, Windows variants | — |
| SSRF / cloud metadata | AWS, GCP, Alibaba, Azure IMDS, DigitalOcean, Oracle, OpenStack, Kubernetes service host (with hex/decimal/IPv6-mapped variants) | — |
| LDAP / XXE / SSTI | Parens-anchored LDAP filters, `<!entity`, `SYSTEM "file://"`, Jinja/JSP <span v-pre>`{{7*7}}`</span> | — |
| CRLF / header injection | `%0d%0a`, `%0aset-cookie:`, `\r\nset-cookie:` | — |
| Log4Shell / JNDI | `${jndi:`, `${env:`, `${sys:` | — |
| Prototype pollution | `__proto__`, `constructor.prototype` | <span v-pre>`{{constructor`, `{{.constructor`</span>, `this.constructor` |
| PHP | `unserialize(`, `php://input`, `php://filter`, `phar://` | — |
| GraphQL introspection | `{__schema`, `{__type`, `query{__` | Lone tokens `__schema`, `__type`, `mutation{` |
| NoSQL operators | — | `$gt`, `$ne`, `$regex`, `$where`, `$lookup`, `db.collection`, `.find({` |
| Deserialization (RCE) | — | Java (`Runtime.getRuntime`, `ProcessBuilder`, `ObjectInputStream`); Python (`pickle.loads`, `__reduce__`, `__import__(`, `subprocess.call`, `os.system(`, `os.popen(`) |

## Aho-Corasick Properties

- **Algorithm**: Aho-Corasick multi-pattern matching (DFA).
- **Complexity**: O(N) where N is body length, regardless of pattern count. Adding patterns grows automaton memory (~50 bytes per pattern) but does not change scan time.
- **Construction**: Each mode's automaton is built once via `OnceLock` on first hit and reused for the process lifetime.
- **Case sensitivity**: ASCII case-insensitive.
- **No regex**: deterministic finite automaton, no backtracking.

## Entropy Analysis (Gate 4)

Shannon entropy is a heuristic for "this body looks obfuscated / encrypted / packed rather than human text or normal JSON." The default threshold sits intentionally above the theoretical maximum of pure base64 (6.0 bits/byte) so that JWTs, signed URLs, and base64 payloads pass; only near-random / encrypted blobs (~7.5–8.0 bits/byte) are flagged.

| Payload type | Typical entropy (bits/byte) | Action at default threshold (6.5) |
|---|---|---|
| English text | 3.0–4.5 | Allow |
| Typical JSON struct (with keys) | 3.5–5.5 | Allow |
| Pure base64 (theoretical max 6.0) | 5.5–6.0 | Allow |
| JWT / signed URL | 5.5–6.0 | Allow |
| Random / encrypted blob | 7.5–8.0 | **Deny** |

For `application/json` content-types, the calculation is restricted to bytes **inside string literals** — structural punctuation (`{`, `[`, `:`, `,`), whitespace, and numeric literals are skipped so they cannot dilute a high-entropy value hidden inside a single string. If the JSON has fewer than 128 string-content bytes, the gate skips entirely (insufficient sample).

The threshold is per-profile (`entropy_threshold`); the gate can be turned off per-profile (`entropy_check = false`).

## JSON Validation (Gate 5)

Two-phase validation for `application/json` bodies:

1. **simd-json**: SIMD-accelerated structural validation (well-formedness).
2. **Manual byte scan**: walks the body counting brace/bracket nesting depth and string lengths against `max_depth` and `max_string_len`.

This catches deeply nested JSON and oversized string values without ever materialising the full deserialised tree.
