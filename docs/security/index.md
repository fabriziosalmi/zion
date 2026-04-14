# WAF Pipeline

Zion's WAF is a 6-gate pipeline with a SIMD pre-filter. Each gate is fail-fast: the first denial terminates inspection. No gate uses regex; pattern matching uses the Aho-Corasick algorithm (deterministic finite automaton, no backtracking).

::: info v0.1.2 Improvements
- **SIMD pre-filter**: `memchr3` fast-reject skips the full Aho-Corasick scan for clean bodies (90%+ of traffic)
- **80+ patterns** (up from 70+): added SSRF HTTPS/hex IP/decimal IP, spaceless command injection, 2-level path traversal
- **DELETE body validation**: DELETE requests with bodies are now WAF-inspected (RFC 9110 allows bodies on DELETE)
- **Content-Type delimiter enforcement**: `application/jsonFOO` no longer matches `application/json`
- **Normalization convergence**: iterates until no further decoding needed (was fixed at 3 passes)
- **Buffer safety**: thread-local buffers shrink above 64KB to prevent OOM under adversarial large bodies
:::

## Gate Architecture

```
Request Body
    │
    ▼
┌─ SIMD Pre-Filter (memchr3) ──────────────────────┐
│  Fast-reject: if no trigger bytes (' < ; $ { |)   │
│  present → skip Aho-Corasick entirely → Gate 4    │
└───────────────────────────────────────────────────┘
    │
    ▼
┌─ Gate 1: Body Size ──────────────────────────────┐
│  len check: body.len() > max_body_mb * 1MB       │
│  Applied to all methods                          │
└──────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 2: Content-Type Validation ────────────────┐
│  Case-insensitive byte prefix match              │
│  Missing Content-Type on POST/PUT/PATCH → DENY   │
│  Unknown type + deny_unknown = true → DENY       │
└──────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 3: Aho-Corasick Injection Scanner ─────────┐
│  O(N) pass over body (N = body length)           │
│  70+ patterns scanned simultaneously             │
│  Case-insensitive matching (ASCII)               │
│  Built once via OnceLock on first request        │
└──────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 4: Entropy Analysis ───────────────────────┐
│  Shannon entropy calculation                     │
│  Threshold: 5.5 bits/byte                        │
│  Skipped for bodies < 256 bytes                  │
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
┌─ Gate 6: Fixed-Length Profiling ──────────────────┐
│  Anomalous payload size detection                │
└──────────────────────────────────────────────────┘
    │
    ▼
  ALLOW → Forward to upstream
```

## Pattern Categories (Gate 3)

The Aho-Corasick automaton scans for the following injection families in a single pass:

| Category | Examples | Count |
|---|---|---|
| SQL Injection | `' or '1'='1`, `union select`, `sleep(`, `information_schema` | 20 |
| XSS | `<script`, `javascript:`, `onerror=`, `eval(`, `document.cookie` | 18 |
| Command Injection | `; cat `, `$(ls `, `` `rm `` , `/etc/passwd`, `powershell` | 16 |
| Path Traversal | `../../../`, `..\\..\\`, `%2e%2e%2f` | 5 |
| SSRF | `http://169.254.169.254`, `http://metadata.google` | 4 |
| Log4Shell / JNDI | JNDI/env/sys lookups | 3 |
| Template Injection | prototype pollution, constructor access | 4 |

## Aho-Corasick Properties

- **Algorithm**: Aho-Corasick multi-pattern matching
- **Complexity**: O(N) where N = body length, regardless of pattern count
- **Construction**: Built once via `OnceLock`, immutable after initialization
- **Case sensitivity**: Case-insensitive matching (ASCII)
- **No regex**: The automaton is a deterministic finite automaton (DFA). No backtracking.

## Entropy Analysis (Gate 4)

Shannon entropy is used to flag payloads with unusually high randomness, which may indicate encoding or obfuscation:

| Payload type | Typical entropy (bits/byte) | Action |
|---|---|---|
| English text | 3.0–4.5 | Allow |
| Typical JSON | 3.5–4.5 | Allow |
| Base64-encoded payload | 5.5–6.0 | Deny |
| Random/encrypted data | 7.5–8.0 | Deny |

Threshold is 5.5 bits/byte. Bodies shorter than 256 bytes are exempt (insufficient sample size).

## JSON Validation (Gate 5)

Two-phase validation for `application/json` bodies:

1. **simd-json**: SIMD-accelerated structural validation (checks well-formedness)
2. **Manual byte scan**: Walks the body counting brace/bracket nesting depth and string lengths

This catches deeply nested JSON and oversized string values without full deserialization.
