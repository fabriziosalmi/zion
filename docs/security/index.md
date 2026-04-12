# WAF Pipeline

Zion's WAF is a 6-gate pipeline. Each gate is fail-fast: the first denial terminates inspection immediately. No gate uses regex -- the entire pipeline is ReDoS-immune by construction.

## Gate Architecture

```
Request Body
    │
    ▼
┌─ Gate 1: Body Size ──────────────────────────────┐
│  O(1) check: body.len() > max_body_mb * 1MB      │
│  Enforced for ALL methods (including GET)         │
└───────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 2: Content-Type Validation ─────────────────┐
│  Zero-alloc, case-insensitive prefix match        │
│  Missing Content-Type on POST/PUT/PATCH → DENY    │
│  Unknown type + deny_unknown = true → DENY        │
└───────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 3: Aho-Corasick Injection Scanner ──────────┐
│  Single O(N) pass over entire body                │
│  70+ patterns scanned simultaneously              │
│  Case-insensitive matching                        │
│  Built once at first use (OnceLock)               │
└───────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 4: Entropy Analysis ────────────────────────┐
│  Shannon entropy calculation                      │
│  Threshold: 5.5 bits/byte                         │
│  Normal text: ~3.5-4.5 bits                       │
│  Base64/obfuscated: ~5.5-6.0 bits                 │
│  Skipped for bodies < 256 bytes                   │
└───────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 5: JSON Structural Validation ──────────────┐
│  simd-json validation (SIMD-accelerated)          │
│  Nesting depth check (manual byte scan)           │
│  String length check (keys + values)              │
│  Only applied when Content-Type = application/json│
└───────────────────────────────────────────────────┘
    │ ALLOW
    ▼
┌─ Gate 6: Fixed-Length Profiling ──────────────────┐
│  Anomalous payload size detection                 │
└───────────────────────────────────────────────────┘
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
- **No regex**: The automaton is a deterministic finite automaton (DFA). There is no backtracking and no possibility of catastrophic performance.

## Entropy Analysis (Gate 4)

Shannon entropy detects obfuscated or encoded payloads that evade pattern matching:

| Payload type | Entropy (bits/byte) | Action |
|---|---|---|
| Normal English text | 3.0 - 4.5 | Allow |
| Typical JSON | 3.5 - 4.5 | Allow |
| Base64-encoded payload | 5.5 - 6.0 | Deny |
| Random/encrypted data | 7.5 - 8.0 | Deny |

Threshold is 5.5 bits/byte. Bodies shorter than 256 bytes are exempt (insufficient data for meaningful analysis).

## JSON Validation (Gate 5)

Two-phase validation for `application/json` bodies:

1. **simd-json**: SIMD-accelerated structural validation (well-formedness)
2. **Manual byte scan**: Zero-allocation walk counting brace/bracket depth and string lengths

This catches deeply nested JSON bombs and oversized string values without deserializing the payload.
