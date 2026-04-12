# WAF Configuration

The WAF is configured per-route via named profiles. Each profile controls body size limits, content-type enforcement, JSON depth, and string length limits.

## Defining Profiles

```toml
[waf_profile.strict]
max_body_mb = 10
max_depth = 10
max_string_len = 1048576
deny_unknown_content_types = true
allowed_content_types = ["application/json", "multipart/form-data"]

[waf_profile.upload]
max_body_mb = 500
max_depth = 5
max_string_len = 1048576
deny_unknown_content_types = false
allowed_content_types = ["multipart/form-data", "application/octet-stream"]
```

## Assigning Profiles to Routes

```toml
[[route]]
path = "/api/{*rest}"
upstream = "api"
waf_profile = "strict"

[[route]]
path = "/api/v1/backups"
upstream = "api"
waf_profile = "upload"
```

## Profile Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_body_mb` | u64 | `10` | Maximum request body size. Exceeding returns 413. |
| `max_depth` | usize | `10` | Maximum JSON nesting depth (objects + arrays). |
| `max_string_len` | usize | `1048576` (1 MB) | Maximum length of any JSON string value or key. |
| `deny_unknown_content_types` | bool | `true` | Reject content types not in `allowed_content_types`. |
| `allowed_content_types` | string[] | `["application/json", "multipart/form-data"]` | Permitted content types for POST/PUT/PATCH. |

## Content-Type Enforcement

When `deny_unknown_content_types = true` (default):

- POST/PUT/PATCH requests must include a `Content-Type` header
- The content type must match one of the `allowed_content_types` (case-insensitive prefix match)
- Charset suffixes like `; charset=utf-8` are allowed
- Unknown content types return `400 Bad Request`

When set to `false`, requests with unlisted content types pass through without body inspection.

## Legacy Configuration

The older inline syntax is still supported:

```toml
[[route]]
path = "/api/{*rest}"
upstream = "backend"
waf = true
max_body_mb = 10
```

This creates an implicit profile with default values and the specified `max_body_mb`. Named profiles are recommended for new configurations.

## WAF Behavior by HTTP Method

| Method | Body inspected | Gates applied |
|---|---|---|
| GET, HEAD, DELETE, OPTIONS | No (body skipped) | Gate 1 (size) only |
| POST, PUT, PATCH | Yes | All 6 gates |

Empty bodies on POST/PUT/PATCH are allowed without inspection.

## Tuning Guidelines

| Use case | `max_body_mb` | `max_depth` | `deny_unknown_content_types` |
|---|---|---|---|
| JSON API | 10 | 10 | `true` |
| File upload | 500 | 5 | `false` |
| Webhook receiver | 1 | 5 | `true` |
| GraphQL | 5 | 20 | `true` |

See [WAF Pipeline](/security/) for details on the 6-gate architecture and pattern categories.

## WAF Pipeline (6-Gate Architecture)

Every request with a body passes through a **6-gate pipeline** in strict order. Each gate is O(N) or O(1). The pipeline **fail-fasts** — the first gate that triggers a violation returns `400 Bad Request` without executing subsequent gates.

```
Request → Gate 1 → Gate 2 → Gate 3 → Gate 4 → Gate 5 → Gate 6 → Allow
              │         │         │         │         │         │
            Size    Content-  Injection  Entropy   JSON     Anomaly
            Check    Type      Scanner   Analysis  Depth    Profiling
```

| Gate | Check | Cost | Description |
|---|---|---|---|
| 1 | Body size | O(1) | Reject if `Content-Length > max_body_mb × 1MB` |
| 2 | Content-Type | O(1) | Reject if content type not in `allowed_content_types` |
| 3 | Injection scanner | O(N) | Aho-Corasick multi-pattern scan (see below) |
| 4 | Entropy analysis | O(N) | Shannon entropy — detect obfuscated/encoded payloads |
| 5 | JSON validation | O(N) | simd-json structural validation + depth/string limits |
| 6 | Anomaly profiling | O(1) | Fixed-length payload ratio check |

GET, HEAD, DELETE, and OPTIONS requests skip gates 2–6 (no body to inspect).

## Built-in Injection Patterns

Gate 3 uses an [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) automaton — a single O(N) pass over the body that scans **all patterns simultaneously**. No regex, no backtracking, no ReDoS risk.

**70+ patterns in 7 categories:**

### SQL Injection (19 patterns)
```
' or '1'='1    ' or 1=1           '; drop table      union select
union all select   1; exec        sleep(              benchmark(
waitfor delay      pg_sleep(      '; shutdown         into outfile
into dumpfile      load_file(     information_schema  @@version
char(0x            '; delete from  ' and '1'='1
```

### Cross-Site Scripting (18 patterns)
```
<script     </script     javascript:    onerror=       onload=
onfocus=    onmouseover=  onclick=      <iframe        <object
<embed      <svg onload   expression(    alert(        document.cookie
document.write  eval(     fromcharcode
```

### Command Injection (16 patterns)
```
; cat      ; ls       ; rm       ; wget     ; curl
| cat      | ls       | rm       $(cat      $(ls
`cat       `ls        /etc/passwd  /etc/shadow  cmd.exe    powershell
```

### Path Traversal (5 patterns)
```
../../../    ..\..\     %2e%2e%2f    %2e%2e/    ....//
```

### SSRF (4 patterns)
```
http://169.254.169.254    http://[::ffff:169.254
http://metadata.google    http://100.100.100.200
```

### Log4Shell / JNDI (3 patterns)
```
${jndi:    ${env:    ${sys:
```

### Template Injection (4 patterns)
```
{{constructor    {{.constructor    __proto__    constructor.prototype
```

### Double Encoding Bypass

Before running the Aho-Corasick scanner, Zion checks for **double URL encoding** (e.g., `%2527` → `%27` → `'`). If double encoding is detected, the request is rejected immediately — this is a classic WAF bypass technique.

## Extending the Pattern Set

The injection patterns are compiled into the binary at build time via `OnceLock` (lazy initialization on first request). To add custom patterns:

### Step 1: Edit `src/waf.rs`

Locate the `get_scanner()` function and add patterns to the relevant category:

```rust
// In src/waf.rs, inside get_scanner()
let patterns = &[
    // ── SQL Injection ──
    "' or '1'='1",
    // ... existing patterns ...

    // ── Custom: Application-specific ──
    "your_custom_pattern",
    "another_pattern",
];
```

### Step 2: Rebuild

```bash
cargo build --release
```

### Guidelines for Custom Patterns

| Do | Don't |
|---|---|
| Use lowercase patterns (matching is case-insensitive) | Add patterns with regex syntax (not supported) |
| Keep patterns short (3+ chars) for high recall | Add overly generic patterns (`select`, `drop`) |
| Test with `cargo test` after adding | Add patterns that match legitimate API payloads |
| Group by attack category with comments | Mix categories |

### Performance Impact

The Aho-Corasick automaton scans all patterns in a single pass regardless of count. Adding 10 or 100 patterns has **zero additional latency** — the automaton state machine grows in memory (~50 bytes per pattern) but scan speed is always O(N) where N is the body length.
