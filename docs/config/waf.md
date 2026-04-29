# WAF Configuration

The WAF is configured per-route via named profiles. Each profile controls the **detection mode** (which Aho-Corasick pattern set is scanned), the **entropy gate** (threshold + kill-switch), and the body inspection limits (size, JSON depth, string length, content-type allow-list).

## Defining Profiles

```toml
[waf_profile.strict]
mode = "balanced"            # default — high precision, low FP
max_body_mb = 10
max_depth = 10
max_string_len = 1048576
deny_unknown_content_types = true
allowed_content_types = ["application/json", "multipart/form-data"]
entropy_check = true
entropy_threshold = 6.5      # bits/byte; default leaves base64 / JWT through

[waf_profile.admin]
mode = "aggressive"          # broader recall — also catches alert(, eval(,
                              # $gt, os.system(, runtime.getruntime, etc.
max_body_mb = 1
max_depth = 8

[waf_profile.upload]
max_body_mb = 500
max_depth = 5
deny_unknown_content_types = false
allowed_content_types = ["multipart/form-data", "application/octet-stream"]
entropy_check = false        # binary uploads are high-entropy by nature
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
| `mode` | string | `"balanced"` | Pattern set: `"balanced"` (high precision) or `"aggressive"` (high recall). See [Detection Modes](#detection-modes). |
| `max_body_mb` | u64 | `10` | Maximum request body size. Exceeding returns 400. |
| `max_depth` | usize | `10` | Maximum JSON nesting depth (objects + arrays). |
| `max_string_len` | usize | `1048576` (1 MB) | Maximum length of any JSON string value or key. |
| `deny_unknown_content_types` | bool | `true` | Reject content types not in `allowed_content_types`. |
| `allowed_content_types` | string[] | `["application/json", "multipart/form-data"]` | Permitted content types for POST/PUT/PATCH. |
| `entropy_check` | bool | `true` | Enable Gate 4 (Shannon entropy). Disable on routes that legitimately accept high-entropy bodies (binary uploads, encrypted blobs). |
| `entropy_threshold` | f64 | `6.5` | Bits/byte. Bodies above this are denied. Default sits above pure base64 (theoretical max 6.0); random/encrypted blobs land at 7.5–8.0. |

## Detection Modes

`mode` selects which pattern set Gate 3 scans. Both modes share the same fail-fast pipeline; only the Aho-Corasick automaton differs.

| Mode | Patterns | Use case |
|---|---|---|
| `balanced` (default) | ~120 high-precision: anchored SQLi/XSS tags, specific SSRF endpoints, exact-string CVEs (Log4Shell, XXE), specific PHP wrappers. | User-content APIs (comments, code paste, MDN-style docs, base64-bearing payloads). |
| `aggressive` | balanced + ~70 broad-substring patterns: `alert(`, `eval(`, `confirm(`, `document.cookie`, `innerhtml`, `$gt`/`$ne`/`$regex`, `os.system(`, `pickle.loads`, `Runtime.getRuntime`, generic event handlers (`onclick=`, `onmouseover=`, …). | Admin panels, internal tooling, API surfaces where the FP cost is acceptable. |

The two automata are built lazily (on first hit per process) and cached; switching profiles costs nothing at request time. A request denied by an aggressive-only pattern returns the same `400` body and `waf_denied` metric as a balanced denial — there is no separate counter.

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
| GET, HEAD, OPTIONS | No (body skipped) | Gate 1 (size) only |
| DELETE | Yes (RFC 9110 allows DELETE bodies) | All 5 gates |
| POST, PUT, PATCH | Yes | All 5 gates |

Empty bodies on POST/PUT/PATCH are allowed without inspection.

## Tuning Guidelines

| Use case | `mode` | `max_body_mb` | `max_depth` | `entropy_check` | `deny_unknown_content_types` |
|---|---|---|---|---|---|
| JSON API | `balanced` | 10 | 10 | `true` | `true` |
| Admin / internal | `aggressive` | 1 | 8 | `true` | `true` |
| File upload | `balanced` | 500 | 5 | `false` | `false` |
| Webhook receiver | `balanced` | 1 | 5 | `true` | `true` |
| GraphQL | `balanced` | 5 | 20 | `true` | `true` |

See [WAF Pipeline](/security/) for the full per-gate description and the source-of-truth pattern listing.

## WAF Pipeline (5-Gate Architecture)

Every request with a body passes through a **5-gate pipeline** in strict order. Each gate is O(N) or O(1). The pipeline **fail-fasts** — the first gate that triggers a violation returns `400 Bad Request` (or `413 Payload Too Large` for Gate 1) without executing subsequent gates.

```
Request → Gate 1 → Gate 2 → Gate 3 → Gate 4 → Gate 5 → Allow
              │         │         │         │         │
            Size    Content-  Injection  Entropy    JSON
            Check    Type      Scanner   Analysis   Depth
```

| Gate | Check | Cost | Description |
|---|---|---|---|
| 1 | Body size | O(1) | Reject if body length > `max_body_mb × 1MB` |
| 2 | Content-Type | O(1) | Reject if content type not in `allowed_content_types` (case-insensitive prefix with delimiter check) |
| 3 | Injection scanner | O(N) | Aho-Corasick multi-pattern scan over raw body, then over iteratively-normalised body (URL-decode, SQL comments, JSON unicode); uses the balanced or aggressive set per `mode` |
| 4 | Entropy analysis | O(N) | Shannon entropy. For JSON content-types, computed on bytes inside string literals only (`shannon_entropy_json_strings`); for non-JSON, on the whole body. Skipped if `entropy_check = false` or body < 256 bytes. |
| 5 | JSON validation | O(N) | simd-json structural validation + depth and per-string length limits |

GET, HEAD, OPTIONS requests skip Gates 2–5 (no body to inspect). DELETE bodies are inspected (RFC 9110 allows them and some APIs use them).

## Built-in Injection Patterns

Gate 3 uses an [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) automaton — a single O(N) pass over the body that scans all patterns simultaneously. No regex, no backtracking, no ReDoS risk.

The full, authoritative pattern lists live in [`src/waf.rs`](https://github.com/fabriziosalmi/zion/blob/master/src/waf.rs) as two `&[&str]` constants:

- `BALANCED_PATTERNS` — active in both modes
- `AGGRESSIVE_EXTRA_PATTERNS` — added on top under `mode = "aggressive"`

The current category breakdown is summarised below; consult the source for the exact strings (the lists evolve faster than this page).

### Balanced (default) — categories
- **SQL injection** — anchored quote/keyword combos: `' or '1'='1`, `union select`, `'; drop table`, `waitfor delay`, `information_schema`, …
- **XSS tags** — `<script`, `<iframe`, `<object`, `<svg onload`, `<img src`, …
- **High-signal XSS handlers / sinks** — `onerror=`, `onload=`, `srcdoc=`, `javascript:` (other handlers live in aggressive)
- **Command injection** — anchored on `;`, `|`, `$(`, backtick, newline followed by a binary name; `/etc/passwd`, `/etc/shadow`
- **Path traversal** — `../../`, `..\..\`, `%2e%2e%2f`, `....//`, Windows variants
- **SSRF / cloud metadata** — `169.254.169.254` (AWS, with hex/decimal/IPv6-mapped variants), GCP, Alibaba, Azure IMDS, DigitalOcean, Oracle, OpenStack, Kubernetes service host
- **LDAP, XXE, SSTI** — parens-anchored LDAP filters, `<!entity`/`<!doctype`/`SYSTEM "file://"`, Jinja/JSP `{{7*7}}` markers
- **CRLF / header injection** — `%0d%0a`, `%0aset-cookie:`, `\r\nset-cookie:`
- **Log4Shell / JNDI** — `${jndi:`, `${env:`, `${sys:`
- **Prototype pollution** — `__proto__`, `constructor.prototype`
- **PHP** — `unserialize(`, `php://input`, `php://filter`, `phar://`
- **GraphQL introspection** — `{__schema`, `{__type`, `query{__`

### Aggressive (opt-in) — additional categories
- **JS API sinks** — `alert(`, `confirm(`, `prompt(`, `eval(`, `document.cookie`, `document.write`, `window.location`, `innerhtml`, `outerhtml`, `expression(`, `fromcharcode`, …
- **Generic XSS event handlers** — `onclick=`, `onmouseover=`, `oninput=`, `onchange=`, `ontoggle=`, … (~25 handlers that the balanced set excludes for FP control)
- **NoSQL operators (unanchored)** — `$gt`, `$ne`, `$regex`, `$where`, `$lookup`, `db.collection`, `.find({`, …
- **Deserialization class names** — Java (`Runtime.getRuntime`, `ProcessBuilder`, `ObjectInputStream`, …), Python (`pickle.loads`, `__reduce__`, `__import__(`, `subprocess.call`, `subprocess.popen`, `os.system(`, `os.popen(`)
- **SQLi function calls** — `sleep(`, `benchmark(`, `into outfile`, `load_file(`, `@@version`, `char(0x`
- **Windows tokens** — `cmd.exe`, `powershell`
- **Lone GraphQL introspection tokens** — `__schema`, `__type`, `mutation{`

### Iterative encoding normalisation

Before declaring a body clean, Gate 3 runs the scanner over a **normalised** copy that successively decodes URL escapes (`%XX`, `+`), strips SQL comments (`/* … */` → space), and decodes JSON unicode escapes (`\uXXXX`). The decode loop runs up to **3 passes**, which catches single, double, and triple encoding (the realistic real-world maximum). At each iteration the scanner runs again; if any pass matches, the request is denied with reason `injection pattern detected (encoded)`.

Earlier docs claimed Zion "rejects requests on detection of double encoding." That has never been the behaviour and would have been wrong: legitimate URLs can contain double-encoded characters (e.g., search queries about URL encoding itself). What Zion actually does is *re-scan after each decode pass*.

## Extending the Pattern Set

Patterns are compiled into the binary at build time via two `OnceLock<AhoCorasick>` automata (one per mode), built lazily on first hit. To add custom patterns:

### Step 1: Edit `src/waf.rs`

The two constants live near the top of the file:

```rust
// In src/waf.rs
const BALANCED_PATTERNS: &[&str] = &[
    // ── SQL Injection ──
    "' or '1'='1",
    // ... existing patterns ...

    // ── Custom: high-precision, anchored ──
    "your_custom_anchored_pattern",
];

const AGGRESSIVE_EXTRA_PATTERNS: &[&str] = &[
    // ... existing aggressive patterns ...

    // ── Custom: broader recall ──
    "your_custom_substring",
];
```

The runtime entry point is `scanner_for(mode)` (replaced the older `get_scanner()` helper); both automata are accessed through it.

### Step 2: Rebuild

```bash
cargo build --release
```

### Guidelines for Custom Patterns

| Do | Don't |
|---|---|
| Anchor patterns whenever possible (with `<`, `;`, `'`, `$(`, …) and put them in `BALANCED_PATTERNS` | Add unanchored substrings to balanced — put them in `AGGRESSIVE_EXTRA_PATTERNS` |
| Use lowercase (matching is ASCII case-insensitive) | Use regex syntax — not supported |
| Test with `cargo test --release --bin zion` after adding | Match legitimate API payloads (run your real corpus through the scanner before committing) |

### Performance Impact

The Aho-Corasick automaton scans all patterns in a single pass regardless of count. Adding 10 or 100 patterns adds no per-request CPU cost — the automaton state machine grows in memory (≈50 bytes per pattern) but scan throughput stays O(N) in body length.
