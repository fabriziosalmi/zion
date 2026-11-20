# WAF Configuration

The WAF is configured per-route via named profiles. Each profile controls the **detection mode** (which Aho-Corasick pattern set is scanned), the **entropy gate** (threshold + kill-switch), and the body inspection limits (size, JSON depth, string length, content-type allow-list).

## Defining profiles

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

## Assigning profiles to routes

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

## Profile parameters

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
| `scan_headers` | string[] | `[]` | Request headers whose values go through the injection scanner (case-insensitive names, optional trailing `*`). Empty scans none. See [Scanning request headers](#scanning-request-headers). |
| `max_parts` | usize | `1000` | Maximum number of parts in a `multipart/form-data` body. See [Multipart structure](#multipart-structure). |
| `max_file_parts` | usize | `256` | Maximum number of file parts (a part with a `filename` or a `filename*`, empty `filename=""` included). `0` refuses every file part. |
| `max_part_headers` | usize | `16` | Maximum header lines in one part. |
| `max_part_header_bytes` | usize | `8192` | Maximum total bytes of one part's header block. |
| `deny_field_names` | string[] | `[]` | Form field names refused outright (a part whose Content-Disposition `name` matches, case-insensitive). E.g. `PHP_SESSION_UPLOAD_PROGRESS`. |
| `deny_part_header_names` | string[] | `["__proto__", "constructor"]` | Part header names refused outright (case-insensitive). |
| `max_field_name_index` | u64 | `100000` | Refuse a field name that encodes an array index above this (e.g. `items[4294967295]`); `0` disables. |

## Multipart structure

When a request body is labelled `multipart/form-data`, the WAF parses it by RFC 2046
and holds it to the structure limits above, before the injection scan. The parser
is strict: a body it cannot parse cleanly is refused (`400`), never forwarded, and so
is a body that PHP, Werkzeug or Django would split into other parts (see below).
That stops the part/header floods that PHP2Shell and a series of parser CVEs rely
on, and the smuggling shapes listed below. It does not make every backend read the
same field names as the gate: see [what is still open](#what-is-still-open).

A body is refused when: the `boundary` parameter is missing, malformed, or
declared twice; the body does not begin at its boundary (a preamble); the closing
`--boundary--` is absent; a part has no field `name`; a part's header block is not
terminated; `max_parts`, `max_file_parts`, `max_part_headers`,
`max_part_header_bytes`, or `max_field_name_index` is exceeded; or a
`deny_field_names` / `deny_part_header_names` entry matches. The defaults are
generous enough for real browser and `curl -F` uploads; tighten them per profile
for an endpoint that takes only small forms.

Common backends parse multipart more leniently than RFC 2046, so a body that
leaves them another reading is refused too:

- a `boundary` parameter another backend reads differently: an RFC 2231 form
  (`boundary*`, `boundary*0`), which Werkzeug and Django take as the boundary; an
  unquoted value with a space or one of `( ) , / : = ?` in it, which RFC 2045
  wants quoted and Werkzeug cuts short there; a space or tab right after the `=`,
  which PHP keeps in the boundary; or a `boundary` substring before the parameter
  (`xboundary=C; boundary=B`, or inside another parameter's value), since PHP takes
  the first one it finds. A quoted value (`boundary="a/b c"`) is read the same way
  by all three and passes.
- `--boundary` anywhere except at the start of the body and right after the CRLF
  that ends a part. PHP, Werkzeug and Django also split parts on a bare LF before
  it, Werkzeug and Django on a bare CR, and Django on `--boundary` anywhere, so a
  part there would be one the gate never saw.
- anything but spaces, tabs, CR and LF after the closing `--boundary--`. RFC 2046
  calls it an epilogue for parsers to ignore, but PHP and Django read parts out of
  it; `curl -F` and Python `requests` send one CRLF there.
- a CR or LF in a part's headers that is not part of a CRLF. PHP breaks a header
  line at a bare LF and Werkzeug at either, and Werkzeug also ends the headers at
  `\n\n` or `\r\r`, so they would read another field `name` than the gate.
- a part with two `Content-Disposition` headers (PHP and Werkzeug read the first,
  Django the last), two `name` parameters (all three keep the last), or a `name*`
  or `name*0` parameter (RFC 2231), which Werkzeug and Django take as the field
  name. A `filename*` parameter makes a part a file part, as it does for them; .NET
  sends one next to every `filename`, which still passes.

The field-name rules apply to every media type that a backend reads as
`multipart/form-data`: spaces and tabs before it and before the `;` are skipped
(`multipart/form-data<TAB>; boundary=B` is form-data to Werkzeug and Django), and
so is anything after it that cannot continue a media type (PHP ends it at `,`).

The gate also runs on **any other content-type that carries a `boundary`
parameter**, plain or `boundary*` (for example `multipart/mixed`, or a wildcard
variant a framework maps to multipart). A lenient upstream parses such a body as
multipart while a front proxy that only recognised `multipart/form-data` would
forward it unparsed, so the two could split the body on a different boundary: the
content-type smuggling class (Spring CVE-2026-41853). Zion parses it with the same
boundary and structure rules (without the form-data field-name rules) and refuses
it unless it parses cleanly. A strict `deny_unknown_content_types` already refuses
these at the content-type gate; this covers the lenient profiles that accept them.

### What is still open

The gate reads a part's field name as the value of its one `name` parameter, with
one layer of double quotes removed. A backend can read a malformed value another
way, so a name in `deny_field_names` can still reach it in that shape: Werkzeug
ignores bytes after a closing quote (`name="x"y`) and after an unquoted value and a
space (`name=x y`), and PHP also strips single quotes (`name='x'`, read from its
source, not run). On a `multipart/mixed` or other non-form-data body the
field-name rules do not apply at all. Treat `deny_field_names` as a limit for the
bodies real clients send, not as proof that no parser behind zion can see another
field name.

## Detection modes

`mode` selects which pattern set Gate 3 scans. Both modes share the same fail-fast pipeline; only the Aho-Corasick automaton differs.

| Mode | Patterns | Use case |
|---|---|---|
| `balanced` (default) | ~100 high-precision: anchored SQLi/XSS tags, specific SSRF endpoints, exact-string CVEs (Log4Shell, XXE), specific PHP wrappers. | User-content APIs (comments, code paste, MDN-style docs, base64-bearing payloads). |
| `aggressive` | balanced + ~140 broad-substring patterns: `alert(`, `eval(`, `confirm(`, `document.cookie`, `innerhtml`, `$gt`/`$ne`/`$regex`, `os.system(`, `pickle.loads`, `Runtime.getRuntime`, generic event handlers (`onclick=`, `onmouseover=`, …). | Admin panels, internal tooling, API surfaces where the FP cost is acceptable. |

The two automata are built lazily (on first hit per process) and cached; switching profiles costs nothing at request time. A request denied by an aggressive-only pattern returns the same `400` body and `waf_denied` metric as a balanced denial — there is no separate counter.

## Content-Type enforcement

A request that carries a body and no `Content-Type` is refused (`400`), whatever the
setting below.

When `deny_unknown_content_types = true` (default):

- The content type must match one of the `allowed_content_types` (case-insensitive prefix match)
- Charset suffixes like `; charset=utf-8` are allowed
- Unknown content types return `400 Bad Request`

When set to `false`, a body of an unlisted content type is not refused for its type, but
it is still inspected: the size cap, the [multipart structure](#multipart-structure)
gate, the injection scan and the entropy check run on it as on a listed type. Only the
JSON checks (depth, string length, well-formed JSON) are left out: they run on a listed
`application/json` body alone.

Whatever the setting, a request with a body and more than one `Content-Type` line is
refused (`400`): the field is a singleton (RFC 9110), the gates read the first line,
and an upstream may act on another one (gunicorn 23 hands the app the last). A route's
`content_types` list refuses such a body too, with its `415`.

## Legacy configuration

The older inline syntax is still supported:

```toml
[[route]]
path = "/api/{*rest}"
upstream = "backend"
waf = true
max_body_mb = 10
```

This creates an implicit profile with default values and the specified `max_body_mb`. Named profiles are recommended for new configurations.

A route has **one** WAF policy: `waf = true` (inline), a `waf_profile`, or neither. Combining `waf = true` with `waf_profile` is a load-time error (the profile would win and `waf = true` would do nothing), and so is a route-level `max_body_mb` next to a `waf_profile` (the profile carries its own cap, so set `max_body_mb` inside the `[waf_profile.<name>]` table). A `max_body_mb` on a route with no WAF is still accepted, with a boot warning that the cap is not enforced.

## WAF behavior by HTTP method

| Method | Body inspected | Gates applied |
|---|---|---|
| GET, HEAD, OPTIONS | No (body skipped) | Gate 1 (size) only |
| DELETE | Yes (RFC 9110 allows DELETE bodies) | All 5 gates |
| POST, PUT, PATCH | Yes | All 5 gates |

Empty bodies on POST/PUT/PATCH are allowed without inspection.

## Scanning request headers

A payload does not only travel in the URI or the body: Log4Shell arrived in `User-Agent`.
By default zion scans no header. A profile opts in by naming the headers:

```toml
[waf_profile.api]
scan_headers = ["user-agent", "referer", "x-*"]   # "x-*" = every header starting with x-

[[route]]
path = "/api/{*rest}"
upstream = "api"
waf_profile = "api"
waf_shadow = true        # first: count what would be blocked, block nothing
```

A listed header's value goes through the same scanner as the URI, raw and then decoded
(URL-encoding, SQL comments, unicode escapes), in the profile's `mode`. A match answers
`400`; the log names the header, never its value. The cost is bounded by the request's
header budget (64 headers, 16 KB).

**Why it is opt-in, and how to turn it on.** A signature that is right for a query string
can be wrong for a header. Measured on the benign header corpus
(`benchmarks/waf-corpus/headers-benign.json`: 124 values from real browsers, crawlers,
HTTP libraries, monitoring agents, consent and analytics cookies, search-engine referers):

| Mode | Benign values blocked | Which |
|---|---|---|
| `balanced` | 0 of 124 | none |
| `aggressive` | 2 of 124 | `Origin: http://localhost:3000` (the SSRF signature) and a `Referer` whose URL contains `eval(` |

Detection is the engine's own: the attack corpus sent as a header value is caught as often
as in a query string (177 of 1,058 in `balanced`, 429 in `aggressive`).

That corpus is not your traffic. Start with `waf_shadow = true`, watch
`zion_waf_shadow_would_block` and the `waf_shadow` log lines (`source=header header=<name>`)
for a few days, then remove `waf_shadow`. Suggested lists: `["user-agent", "referer", "x-*"]`
in `balanced`; in `aggressive` leave out `origin` and `referer`. `cookie` is worth scanning
if your application reads cookies into queries or templates, and is the header most likely
to carry something that looks like a payload. A test (`benign_headers_are_not_blocked`)
keeps the table above true; add a value to the corpus whenever shadow mode shows a false
positive.

## Tuning guidelines

| Use case | `mode` | `max_body_mb` | `max_depth` | `entropy_check` | `deny_unknown_content_types` |
|---|---|---|---|---|---|
| JSON API | `balanced` | 10 | 10 | `true` | `true` |
| Admin / internal | `aggressive` | 1 | 8 | `true` | `true` |
| File upload | `balanced` | 500 | 5 | `false` | `false` |
| Webhook receiver | `balanced` | 1 | 5 | `true` | `true` |
| GraphQL | `balanced` | 5 | 20 | `true` | `true` |

See [WAF Pipeline](/security/) for the full per-gate description and the source-of-truth pattern listing.

## WAF pipeline (5-Gate architecture)

Every request with a body passes through a **5-gate pipeline** in strict order. Each gate is O(N) or O(1). The pipeline **fail-fasts** — the first gate that triggers a violation returns `400 Bad Request` (or `413 Payload Too Large` for Gate 1) without executing subsequent gates.

```text
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

## Built-in injection patterns

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
- **LDAP, XXE, SSTI** — parens-anchored LDAP filters, `<!entity`/`<!doctype`/`SYSTEM "file://"`, Jinja/JSP <span v-pre>`{{7*7}}`</span> markers
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

## Extending the pattern set

Patterns are compiled into the binary at build time via two `OnceLock<AhoCorasick>` automata (one per mode), built lazily on first hit. To add custom patterns:

### Step 1: edit `src/waf.rs`

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

### Step 2: rebuild

```bash
cargo build --release
```

### Guidelines for custom patterns

| Do | Don't |
|---|---|
| Anchor patterns whenever possible (with `<`, `;`, `'`, `$(`, …) and put them in `BALANCED_PATTERNS` | Add unanchored substrings to balanced — put them in `AGGRESSIVE_EXTRA_PATTERNS` |
| Use lowercase (matching is ASCII case-insensitive) | Use regex syntax — not supported |
| Test with `cargo test --release --bin zion` after adding | Match legitimate API payloads (run your real corpus through the scanner before committing) |

### Performance impact

The Aho-Corasick automaton scans all patterns in a single pass regardless of count. Adding 10 or 100 patterns adds no per-request CPU cost — the automaton state machine grows in memory (≈50 bytes per pattern) but scan throughput stays O(N) in body length.
