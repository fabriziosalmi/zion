// SPDX-License-Identifier: Apache-2.0
//! Virtual-patch rules (#698): operator-editable CVE shields loaded from a TOML data file, so a
//! new CVE can be answered by editing a file and reloading, not by cutting a release.
//!
//! A rule names its CVE and a source link, matches on request shape (method, path glob, header
//! presence/value, cookie name, query parameter, Content-Type), and either denies the request or
//! only logs it (`action`), optionally in shadow mode (count and log, never block). Every criterion
//! present on a rule must match (AND); the first matching rule wins. Each rule carries its own
//! match counter, exported per-CVE. This v1 covers the non-body request shape; rules that need the
//! body (e.g. a multipart field name) are a planned follow-up.
//!
//! The rules live in their own file, watched and hot-reloaded independently of `zion.toml`
//! (`src/reload.rs` wires the watcher); a parse error keeps the previous rules, never an empty set.

use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Block the request (the gate answers 403).
    Deny,
    /// Only record that the shape was seen; never block.
    Log,
}

/// A condition on one header.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    /// Header name, compared case-insensitively.
    pub name: String,
    /// Exact value (case-sensitive) the header must have. Omit to match on mere presence.
    #[serde(default)]
    pub equals: Option<String>,
    /// Substring the header value must contain. Omit to match on mere presence.
    #[serde(default)]
    pub contains: Option<String>,
}

/// A condition on one query parameter.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryMatch {
    /// Parameter name (case-sensitive, as it appears in the query string).
    pub name: String,
    /// Exact value the parameter must have. Omit to match on mere presence.
    #[serde(default)]
    pub equals: Option<String>,
}

/// One rule as written in the TOML file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Stable short id, unique in the file (the metric label and log key).
    pub id: String,
    /// The CVE this rule shields against (e.g. "CVE-2025-12345").
    pub cve: String,
    /// A link to the advisory / source.
    #[serde(default)]
    pub source: String,
    /// `deny` or `log`.
    pub action: Action,
    /// Run the rule but never block, only count and log (overrides `deny`).
    #[serde(default)]
    pub shadow: bool,

    /// HTTP methods this rule applies to (empty = any method).
    #[serde(default)]
    pub methods: Vec<String>,
    /// A glob over the request path (`*` matches any run of characters). Omit = any path.
    #[serde(default)]
    pub path_glob: Option<String>,
    /// Header conditions (all must match).
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
    /// Cookie names that must be present.
    #[serde(default)]
    pub cookies: Vec<String>,
    /// Query-parameter conditions (all must match).
    #[serde(default)]
    pub query: Vec<QueryMatch>,
    /// Content-Type prefixes (any one matching is enough); empty = any.
    #[serde(default)]
    pub content_types: Vec<String>,
}

/// The whole file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default)]
    rule: Vec<RuleConfig>,
}

/// A compiled rule: the config plus a compiled path glob and the live match counters.
#[derive(Debug)]
pub struct Rule {
    cfg: RuleConfig,
    path_glob: Option<Glob>,
    methods_upper: Vec<String>,
    /// Times this rule matched a request (exported per CVE).
    matched: AtomicU64,
    /// Of those, times it only counted because it was in shadow / `log` mode.
    would_block: AtomicU64,
}

impl Rule {
    pub fn id(&self) -> &str {
        &self.cfg.id
    }
    pub fn cve(&self) -> &str {
        &self.cfg.cve
    }
    pub fn source(&self) -> &str {
        &self.cfg.source
    }
    pub fn matched(&self) -> u64 {
        self.matched.load(Ordering::Relaxed)
    }
    pub fn would_block(&self) -> u64 {
        self.would_block.load(Ordering::Relaxed)
    }
    /// True when a match must block (action deny and not shadow).
    fn blocks(&self) -> bool {
        self.cfg.action == Action::Deny && !self.cfg.shadow
    }
}

/// The request facts a rule matches against (the non-body shape). There is no separate
/// `content_type` field: `headers` already carries every `Content-Type` value a request
/// sent, and `rule_matches()` reads all of them -- a single pre-extracted value (as this
/// struct used to carry, built from `HeaderMap::get()`, which only sees the FIRST of a
/// repeated header) would have let a rule's `content_types` or `[[rule.headers]]` check be
/// evaded by putting the dangerous value in a second occurrence of the header (found on
/// review of #774's own audit trail: the same class of bug already fixed once today in
/// `tls_fp`'s User-Agent check, for the same reason).
pub struct Target<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a hyper::HeaderMap,
}

/// What evaluating the rules decided.
pub enum Verdict<'a> {
    /// No rule matched.
    NoMatch,
    /// A rule matched and the request must be blocked (by this rule).
    Block(&'a Rule),
    /// A rule matched but only logs / shadows: proceed, but it was counted.
    Observed(&'a Rule),
}

/// A compiled, hot-swappable set of virtual-patch rules.
#[derive(Debug, Default)]
pub struct VirtualPatchRules {
    rules: Vec<Rule>,
}

impl VirtualPatchRules {
    /// Parse and compile a rules file. Returns an error (keeping the caller's previous rules) if
    /// the TOML is invalid, a rule has no match criteria, a glob is malformed, or an id repeats.
    pub fn from_toml_str(s: &str) -> Result<Self, String> {
        let file: RulesFile = toml::from_str(s).map_err(|e| format!("parse: {e}"))?;
        let mut rules = Vec::with_capacity(file.rule.len());
        let mut seen = std::collections::HashSet::new();
        for cfg in file.rule {
            if !seen.insert(cfg.id.clone()) {
                return Err(format!("duplicate rule id '{}'", cfg.id));
            }
            if cfg.cve.trim().is_empty() {
                return Err(format!("rule '{}' has no cve", cfg.id));
            }
            let has_match = !cfg.methods.is_empty()
                || cfg.path_glob.is_some()
                || !cfg.headers.is_empty()
                || !cfg.cookies.is_empty()
                || !cfg.query.is_empty()
                || !cfg.content_types.is_empty();
            if !has_match {
                return Err(format!(
                    "rule '{}' has no match criteria (it would match every request)",
                    cfg.id
                ));
            }
            let path_glob = match &cfg.path_glob {
                Some(g) => Some(Glob::compile(g).map_err(|e| format!("rule '{}': {e}", cfg.id))?),
                None => None,
            };
            let methods_upper = cfg.methods.iter().map(|m| m.to_ascii_uppercase()).collect();
            rules.push(Rule {
                path_glob,
                methods_upper,
                matched: AtomicU64::new(0),
                would_block: AtomicU64::new(0),
                cfg,
            });
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Every rule, for metric rendering.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Append per-rule Prometheus counters, labelled by rule id and CVE. No output when empty.
    pub fn render_prometheus(&self, out: &mut String) {
        if self.rules.is_empty() {
            return;
        }
        out.push_str(
            "# HELP zion_virtual_patch_matches_total Requests matched by a virtual-patch rule.\n\
             # TYPE zion_virtual_patch_matches_total counter\n",
        );
        for r in self.rules() {
            out.push_str("zion_virtual_patch_matches_total{rule=\"");
            push_label(out, r.id());
            out.push_str("\",cve=\"");
            push_label(out, r.cve());
            out.push_str("\"} ");
            out.push_str(&r.matched().to_string());
            out.push('\n');
        }
        out.push_str(
            "# HELP zion_virtual_patch_would_block_total Matches that only logged (log/shadow mode).\n\
             # TYPE zion_virtual_patch_would_block_total counter\n",
        );
        for r in self.rules() {
            out.push_str("zion_virtual_patch_would_block_total{rule=\"");
            push_label(out, r.id());
            out.push_str("\",cve=\"");
            push_label(out, r.cve());
            out.push_str("\"} ");
            out.push_str(&r.would_block().to_string());
            out.push('\n');
        }
    }

    /// Evaluate the rules against a request. The first matching rule wins; its counters are bumped.
    /// `global_shadow` forces every rule to observe-only (count and log, never block), so the
    /// `would_block` counter stays accurate for a staged dry-run of the whole pack.
    pub fn evaluate<'a>(&'a self, t: &Target<'_>, global_shadow: bool) -> Verdict<'a> {
        for rule in &self.rules {
            if rule_matches(rule, t) {
                rule.matched.fetch_add(1, Ordering::Relaxed);
                if rule.blocks() && !global_shadow {
                    return Verdict::Block(rule);
                }
                rule.would_block.fetch_add(1, Ordering::Relaxed);
                return Verdict::Observed(rule);
            }
        }
        Verdict::NoMatch
    }
}

fn rule_matches(rule: &Rule, t: &Target<'_>) -> bool {
    let c = &rule.cfg;
    // method
    if !rule.methods_upper.is_empty()
        && !rule
            .methods_upper
            .iter()
            .any(|m| m.eq_ignore_ascii_case(t.method))
    {
        return false;
    }
    // path glob
    if let Some(g) = &rule.path_glob {
        if !g.matches(t.path) {
            return false;
        }
    }
    // content-type (any prefix matches ANY of the request's Content-Type values -- a request
    // can carry more than one, and the one an upstream actually acts on is not necessarily
    // the first; HeaderMap::get() would only ever see that first one).
    if !c.content_types.is_empty() {
        let any_matches = t
            .headers
            .get_all(hyper::header::CONTENT_TYPE)
            .iter()
            .any(|v| {
                let ct = v.to_str().unwrap_or("");
                c.content_types
                    .iter()
                    .any(|p| ct.len() >= p.len() && ct[..p.len()].eq_ignore_ascii_case(p))
            });
        if !any_matches {
            return false;
        }
    }
    // headers: for each named header, some ONE of its (possibly repeated) values must satisfy
    // every condition configured for it -- not "the first value satisfies equals and some
    // other, different occurrence happens to satisfy contains". Repeating a header is how a
    // request can carry a dangerous value while an inspector that only reads HeaderMap::get()
    // (the first occurrence) sees only an innocuous one.
    for h in &c.headers {
        let any_matches = t.headers.get_all(&h.name).iter().any(|val| {
            let val = val.as_bytes();
            let eq_ok = h.equals.as_deref().is_none_or(|eq| val == eq.as_bytes());
            let sub_ok = h
                .contains
                .as_deref()
                .is_none_or(|sub| contains_subslice(val, sub.as_bytes()));
            eq_ok && sub_ok
        });
        if !any_matches {
            return false;
        }
    }
    // cookies (names present)
    if !c.cookies.is_empty() {
        let present = cookie_names(t.headers);
        if !c
            .cookies
            .iter()
            .all(|want| present.iter().any(|n| n == want))
        {
            return false;
        }
    }
    // query params
    if !c.query.is_empty() {
        let q = t.query.unwrap_or("");
        for want in &c.query {
            if !query_has(q, &want.name, want.equals.as_deref()) {
                return false;
            }
        }
    }
    true
}

/// Append `s` as a Prometheus label value, escaping `\`, `"` and newline (RFC exposition format).
fn push_label(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Cookie names present in the `Cookie` header(s).
fn cookie_names(headers: &hyper::HeaderMap) -> Vec<String> {
    let mut names = Vec::new();
    for v in headers.get_all(hyper::header::COOKIE) {
        if let Ok(s) = v.to_str() {
            for pair in s.split(';') {
                let name = pair.split('=').next().unwrap_or("").trim();
                if !name.is_empty() {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

/// Decode a query-string component the way PHP's `parse_str` (and so WordPress, and most other
/// backends behind zion) decodes one: `+` is a space, `%XX` is the byte it names, one pass, and
/// a malformed `%` sequence (not followed by two hex digits) is left exactly as written rather
/// than rejected — `parse_str` does not error on it either, it leaves it alone. `rule.query`
/// compared the RAW query string (`k == name`) until this was added: `?%69d=1z` decodes to
/// `id=1z` by the time PHP sees it, so a rule naming `id` never matched it and the shield it was
/// meant to be could be bypassed with any percent-encoding of its parameter name (found by
/// review on #773, which also promoted the WordPress rule this engine first needed it for).
fn percent_decode(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains(['%', '+']) {
        return std::borrow::Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // A decoded byte sequence that is not valid UTF-8 cannot equal any rule's (UTF-8) `name` or
    // `value` anyway, so lossy conversion -- never a panic, never rejecting the request -- is
    // the right failure mode here: the comparison below just returns false for it.
    String::from_utf8_lossy(&out).into_owned().into()
}

/// Does query string `q` carry a parameter `name` (optionally equal to `value`)? Both the
/// string being searched and `name`/`value` are compared after percent-decoding -- see
/// [`percent_decode`] -- since `q` is the raw bytes of the URI's query component (hyper does not
/// decode it) and is compared against a rule's plain-text `name`/`value` in `virtual-patch.toml`.
fn query_has(q: &str, name: &str, value: Option<&str>) -> bool {
    q.split('&').any(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        percent_decode(k) == name && value.is_none_or(|want| percent_decode(v) == want)
    })
}

/// A minimal glob: `*` matches any run of characters (including `/` and the empty run). Every other
/// character is literal, compared ASCII case-insensitively. No `?` or character classes — enough
/// to shield a CVE by path shape.
///
/// Case-insensitive on purpose, not because HTTP paths are (RFC 3986: they are not) -- because
/// case variation is a textbook WAF-evasion technique, and this engine is used only for narrow,
/// specific, security-sensitive prefixes (an actuator endpoint, a management API, a REST route)
/// that nothing legitimate is going to coincidentally share at a different case. The asymmetry
/// is the point: a missed `/MGMT/tm/util/bash` because the real backend's routing turned out to
/// be case-insensitive is a remote-code-execution-class miss; a path that happens to collide
/// case-insensitively with one of these specific prefixes and gets a 403 it didn't need is a
/// false positive on a shield a route opted into. Found by review-driven audit of the two
/// pre-existing shipped rules (#773): `path_glob = "/mgmt/*"` let `/MGMT/tm/util/bash` straight
/// through on the real binary, confirmed before this fix existed.
#[derive(Debug)]
pub struct Glob {
    /// Literal segments between `*`s. `leading`/`trailing` say whether the pattern starts/ends
    /// with `*`.
    parts: Vec<String>,
    anchored_start: bool,
    anchored_end: bool,
}

impl Glob {
    pub fn compile(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("empty path_glob".to_string());
        }
        let anchored_start = !pattern.starts_with('*');
        let anchored_end = !pattern.ends_with('*');
        let parts: Vec<String> = pattern
            .split('*')
            .filter(|p| !p.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        Ok(Glob {
            parts,
            anchored_start,
            anchored_end,
        })
    }

    pub fn matches(&self, s: &str) -> bool {
        // Pattern was all '*' (no literal parts): matches anything.
        if self.parts.is_empty() {
            return true;
        }
        // One lowercase pass of the input, not one per part: parts are already lowercased
        // at compile() time, so this keeps the comparison itself a plain byte match.
        let lowered = s.to_ascii_lowercase();
        let mut rest = lowered.as_str();
        let last_index = self.parts.len() - 1;
        for (i, part) in self.parts.iter().enumerate() {
            let first = i == 0;
            let last = i == last_index;
            if last {
                // The final part decides the match by itself, against what the earlier parts
                // left in `rest`. It must sit at an END, not merely occur somewhere in `rest`
                // -- `find()`'s first occurrence can be an earlier, coincidental occurrence of
                // the same literal (`*.php` against "/public.php.bak/index.php" genuinely
                // ends in ".php", but find() matches the ".php" inside "public.php.bak" first
                // and then rejects on what trails it; found by review on #774, where a
                // same-case input alone already triggers it -- case-folding was not what
                // created this, only what made it easy to reach).
                return match (first && self.anchored_start, self.anchored_end) {
                    (true, true) => rest == part.as_str(), // no `*` at all: exact
                    (true, false) => rest.starts_with(part.as_str()), // "/a/*": prefix
                    (false, true) => rest.ends_with(part.as_str()), // "*.php": suffix
                    (false, false) => rest.contains(part.as_str()), // "*x*": substring
                };
            }
            if first && self.anchored_start {
                if !rest.starts_with(part.as_str()) {
                    return false;
                }
                rest = &rest[part.len()..];
            } else {
                // A middle part (between two `*`s, or after a leading `*` with more parts
                // still to come): any position it occurs at is fine here, since what matters
                // is whether the LATER parts can still match in what remains -- unlike the
                // last part above, there is no "nothing may trail it" requirement yet.
                match rest.find(part.as_str()) {
                    Some(pos) => rest = &rest[pos + part.len()..],
                    None => return false,
                }
            }
        }
        unreachable!("the loop always returns on its last iteration")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    fn target<'a>(
        method: &'a str,
        path: &'a str,
        query: Option<&'a str>,
        headers: &'a hyper::HeaderMap,
    ) -> Target<'a> {
        Target {
            method,
            path,
            query,
            headers,
        }
    }

    #[test]
    fn the_shipped_pack_parses() {
        // The starter pack must always compile, or it ships un-loadable (mirrors the
        // example-config guard in config.rs).
        let pack = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/virtual-patch.toml"
        ));
        let rules = VirtualPatchRules::from_toml_str(pack).expect("shipped pack compiles");
        assert!(!rules.is_empty(), "the shipped pack has rules");
        for r in rules.rules() {
            assert!(r.cve().starts_with("CVE-"), "rule {} names a CVE", r.id());
        }
    }

    #[test]
    fn glob_anchors_and_wildcards() {
        assert!(Glob::compile("/a/*").unwrap().matches("/a/b/c"));
        assert!(Glob::compile("/a/*").unwrap().matches("/a/"));
        assert!(!Glob::compile("/a/*").unwrap().matches("/b/a/"));
        assert!(Glob::compile("*.php").unwrap().matches("/x/y.php"));
        assert!(!Glob::compile("*.php").unwrap().matches("/x/y.phps"));
        assert!(Glob::compile("/*/admin/*").unwrap().matches("/v1/admin/x"));
        assert!(Glob::compile("/exact").unwrap().matches("/exact"));
        assert!(!Glob::compile("/exact").unwrap().matches("/exact/more"));
    }

    #[test]
    fn glob_matching_is_ascii_case_insensitive() {
        // Case variation is a textbook evasion technique against a path-based security shield
        // (found on the two pre-existing shipped rules, #773: `/mgmt/*` let `/MGMT/...` through).
        // Every combination of pattern case and input case must match the same way.
        for pattern in ["/mgmt/*", "/MGMT/*", "/Mgmt/*"] {
            let g = Glob::compile(pattern).unwrap();
            assert!(g.matches("/mgmt/tm/util/bash"), "{pattern}");
            assert!(g.matches("/MGMT/tm/util/bash"), "{pattern}");
            assert!(g.matches("/MgMt/Tm/UTIL/bash"), "{pattern}");
        }
        // A middle literal part (between two `*`s), not just the anchored prefix.
        assert!(Glob::compile("/*/ADMIN/*").unwrap().matches("/v1/admin/x"));
        // Still anchored correctly: case-folding must not loosen what the pattern excludes.
        assert!(!Glob::compile("/mgmt/*").unwrap().matches("/not-mgmt/x"));
        assert!(!Glob::compile("/EXACT").unwrap().matches("/exact/more"));
    }

    #[test]
    fn end_anchored_matching_finds_the_true_suffix_not_an_earlier_coincidental_one() {
        // Review finding on #774: lowercasing the input can turn two previously-distinct
        // substrings into the same literal text, and matches() used to take `find()`'s FIRST
        // occurrence even for the end-anchored LAST part, then reject on whatever trailed it
        // -- so an earlier, coincidental occurrence of the literal could hide a real match at
        // the true end. This is not actually a case-folding bug: the identical shape, same
        // case throughout, already demonstrates it.
        let g = Glob::compile("*.php").unwrap();
        assert!(
            g.matches("/public.php.bak/index.php"),
            "the true suffix is real"
        );
        // The exact case from review: mixed case only collides into the same bug via folding.
        assert!(g.matches("/public.PHP/index.php"));
        assert!(g.matches("/PUBLIC.PHP/INDEX.PHP"));
        // And the end-anchor must still correctly REJECT when nothing of the pattern's
        // literal actually sits at the true end.
        assert!(!g.matches("/index.php.bak"));
        assert!(!g.matches("/public.php/index.phps"));
        // The same end-anchor fix, exercised in a multi-part pattern (a middle part between
        // two `*`s, then the end-anchored final literal) rather than a single-part one.
        let g2 = Glob::compile("/a/*/admin/*.conf").unwrap();
        assert!(g2.matches("/a/admin-looking/admin/real.conf"));
        assert!(!g2.matches("/a/admin-looking/admin/real.conf.bak"));
    }

    #[test]
    fn a_rule_needs_at_least_one_criterion() {
        let toml = "[[rule]]\nid='r'\ncve='CVE-1'\naction='deny'\n";
        assert!(VirtualPatchRules::from_toml_str(toml)
            .unwrap_err()
            .contains("no match criteria"));
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let toml = "[[rule]]\nid='r'\ncve='CVE-1'\naction='log'\nmethods=['GET']\n\
                    [[rule]]\nid='r'\ncve='CVE-2'\naction='log'\nmethods=['POST']\n";
        assert!(VirtualPatchRules::from_toml_str(toml)
            .unwrap_err()
            .contains("duplicate rule id"));
    }

    #[test]
    fn deny_rule_blocks_its_shape_and_only_its_shape() {
        let toml = "[[rule]]\nid='cl-te'\ncve='CVE-2099-1'\nsource='http://x'\naction='deny'\n\
                    methods=['POST']\npath_glob='/api/*'\n\
                    [[rule.headers]]\nname='x-evil'\n";
        let rules = VirtualPatchRules::from_toml_str(toml).unwrap();
        // matches: POST /api/.. with x-evil present
        let h = hm(&[("x-evil", "1")]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/api/users", None, &h), false),
            Verdict::Block(_)
        ));
        // wrong method
        let h2 = hm(&[("x-evil", "1")]);
        assert!(matches!(
            rules.evaluate(&target("GET", "/api/users", None, &h2), false),
            Verdict::NoMatch
        ));
        // missing header
        let h3 = hm(&[("x-good", "1")]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/api/users", None, &h3), false),
            Verdict::NoMatch
        ));
        // wrong path
        let h4 = hm(&[("x-evil", "1")]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/public", None, &h4), false),
            Verdict::NoMatch
        ));
    }

    #[test]
    fn shadow_and_log_observe_but_do_not_block() {
        let toml =
            "[[rule]]\nid='s'\ncve='CVE-2099-2'\naction='deny'\nshadow=true\nmethods=['GET']\n\
                    [[rule]]\nid='l'\ncve='CVE-2099-3'\naction='log'\npath_glob='/log/*'\n";
        let rules = VirtualPatchRules::from_toml_str(toml).unwrap();
        let h = hm(&[]);
        // shadow deny -> observed, not blocked, counted as would_block
        assert!(matches!(
            rules.evaluate(&target("GET", "/x", None, &h), false),
            Verdict::Observed(_)
        ));
        // log -> observed
        assert!(matches!(
            rules.evaluate(&target("POST", "/log/y", None, &h), false),
            Verdict::Observed(_)
        ));
        // counters: rule 's' matched once, would_block once
        let s = rules.rules().iter().find(|r| r.id() == "s").unwrap();
        assert_eq!(s.matched(), 1);
        assert_eq!(s.would_block(), 1);
    }

    #[test]
    fn header_value_and_query_and_cookie_match() {
        let toml = "[[rule]]\nid='hv'\ncve='CVE-2099-4'\naction='deny'\n\
                    [[rule.headers]]\nname='content-type'\ncontains='multipart'\n\
                    [[rule.query]]\nname='tag'\nequals='bad'\n";
        let rules = VirtualPatchRules::from_toml_str(toml).unwrap();
        let h = hm(&[("content-type", "multipart/form-data; boundary=x")]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/u", Some("tag=bad&z=1"), &h), false),
            Verdict::Block(_)
        ));
        // query value wrong
        assert!(matches!(
            rules.evaluate(&target("POST", "/u", Some("tag=good"), &h), false),
            Verdict::NoMatch
        ));

        let toml2 = "[[rule]]\nid='ck'\ncve='CVE-2099-5'\naction='deny'\ncookies=['sessionid']\n";
        let rules2 = VirtualPatchRules::from_toml_str(toml2).unwrap();
        let hc = hm(&[("cookie", "a=1; sessionid=zzz; b=2")]);
        assert!(matches!(
            rules2.evaluate(&target("GET", "/", None, &hc), false),
            Verdict::Block(_)
        ));
        let hc2 = hm(&[("cookie", "a=1; b=2")]);
        assert!(matches!(
            rules2.evaluate(&target("GET", "/", None, &hc2), false),
            Verdict::NoMatch
        ));
    }

    #[test]
    fn content_types_and_header_match_see_a_dangerous_value_in_any_repeated_occurrence() {
        // Real finding on #774 (same class as the tls_fp User-Agent fix done earlier the same
        // day): HeaderMap::get() only sees the FIRST of a repeated header. A request can carry
        // the dangerous value in a SECOND occurrence while the first is innocuous -- zion
        // forwards every value it received, so there is no basis for assuming an upstream
        // only ever acts on the first one either. Confirmed against the real binary before
        // this fix: curling two Content-Type headers (text/plain, then multipart/form-data)
        // at a rule with content_types = ["multipart/form-data"] got 503 (not matched), not
        // 403 -- and the same for a [[rule.headers]] equals check on a repeated header.
        let toml = "[[rule]]\nid='ct'\ncve='CVE-2099-7'\naction='deny'\ncontent_types=['multipart/form-data']\n\
                    [[rule]]\nid='hdr'\ncve='CVE-2099-8'\naction='deny'\n\
                    [[rule.headers]]\nname='x-probe'\nequals='bad'\n";
        let rules = VirtualPatchRules::from_toml_str(toml).unwrap();

        // The dangerous Content-Type as the SECOND of two values.
        let h1 = hm(&[
            ("content-type", "text/plain"),
            ("content-type", "multipart/form-data; boundary=x"),
        ]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/x", None, &h1), false),
            Verdict::Block(_)
        ));
        // As the only value, for comparison -- must still match (not a regression).
        let h1_only = hm(&[("content-type", "multipart/form-data; boundary=x")]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/x", None, &h1_only), false),
            Verdict::Block(_)
        ));
        // Neither value dangerous: must not match.
        let h1_safe = hm(&[
            ("content-type", "text/plain"),
            ("content-type", "text/html"),
        ]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/x", None, &h1_safe), false),
            Verdict::NoMatch
        ));

        // The dangerous header value as the SECOND of two x-probe occurrences.
        let h2 = hm(&[("x-probe", "good"), ("x-probe", "bad")]);
        assert!(matches!(
            rules.evaluate(&target("GET", "/x", None, &h2), false),
            Verdict::Block(_)
        ));
        let h2_safe = hm(&[("x-probe", "good"), ("x-probe", "also-good")]);
        assert!(matches!(
            rules.evaluate(&target("GET", "/x", None, &h2_safe), false),
            Verdict::NoMatch
        ));
        // Missing entirely: must not match (unaffected by the fix).
        let h2_absent = hm(&[]);
        assert!(matches!(
            rules.evaluate(&target("GET", "/x", None, &h2_absent), false),
            Verdict::NoMatch
        ));
    }

    #[test]
    fn percent_decode_matches_phps_parse_str() {
        // The exact bypass review found on #773: a query key written with any byte
        // percent-encoded must still match, since that is what PHP's parse_str (and so
        // WordPress) decodes it to before the application ever sees the raw bytes.
        assert_eq!(percent_decode("%69d"), "id");
        assert_eq!(percent_decode("i%64"), "id");
        assert_eq!(percent_decode("%69%64"), "id");
        // '+' is a space in a query string (application/x-www-form-urlencoded), not literal.
        assert_eq!(percent_decode("a+b"), "a b");
        // A malformed sequence is left exactly as written -- parse_str does not error on it,
        // and this must not panic on a byte string that ends mid-escape.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("100%2"), "100%2");
        assert_eq!(percent_decode("100%zz"), "100%zz");
        // No '%' or '+' at all: the common case, must not allocate or alter the string.
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn query_has_sees_through_percent_encoding_of_the_name_or_the_value() {
        assert!(query_has("%69d=1z", "id", None));
        assert!(query_has("id=%31z", "id", Some("1z")));
        assert!(query_has("a=1&%69d=1z&b=2", "id", None));
        // Still false when the decoded name genuinely differs.
        assert!(!query_has("%69%64x=1z", "id", None));
        assert!(!query_has("other=1", "id", None));
    }

    #[test]
    fn a_query_rule_catches_the_percent_encoded_bypass_an_unmodified_query_has_would_miss() {
        let toml = "[[rule]]\nid='q'\ncve='CVE-2099-6'\naction='deny'\n\
                    [[rule.query]]\nname='id'\n";
        let rules = VirtualPatchRules::from_toml_str(toml).unwrap();
        let h = hm(&[]);
        for q in ["id=1z", "%69d=1z", "i%64=1z", "%69%64=1z"] {
            assert!(
                matches!(
                    rules.evaluate(&target("GET", "/x", Some(q), &h), false),
                    Verdict::Block(_)
                ),
                "query {q:?} must be caught"
            );
        }
        assert!(matches!(
            rules.evaluate(&target("GET", "/x", Some("other=1"), &h), false),
            Verdict::NoMatch
        ));
    }
}
