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

/// The request facts a rule matches against (the non-body shape).
pub struct Target<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a hyper::HeaderMap,
    pub content_type: Option<&'a str>,
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
    // content-type (any prefix matches)
    if !c.content_types.is_empty() {
        let ct = t.content_type.unwrap_or("");
        if !c
            .content_types
            .iter()
            .any(|p| ct.len() >= p.len() && ct[..p.len()].eq_ignore_ascii_case(p))
        {
            return false;
        }
    }
    // headers
    for h in &c.headers {
        let Some(val) = t.headers.get(&h.name) else {
            return false;
        };
        let val = val.as_bytes();
        if let Some(eq) = &h.equals {
            if val != eq.as_bytes() {
                return false;
            }
        }
        if let Some(sub) = &h.contains {
            if !contains_subslice(val, sub.as_bytes()) {
                return false;
            }
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

/// Does query string `q` carry a parameter `name` (optionally equal to `value`)?
fn query_has(q: &str, name: &str, value: Option<&str>) -> bool {
    q.split('&').any(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        k == name && value.is_none_or(|want| v == want)
    })
}

/// A minimal glob: `*` matches any run of characters (including `/` and the empty run). Every other
/// character is literal. No `?` or character classes — enough to shield a CVE by path shape.
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
            .map(String::from)
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
        let mut rest = s;
        for (i, part) in self.parts.iter().enumerate() {
            let first = i == 0;
            let last = i == self.parts.len() - 1;
            if first && self.anchored_start {
                if !rest.starts_with(part.as_str()) {
                    return false;
                }
                rest = &rest[part.len()..];
            } else {
                match rest.find(part.as_str()) {
                    Some(pos) => rest = &rest[pos + part.len()..],
                    None => return false,
                }
            }
            if last && self.anchored_end && !rest.is_empty() {
                return false;
            }
        }
        true
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
        ct: Option<&'a str>,
    ) -> Target<'a> {
        Target {
            method,
            path,
            query,
            headers,
            content_type: ct,
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
            rules.evaluate(&target("POST", "/api/users", None, &h, None), false),
            Verdict::Block(_)
        ));
        // wrong method
        let h2 = hm(&[("x-evil", "1")]);
        assert!(matches!(
            rules.evaluate(&target("GET", "/api/users", None, &h2, None), false),
            Verdict::NoMatch
        ));
        // missing header
        let h3 = hm(&[("x-good", "1")]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/api/users", None, &h3, None), false),
            Verdict::NoMatch
        ));
        // wrong path
        let h4 = hm(&[("x-evil", "1")]);
        assert!(matches!(
            rules.evaluate(&target("POST", "/public", None, &h4, None), false),
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
            rules.evaluate(&target("GET", "/x", None, &h, None), false),
            Verdict::Observed(_)
        ));
        // log -> observed
        assert!(matches!(
            rules.evaluate(&target("POST", "/log/y", None, &h, None), false),
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
            rules.evaluate(
                &target(
                    "POST",
                    "/u",
                    Some("tag=bad&z=1"),
                    &h,
                    Some("multipart/form-data")
                ),
                false
            ),
            Verdict::Block(_)
        ));
        // query value wrong
        assert!(matches!(
            rules.evaluate(&target("POST", "/u", Some("tag=good"), &h, None), false),
            Verdict::NoMatch
        ));

        let toml2 = "[[rule]]\nid='ck'\ncve='CVE-2099-5'\naction='deny'\ncookies=['sessionid']\n";
        let rules2 = VirtualPatchRules::from_toml_str(toml2).unwrap();
        let hc = hm(&[("cookie", "a=1; sessionid=zzz; b=2")]);
        assert!(matches!(
            rules2.evaluate(&target("GET", "/", None, &hc, None), false),
            Verdict::Block(_)
        ));
        let hc2 = hm(&[("cookie", "a=1; b=2")]);
        assert!(matches!(
            rules2.evaluate(&target("GET", "/", None, &hc2, None), false),
            Verdict::NoMatch
        ));
    }
}
