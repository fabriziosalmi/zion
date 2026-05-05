# ADR-0002: Aho-Corasick over regex for the WAF scanner

- **Status**: accepted
- **Date**: 2026-04-22
- **Tags**: waf, performance, security

## Context

The WAF needs to scan request URIs and bodies for ~190 attack patterns
(SQLi, XSS, command injection, SSRF, Log4Shell, XXE, NoSQL operators,
GraphQL probes, etc.) at 100K+ rps. Two scanner styles were on the table:

1. **Regex** — a `RegexSet` over the pattern list. Familiar, expressive,
   and gives `\b`, `\W`, anchors, alternation. Cost: even an O(N×M)
   compiled DFA holds noticeable per-byte overhead, and ReDoS is a real
   concern when patterns are operator-supplied.
2. **Aho-Corasick** — a multi-pattern string matcher, single-pass O(N)
   over the input regardless of pattern count. No backtracking, no
   pathological inputs, no regex-injection risk. Limitation: literal
   substrings only — no anchors, no `\b`.

## Decision

Use the [`aho-corasick`](https://docs.rs/aho-corasick) crate exclusively.
Patterns are organised into two pre-built scanners (`OnceLock`):

- `BALANCED` (~120 patterns): high-precision anchored substrings —
  `union select`, `<script>`, `${jndi:`, etc. Designed for low false
  positives on production traffic. Default for every route.
- `AGGRESSIVE` (+~70 patterns): broader substrings — `alert(`, `eval(`,
  `os.system(`, generic event handlers. Higher recall, higher false-
  positive rate; opt-in per-route via `mode = "aggressive"`, recommended
  only for admin / internal endpoints.

To recover what regex anchoring would have given us, we **iteratively
normalize** the input *before* the scan: URL-decode, strip SQL `--` /
`/* */` comments, unescape JSON unicode, lowercase. The Aho-Corasick
match then catches the underlying substring even when wrapped in
encoding tricks.

## Consequences

- **Positive**: O(N) single-pass over the request — measurable benchmark
  difference (`balanced` mode at ~103K req/s WAF POST) vs. a regex DFA
  alternative.
- **Positive**: no ReDoS surface; no regex syntax to mis-author in
  operator-controlled additions to the pattern list (the patterns are
  *literal substrings* and ship with the binary).
- **Negative**: no `\b` / anchors. Mitigated by the normalization step
  ahead of the scan; documented in the WAF profile docs.
- **Negative**: pattern drift across releases is reviewed manually. We
  have a `scripts/update-readme-stats.sh` that keeps the pattern count
  in sync with what's in `src/waf.rs`.

## Alternatives considered

- **`regex::RegexSet`** — flexible but ReDoS-prone and slower in our
  benchmarks. We measured a 1.5–2× cost on representative bodies.
- **Hyperscan via `vectorscan`** — Intel-only at the time; we did not
  want a `cfg(target_arch)` split in the WAF.
- **Hand-rolled scanner with SIMD** — out of scope for the v0.1 surface;
  Aho-Corasick already pegs near memory bandwidth on the M4 benchmark.

## References

- [src/waf.rs](../../src/waf.rs)
- Aho, A.V. & Corasick, M.J., *Efficient string matching: an aid to
  bibliographic search*, CACM 1975.
